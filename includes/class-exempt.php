<?php
/**
 * Exemption helper.
 *
 * Central "is this visitor whitelisted?" check used by every protection to
 * bypass all blocks and flags for trusted IPs, users, and email addresses.
 *
 * @package MightyShield
 * @since   1.4.0
 */
namespace MightyShield\Includes;

use MightyShield\Firewall\ip_whitelist;

class exempt {

    /**
     * Memoized IP/user exemption result for this request.
     *
     * @since   1.4.0
     */
    private static $ip_user_exempt = null;

    /**
     * Whether the exempt event has already been logged this request.
     *
     * @since   1.4.0
     */
    private static $logged = false;

    /**
     * Determine whether the current request is exempt from all checks.
     *
     * @since   1.4.0
     *
     * @param   string    $email     Billing email available at this hook (optional).
     * @param   int|null  $user_id   Explicit user ID (e.g. order customer). Falls
     *                               back to the logged-in user when null.
     * @return  bool
     */
    public static function is_exempt( $email = '', $user_id = null ) {

        $reason = '';

        // IP + current-user checks are request-global — memoize them.
        if( self::$ip_user_exempt === null ) {
            self::$ip_user_exempt = false;

            if( ip_whitelist::is_whitelisted( ip_utils::get_client_ip() ) ) {
                self::$ip_user_exempt = 'ip';
            } else {
                $current = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
                if( $current > 0 && ip_whitelist::is_user_whitelisted( $current ) ) {
                    self::$ip_user_exempt = 'user';
                } elseif( $current > 0 && ip_whitelist::is_role_whitelisted( $current ) ) {
                    self::$ip_user_exempt = 'role';
                }
            }
        }

        if( self::$ip_user_exempt !== false ) {
            $reason = self::$ip_user_exempt;
        }

        // Explicit user id (e.g. order customer) not covered by the memoized
        // current-user check.
        if( $reason === '' && $user_id !== null && (int) $user_id > 0 ) {
            if( ip_whitelist::is_user_whitelisted( (int) $user_id ) ) {
                $reason = 'user';
            } elseif( ip_whitelist::is_role_whitelisted( (int) $user_id ) ) {
                $reason = 'role';
            }
        }

        // Email check — only ever against an address the visitor has PROVEN is
        // theirs, which means the one on the account they are signed in to.
        //
        // The address passed in here comes from the checkout form, so it is
        // whatever the visitor typed. Treating that as proof of identity meant
        // anyone who learned or guessed a whitelisted address could type it and
        // bypass every check in the plugin — the firewall, the blocklist, the
        // score, all of it. An allowlist that anyone can opt into is not an
        // allowlist.
        if( $reason === '' && $email !== '' && self::owns_email( $email ) && ip_whitelist::is_email_whitelisted( $email ) ) {
            $reason = 'email';
        }

        // Say so when a whitelisted address was typed but not proven. A store
        // that was relying on the old behaviour needs to see why it stopped,
        // rather than quietly wondering where its exemption went.
        if( $reason === '' && $email !== '' && ip_whitelist::is_email_whitelisted( $email ) ) {
            self::log_unverified( $email );
        }

        if( $reason === '' ) return false;

        self::log_once( $reason );

        return true;

    }

    /**
     * Whether a STORED order is exempt, judged on the order's own identity.
     *
     * is_exempt() answers "is the visitor making this request exempt", which is
     * exactly right at checkout, where the visitor is the shopper. It is wrong
     * anywhere the order is being looked at after the fact: it memoizes the
     * REQUEST's IP and the CURRENT user, so re-rating an order from wp-admin
     * asks whether the administrator is allowlisted. Activation auto-allowlists
     * the server's own address, so on most stores that answer is yes and every
     * check would silently return nothing while appearing to run.
     *
     * The order's billing email is trusted here where is_exempt() will not
     * trust it, and the difference is deliberate: there, the address is whatever
     * a visitor just typed into a form and treating it as proof of identity
     * would let anyone opt into the allowlist. Here it is a stored value on a
     * completed order that only an administrator can see, and the caller is an
     * administrator acting on that order.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @return  bool
     */
    public static function is_exempt_order( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return false;

        $ip = (string) $order->get_customer_ip_address();

        if( $ip !== '' && ip_whitelist::is_whitelisted( $ip ) ) return true;

        $user_id = (int) $order->get_user_id();

        if( $user_id > 0 ) {
            if( ip_whitelist::is_user_whitelisted( $user_id ) ) return true;
            if( ip_whitelist::is_role_whitelisted( $user_id ) ) return true;
        }

        $email = (string) $order->get_billing_email();

        if( $email !== '' && ip_whitelist::is_email_whitelisted( $email ) ) return true;

        return false;

    }

    /**
     * Whether the visitor has proven this address is theirs.
     *
     * Proof means being signed in to an account carrying that address. A guest
     * typing it into a checkout form has proven nothing.
     *
     * @since   1.9.0
     *
     * @param   string  $email
     * @return  bool
     */
    private static function owns_email( $email ) {

        if( ! function_exists( 'wp_get_current_user' ) ) return false;

        $user = wp_get_current_user();
        if( ! $user || empty( $user->ID ) || empty( $user->user_email ) ) return false;

        return strtolower( trim( $user->user_email ) ) === strtolower( trim( $email ) );

    }

    /**
     * Record that a whitelisted address was used without being proven.
     *
     * @since   1.9.0
     *
     * @param   string  $email
     */
    private static function log_unverified( $email ) {

        if( self::$logged ) return;
        self::$logged = true;

        db::log_event(
            ip_utils::get_client_ip(),
            'classic_checkout',
            'flagged',
            'A whitelisted email address was entered by someone not signed in to that account, so no exemption was granted. '
            . 'Whitelist the IP, the WordPress user, or the role instead if this was meant to be allowed.'
        );

    }

    /**
     * Log a single "exempt" event per request for visibility.
     *
     * @since   1.4.0
     *
     * @param   string  $reason  Which match granted the exemption.
     */
    private static function log_once( $reason ) {

        if( self::$logged ) return;
        self::$logged = true;

        db::log_event(
            ip_utils::get_client_ip(),
            'classic_checkout',
            'exempt',
            'Whitelisted — checks bypassed (' . $reason . ')'
        );

    }

}
