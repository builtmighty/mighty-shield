<?php
/**
 * Exemption helper.
 *
 * Central "is this visitor whitelisted?" check for trusted IPs, users, and
 * email addresses.
 *
 * An exemption suppresses ENFORCEMENT, not scoring. Every detector runs, every
 * signal is emitted and a risk row is written for an allowlisted shopper
 * exactly as it is for anyone else -- the allowlist only stops MightyShield
 * acting on the verdict it reached.
 *
 * It used to be the other way round: this was called at the top of all ~30
 * detectors, which returned before emitting anything. The verdict was not
 * suppressed, it was never formed, so an allowlisted order left no trace in
 * mshield_risk at all. On a store that allowlisted a role its own customers
 * hold, that silently emptied the history the tuning report and the review
 * queue are both built on.
 *
 * Three entry points, and which one to reach for:
 *
 *   suppresses_action()           the visitor making THIS request. Right on the
 *                                 checkout path, where the visitor is the
 *                                 shopper. Will not trust a typed email.
 *   suppresses_action_for_order() the order itself, whoever is asking. Right on
 *                                 a webhook or anywhere wp-admin can reach.
 *   is_exempt_order()             the order, trusting its stored email too.
 *                                 Only for an administrator looking at an order
 *                                 they can already see.
 *
 * There are seven call sites between them, all at points where something is
 * about to be done to somebody. If a new one appears at the top of a method
 * that scores, it is the old bug growing back.
 *
 * @package MightyShield
 * @since   1.4.0
 */
namespace MightyShield\Includes;

defined( 'ABSPATH' ) || exit;

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
     * Whether MightyShield should decline to ACT on the verdict it reached.
     *
     * The enforcement boundary, and the name to call at one. Identical in
     * behaviour to is_exempt() -- the difference is what it says at the call
     * site, which is the whole point: a detector that calls is_exempt() and
     * returns is skipping the scoring too, and that is the bug this name
     * exists to make obvious.
     *
     * Call this where an action is about to be taken, never at the top of a
     * method that scores.
     *
     * @since   3.0.0
     *
     * @param   string    $email     Billing email, where one is available.
     * @param   int|null  $user_id   Explicit user ID (e.g. order customer).
     * @return  bool
     */
    public static function suppresses_action( $email = '', $user_id = null ) {

        return self::is_exempt( $email, $user_id );

    }

    /**
     * The same question, asked about a STORED order rather than a request.
     *
     * Needed because the enforcement boundary is not always reached from the
     * shopper's own request. A gateway webhook arrives as nobody, and an
     * administrator poking an order arrives as themselves -- and activation
     * allowlists both the administrator role and the server's own address, so
     * suppresses_action() would answer "yes, exempt" for an order belonging to
     * a customer who is nothing of the sort.
     *
     * Deliberately NOT is_exempt_order(), which additionally trusts the stored
     * billing address. That is right where it is used -- an administrator
     * looking at an order they can already see -- and wrong here, because this
     * also runs on the checkout path, where the address is whatever the shopper
     * just typed. Trusting it would let anyone who learned an allowlisted
     * address opt out of enforcement by typing it, which is the hole
     * owns_email() exists to close.
     *
     * So: the order's own IP and its own user, both of which are facts about
     * the order rather than claims made by whoever is looking at it.
     *
     * @since   3.0.0
     *
     * @param   \WC_Order   $order
     * @return  bool
     */
    public static function suppresses_action_for_order( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return false;

        $ip = self::order_ip( $order );

        if( $ip !== '' && ip_whitelist::is_whitelisted( $ip ) ) return true;

        $user_id = (int) $order->get_user_id();

        if( $user_id > 0 ) {
            if( ip_whitelist::is_user_whitelisted( $user_id ) ) return true;
            if( ip_whitelist::is_role_whitelisted( $user_id ) ) return true;
        }

        // NOT matches_order(). Phone, name, postcode, city and country are
        // typed into the checkout form by whoever is placing the order, exactly
        // as the billing email is -- so at the enforcement boundary they are a
        // claim, not a fact, and an allowlisted postcode would let anyone who
        // typed it opt out of every hold. A country entry would do that for an
        // entire nation of shoppers. Those entries are honoured in
        // is_exempt_order(), where an administrator is looking at a stored
        // order and the values are what was actually ordered.
        return false;

    }

    /**
     * The address a stored order was really placed from.
     *
     * WooCommerce fills get_customer_ip_address() from X-Real-IP or the first
     * X-Forwarded-For hop, whichever the client chose to send -- so on its own
     * it is a header the shopper controls. Activation allowlists 127.0.0.1,
     * and one forged header made every order allowlisted at dispatch. The
     * recorder stores the address ip_utils resolved (the TCP peer, or a
     * trusted proxy's word for it) on the order at rating time; that is what
     * the allowlist is asked about. Orders rated before 3.0.0 carry no such
     * meta, and for those the enforcement boundary does not consult the
     * allowlist by IP at all: a wrong "yes" here switches enforcement off,
     * a wrong "no" costs one allowlisted shopper a review.
     *
     * @since   3.0.0
     *
     * @param   \WC_Order   $order
     * @return  string      An IP, or '' when nothing trustworthy is known.
     */
    private static function order_ip( $order ) {

        return (string) $order->get_meta( '_mshield_ip' );

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

        // The address the recorder resolved, when there is one; WooCommerce's
        // header-derived value only for orders that predate it. See order_ip().
        $ip = self::order_ip( $order );
        if( $ip === '' ) $ip = (string) $order->get_customer_ip_address();

        if( $ip !== '' && ip_whitelist::is_whitelisted( $ip ) ) return true;

        $user_id = (int) $order->get_user_id();

        if( $user_id > 0 ) {
            if( ip_whitelist::is_user_whitelisted( $user_id ) ) return true;
            if( ip_whitelist::is_role_whitelisted( $user_id ) ) return true;
        }

        $email = (string) $order->get_billing_email();

        if( $email !== '' && ip_whitelist::is_email_whitelisted( $email ) ) return true;

        if( ip_whitelist::matches_order( $order ) ) return true;

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
