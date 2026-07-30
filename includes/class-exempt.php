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

        // In test mode the acting admin must NOT be exempt, so their own
        // checkout genuinely exercises every layer.
        if( test_mode::active() ) return false;

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

        // Email check (varies per request/order).
        if( $reason === '' && $email !== '' && ip_whitelist::is_email_whitelisted( $email ) ) {
            $reason = 'email';
        }

        if( $reason === '' ) return false;

        self::log_once( $reason );

        return true;

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
