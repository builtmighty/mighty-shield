<?php
/**
 * Account, login and coupon guard.
 *
 * Everything else in this plugin watches the checkout. Nothing watched the
 * doors either side of it: registration, login, and coupons had no coverage at
 * all — not a single hook.
 *
 * That matters because the interesting attacks start before checkout. Someone
 * brute-forcing coupon codes, stuffing credentials, or minting accounts is
 * doing reconnaissance, and by the time they reach the checkout form they look
 * like a first-time buyer. Recording it here means the order that follows is
 * judged with that behaviour already known.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\exempt;
use MightyShield\Includes\risk_context;

class account_guard {

    /**
     * How long behaviour is remembered for scoring, in seconds.
     *
     * @since   1.9.0
     */
    const WINDOW = HOUR_IN_SECONDS;

    /**
     * Construct.
     *
     * @since   1.9.0
     */
    public function __construct() {

        // Registration.
        add_action( 'woocommerce_created_customer', [ $this, 'on_registration' ], 10, 1 );
        add_action( 'user_register', [ $this, 'on_registration' ], 10, 1 );

        // Login failures — the precursor to account takeover.
        add_action( 'wp_login_failed', [ $this, 'on_login_failed' ], 10, 1 );

        // Coupons.
        add_filter( 'woocommerce_coupon_is_valid', [ $this, 'on_coupon_checked' ], 999, 2 );
        add_action( 'woocommerce_applied_coupon', [ $this, 'on_coupon_applied' ], 10, 1 );

        // Contribute what was seen to the checkout that follows.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'emit' ], 30, 2 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'emit_store_api' ], 30, 2 );

    }

    /**
     * Count an event against this visitor.
     *
     * Uses the rate-limit table rather than transients: an object cache can
     * evict a transient at any moment, which would silently disable exactly the
     * counting this relies on.
     *
     * @since   1.9.0
     *
     * @param   string  $type   Counter name.
     * @return  int     The new count.
     */
    private static function bump( $type ) {

        $ip = ip_utils::get_client_ip();
        if( empty( $ip ) ) return 0;

        return db::increment_rate_limit( md5( $ip . '|' . $type ), $type, self::WINDOW );

    }

    /**
     * Read a counter without incrementing it.
     *
     * @since   1.9.0
     *
     * @param   string  $type
     * @return  int
     */
    private static function count( $type ) {

        $ip = ip_utils::get_client_ip();
        if( empty( $ip ) ) return 0;

        return db::check_rate_limit( md5( $ip . '|' . $type ), $type );

    }

    /**
     * A new account was created.
     *
     * @since   1.9.0
     *
     * @param   int     $user_id
     */
    public function on_registration( $user_id ) {

        if( exempt::is_exempt( '', $user_id ) ) return;

        $count = self::bump( 'registrations' );

        $limit = (int) settings::get( 'mshield_registration_threshold' );

        if( $limit > 0 && $count > $limit ) {

            db::log_event(
                ip_utils::get_client_ip(),
                'registration',
                'flagged',
                sprintf( 'Registration velocity: %d accounts created in the last hour (limit %d)', $count, $limit )
            );

        }

    }

    /**
     * A login attempt failed.
     *
     * @since   1.9.0
     *
     * @param   string  $username
     */
    public function on_login_failed( $username ) {

        $count = self::bump( 'login_failures' );

        $limit = (int) settings::get( 'mshield_login_failure_threshold' );

        if( $limit > 0 && $count > $limit ) {

            db::log_event(
                ip_utils::get_client_ip(),
                'login',
                'flagged',
                sprintf( 'Login failures: %d in the last hour (limit %d) — possible credential stuffing', $count, $limit )
            );

        }

    }

    /**
     * A coupon was checked for validity.
     *
     * This fires for valid and invalid codes alike, so only the failures are
     * counted — that is what separates someone guessing codes from someone
     * using one they were given.
     *
     * @since   1.9.0
     *
     * @param   bool    $valid
     * @param   object  $coupon
     * @return  bool    Unmodified; this only observes.
     */
    public function on_coupon_checked( $valid, $coupon = null ) {

        if( ! $valid ) self::bump( 'coupon_failures' );

        return $valid;

    }

    /**
     * A coupon was successfully applied.
     *
     * @since   1.9.0
     *
     * @param   string  $code
     */
    public function on_coupon_applied( $code ) {

        self::bump( 'coupon_applied' );

    }

    /**
     * Classic checkout: contribute what was seen before this order.
     *
     * @since   1.9.0
     *
     * @param   array       $data
     * @param   \WP_Error   $errors
     */
    public function emit( $data, $errors ) {

        if( exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        self::assess( get_current_user_id() );

    }

    /**
     * Store API entry point.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order           $order
     * @param   \WP_REST_Request    $request
     */
    public function emit_store_api( $order, $request ) {

        if( exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        self::assess( $order->get_user_id() );

    }

    /**
     * Emit the account signals for the current visitor.
     *
     * @since   1.9.0
     *
     * @param   int     $user_id    Customer's user ID, 0 for a guest.
     */
    public static function assess( $user_id = 0 ) {

        $coupon_limit = (int) settings::get( 'mshield_coupon_failure_threshold' );
        $coupons      = self::count( 'coupon_failures' );

        if( $coupon_limit > 0 && $coupons > $coupon_limit ) {
            risk_context::add(
                'coupon_bruteforce',
                sprintf( '%d invalid coupon codes tried in the last hour', $coupons )
            );
        }

        $login_limit = (int) settings::get( 'mshield_login_failure_threshold' );
        $logins      = self::count( 'login_failures' );

        if( $login_limit > 0 && $logins > $login_limit ) {
            risk_context::add(
                'login_failures',
                sprintf( '%d failed logins from this address in the last hour', $logins )
            );
        }

        $reg_limit = (int) settings::get( 'mshield_registration_threshold' );
        $regs      = self::count( 'registrations' );

        if( $reg_limit > 0 && $regs > $reg_limit ) {
            risk_context::add(
                'registration_velocity',
                sprintf( '%d accounts created from this address in the last hour', $regs )
            );
        }

        self::assess_account_age( $user_id );

    }

    /**
     * Flag an account created moments before it was used.
     *
     * A brand-new account is completely ordinary on its own — everyone has one
     * once. What makes it worth noting is speed: an account created minutes
     * before it places an order has skipped the part where a real customer
     * browses, hesitates, and comes back.
     *
     * @since   1.9.0
     *
     * @param   int     $user_id
     */
    private static function assess_account_age( $user_id ) {

        $user_id = (int) $user_id;
        if( $user_id <= 0 ) return;

        $minutes = (int) settings::get( 'mshield_new_account_minutes' );
        if( $minutes <= 0 ) return;

        $user = get_userdata( $user_id );
        if( ! $user ) return;

        $registered = strtotime( $user->user_registered );
        if( ! $registered ) return;

        $age = ( time() - $registered ) / MINUTE_IN_SECONDS;

        if( $age > $minutes ) return;

        risk_context::add(
            'account_new',
            sprintf( 'Account was created %d minutes before this order', max( 0, (int) $age ) )
        );

    }

}
