<?php
/**
 * Rate Limiter.
 *
 * Per-IP rate limiting for checkout attempts on classic checkout.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;

class rate_limiter {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Check on classic checkout submission.
        add_action( 'woocommerce_checkout_process', [ $this, 'check_checkout_rate' ], 1 );

    }

    /**
     * Check checkout rate limit.
     *
     * Fires at the very start of checkout processing.
     *
     * @since   1.0.0
     */
    public function check_checkout_rate() {

        if( \MightyShield\Includes\exempt::is_exempt( isset( $_POST['billing_email'] ) ? sanitize_email( wp_unslash( $_POST['billing_email'] ) ) : '' ) ) return;

        $ip = ip_utils::get_client_ip();

        // Test-mode force-trip.
        if( \MightyShield\Includes\test_mode::should_trip( 'rate_limit', 'Forced rate-limit trip' ) ) {
            db::log_event( $ip, 'classic_checkout', 'rate_limited', 'Test mode: forced rate-limit trip' );
            wc_add_notice( __( 'Too many checkout attempts. Please wait and try again later.', 'mighty-shield' ), 'error' );
            return;
        }

        // Check if IP is temporarily blocked.
        if( $this->is_temp_blocked( $ip ) ) {

            db::log_event( $ip, 'classic_checkout', 'blocked', 'Temporarily blocked IP' );
            wc_add_notice( __( 'Your access has been temporarily restricted. Please try again later.', 'mighty-shield' ), 'error' );
            return;

        }

        // Check rate limit.
        $limit  = (int) settings::get( 'mshield_rate_checkout_limit' );
        $window = (int) settings::get( 'mshield_rate_checkout_window' );

        $identifier = md5( $ip . '|checkout' );
        $count = db::increment_rate_limit( $identifier, 'checkout', $window );

        if( $count > $limit ) {

            db::log_event( $ip, 'classic_checkout', 'rate_limited', "Checkout rate limit exceeded: {$count}/{$limit}" );
            wc_add_notice( __( 'Too many checkout attempts. Please wait and try again later.', 'mighty-shield' ), 'error' );
            return;

        }

    }

    /**
     * Check if an IP is temporarily blocked.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     IP address.
     * @return  bool
     */
    public static function is_temp_blocked( $ip ) {

        // Whitelisted IPs are never treated as temp-blocked, even if a
        // transient was set before the IP was whitelisted.
        if( \MightyShield\Firewall\ip_whitelist::is_whitelisted( $ip ) ) return false;

        $key = 'mshield_tempblock_' . md5( $ip );
        return (bool) get_transient( $key );

    }

    /**
     * Temporarily block an IP.
     *
     * @since   1.0.0
     *
     * @param   string  $ip         IP address to block.
     * @param   string  $reason     Reason for the block.
     */
    public static function temp_block_ip( $ip, $reason = '' ) {

        $duration = (int) settings::get( 'mshield_temp_block_duration' );
        $key      = 'mshield_tempblock_' . md5( $ip );

        set_transient( $key, [
            'ip'      => $ip,
            'reason'  => $reason,
            'blocked' => time(),
        ], $duration );

        db::log_event( $ip, 'system', 'blocked', 'Temporary block: ' . $reason );

    }

}
