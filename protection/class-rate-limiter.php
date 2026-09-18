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
use MightyShield\Includes\risk_context;
use MightyShield\Includes\response;

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

        // A temporary block costs trust; it does not turn anyone away.
        //
        // It is MightyShield's own inference -- five declined cards in an hour,
        // a browser that declared itself automated -- and it is keyed on an IP
        // address, which behind a carrier NAT, an office or a campus is
        // hundreds of unrelated people. Refusing on it meant one shopper
        // working through three cards locked out everybody sharing their
        // address for a day. At 60 trust it still drops a first-time order
        // into High on its own, which is a hold and a look from a human.
        //
        // The floor came off this signal earlier; the refusal here outlived it
        // and was doing the same job by another route.
        if( $this->is_temp_blocked( $ip ) ) {

            risk_context::add( 'ip_temp_blocked', 'IP is under a temporary block' );

            db::log_event( $ip, 'classic_checkout', 'flagged', 'Temporarily blocked IP' );

            return;

        }

        // Check rate limit.
        $limit  = (int) settings::get( 'mshield_rate_checkout_limit' );
        $window = (int) settings::get( 'mshield_rate_checkout_window' );

        $identifier = md5( $ip . '|checkout' );
        $count = db::increment_rate_limit( $identifier, 'checkout', $window );

        // Also a score. The cap still turns a shopper away on a store that has
        // not touched the setting -- rate_limited is worth 80, which is inside
        // the rejected band on its own -- but it is the engine that turns them
        // away, and the merchant can see and change the number on the Scoring
        // tab instead of discovering it in this file.
        if( $count > $limit ) {

            risk_context::add( 'rate_limited', "Checkout rate limit exceeded: {$count}/{$limit}" );

            db::log_event( $ip, 'classic_checkout', 'rate_limited', "Checkout rate limit exceeded: {$count}/{$limit}" );

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
