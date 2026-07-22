<?php
/**
 * Failed Payment Tracker.
 *
 * Blocks IPs after repeated payment failures.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;

class failed_payment_tracker {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Track failed payment orders.
        add_action( 'woocommerce_order_status_failed', [ $this, 'track_failure' ], 10, 2 );

    }

    /**
     * Track a failed payment.
     *
     * @since   1.0.0
     *
     * @param   int     $order_id   Order ID.
     * @param   object  $order      WC_Order object.
     */
    public function track_failure( $order_id, $order ) {

        if( \MightyShield\Includes\exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        // Get the IP from the order, fall back to current request IP.
        $ip = $order->get_customer_ip_address();
        if( empty( $ip ) ) {
            $ip = ip_utils::get_client_ip();
        }

        // Increment failure count.
        $key   = 'mshield_fail_' . md5( $ip );
        $count = (int) get_transient( $key );
        $count++;

        // Store for 1 hour.
        set_transient( $key, $count, HOUR_IN_SECONDS );

        // Log the failure.
        db::log_event( $ip, 'payment_failed', 'flagged', "Failed payment #{$order_id} (count: {$count})" );

        // Check threshold.
        $threshold = (int) settings::get( 'mshield_failed_payment_threshold' );
        if( $count >= $threshold ) {
            rate_limiter::temp_block_ip( $ip, "Failed payment threshold exceeded: {$count}/{$threshold} in 1 hour" );
        }

    }

}
