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

defined( 'ABSPATH' ) || exit;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\risk_context;

class failed_payment_tracker {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Track failed payment orders.
        add_action( 'woocommerce_order_status_failed', [ $this, 'track_failure' ], 10, 2 );

        // And charge the NEXT checkout for them. track_failure() runs after the
        // order exists and after its verdict was written, so a signal emitted
        // there went into a context nothing evaluated again -- failed_payments
        // never reached a single recorded rating. The count is what carries
        // over; this reads it at validation, where it can still change the
        // outcome. Priority 12: after the cheap structural checks, before the
        // scorers that build on the whole picture.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess_checkout' ], 12 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'assess_checkout' ], 12 );

    }

    /**
     * Charge this checkout for the declines that came before it.
     *
     * @since   2.3.0
     */
    public function assess_checkout() {

        $ip = ip_utils::get_client_ip();
        if( empty( $ip ) ) return;

        $count     = (int) get_transient( 'mshield_fail_' . md5( $ip ) );
        $threshold = (int) settings::get( 'mshield_failed_payment_threshold' );

        if( $threshold > 0 && $count >= $threshold ) {
            risk_context::add( 'failed_payments', "Repeated payment failures from this IP: {$count} in 1 hour" );
        }

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

        // The address MightyShield resolved for this order, never the one
        // WooCommerce copied from a request header: a card tester who set
        // X-Real-IP to a fresh value per attempt was spreading their declines
        // across addresses nobody had, and the threshold was never reached.
        $ip = is_object( $order ) && method_exists( $order, 'get_meta' ) ? (string) $order->get_meta( '_mshield_ip' ) : '';
        if( $ip === '' ) $ip = ip_utils::get_client_ip();

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
            risk_context::add( 'failed_payments', "Repeated payment failures from this IP: {$count} in 1 hour" );

            rate_limiter::temp_block_ip( $ip, "Failed payment threshold exceeded: {$count}/{$threshold} in 1 hour" );
        }

    }

}
