<?php
/**
 * Velocity Detector.
 *
 * Detects rapid-fire order patterns characteristic of card testing.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\risk_context;

class velocity_detector {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Score at validation, against the orders this address has already
        // placed. This used to run only after the order existed, which meant
        // velocity could never contribute to a refusal -- the one decision it
        // is most obviously for. Counting still happens post-order, below,
        // because an order is not an order until it is one.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess_checkout' ], 40, 2 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'assess_draft' ], 40, 2 );

        add_action( 'woocommerce_checkout_order_processed', [ $this, 'track_order' ], 10, 3 );

        // The block checkout registered nothing here at all, so a store on
        // block checkout counted no order velocity whatsoever and the two
        // velocity signals could not fire on it.
        add_action( 'woocommerce_store_api_checkout_order_processed', [ $this, 'track_store_api' ], 10, 1 );

    }

    /**
     * Score velocity on classic checkout, before any order exists.
     *
     * @since   2.2.0
     *
     * @param   array       $data   Checkout posted data.
     * @param   \WP_Error   $errors Unused — this layer does not refuse.
     */
    public function assess_checkout( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        $this->check_thresholds( ip_utils::get_client_ip() );

    }

    /**
     * Score velocity on the block checkout, before payment.
     *
     * @since   2.2.0
     *
     * @param   \WC_Order          $order
     * @param   \WP_REST_Request   $request
     */
    public function assess_draft( $order, $request ) {

        if( \MightyShield\Includes\exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $this->check_thresholds( ip_utils::get_client_ip() );

    }

    /**
     * Count a placed order against this address.
     *
     * @since   1.0.0
     *
     * @param   int     $order_id   Order ID.
     * @param   array   $posted     Posted data.
     * @param   object  $order      WC_Order object.
     */
    public function track_order( $order_id, $posted, $order ) {

        $this->track( $order );

    }

    /**
     * Count a placed block-checkout order against this address.
     *
     * @since   2.2.0
     *
     * @param   \WC_Order   $order
     */
    public function track_store_api( $order ) {

        $this->track( $order );

    }

    /**
     * Record the order against the IP's counters. Counts only; never scores.
     *
     * @since   2.2.0
     *
     * @param   \WC_Order   $order
     */
    private function track( $order ) {

        if( ! is_object( $order ) || ! method_exists( $order, 'get_billing_email' ) ) return;

        if( \MightyShield\Includes\exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $ip    = ip_utils::get_client_ip();
        $email = $order->get_billing_email() ?? '';

        if( ! empty( $email ) ) {
            $this->track_email( $ip, $email );
        }

        $this->track_order_count( $ip );

    }

    /**
     * Track unique email addresses used by an IP.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     Client IP.
     * @param   string  $email  Billing email.
     */
    private function track_email( $ip, $email ) {

        // Distinct-email counting needs the set, not just a tally, so this one
        // genuinely needs a collection. It lives in the rate-limit table rather
        // than a transient for the same reason as the order counter below.
        $hash = md5( strtolower( trim( $email ) ) );

        // The IP hash is a literal PREFIX, not folded into one digest — the
        // count below matches on it with LIKE, and md5 of the whole string
        // shares no prefix with md5 of the IP, so that query could never match
        // and distinct-email velocity would silently never fire.
        db::increment_rate_limit( md5( $ip ) . ':' . $hash, 'vel_email_seen', HOUR_IN_SECONDS );

    }

    /**
     * How many distinct emails this IP has used in the window.
     *
     * @since   1.9.0
     *
     * @param   string  $ip
     * @return  int
     */
    private function unique_emails( $ip ) {

        global $wpdb;

        return (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}mshield_rate_limits
             WHERE action_type = 'vel_email_seen'
               AND identifier LIKE %s
               AND window_end >= %s",
            $wpdb->esc_like( md5( $ip ) . ':' ) . '%',
            gmdate( 'Y-m-d H:i:s' )
        ) );

    }

    /**
     * Track order count per IP.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     Client IP.
     */
    private function track_order_count( $ip ) {

        // Counted in the rate-limit table, not a transient. Under a persistent
        // object cache a transient can be evicted at any moment, which would
        // silently reset the counter and disable velocity detection precisely
        // when a burst of orders was filling the cache.
        db::increment_rate_limit( md5( $ip . '|orders' ), 'vel_orders', 15 * MINUTE_IN_SECONDS );

    }

    /**
     * Check velocity thresholds and block if exceeded.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     Client IP.
     */
    private function check_thresholds( $ip ) {

        $email_threshold = (int) settings::get( 'mshield_velocity_email_threshold' );
        $emails          = $this->unique_emails( $ip );

        if( $email_threshold > 0 && $emails > $email_threshold ) {
            risk_context::add( 'velocity_emails', sprintf( '%d unique emails from this IP in the last hour (limit %d)', $emails, $email_threshold ) );
            rate_limiter::temp_block_ip( $ip, "Velocity: {$email_threshold}+ unique emails in 1 hour" );
            return;
        }

        $order_threshold = (int) settings::get( 'mshield_velocity_order_threshold' );
        $order_count     = db::check_rate_limit( md5( $ip . '|orders' ), 'vel_orders' );

        if( $order_threshold > 0 && $order_count > $order_threshold ) {
            risk_context::add( 'velocity_orders', sprintf( '%d orders from this IP in the last 15 minutes (limit %d)', $order_count, $order_threshold ) );
            rate_limiter::temp_block_ip( $ip, "Velocity: {$order_threshold}+ orders in 15 minutes" );
            return;
        }

    }

}
