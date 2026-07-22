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

class velocity_detector {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Track after order is created.
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'track_order' ], 10, 3 );

    }

    /**
     * Track order velocity.
     *
     * @since   1.0.0
     *
     * @param   int     $order_id   Order ID.
     * @param   array   $posted     Posted data.
     * @param   object  $order      WC_Order object.
     */
    public function track_order( $order_id, $posted, $order ) {

        if( \MightyShield\Includes\exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $ip    = ip_utils::get_client_ip();
        $email = $order->get_billing_email() ?? '';

        // Track unique emails per IP.
        if( ! empty( $email ) ) {
            $this->track_email( $ip, $email );
        }

        // Track order count per IP.
        $this->track_order_count( $ip );

        // Check thresholds.
        $this->check_thresholds( $ip );

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

        $key    = 'mshield_emails_' . md5( $ip );
        $emails = get_transient( $key );

        if( ! is_array( $emails ) ) {
            $emails = [];
        }

        $email_hash = md5( strtolower( trim( $email ) ) );
        if( ! in_array( $email_hash, $emails, true ) ) {
            $emails[] = $email_hash;
        }

        // Store for 1 hour.
        set_transient( $key, $emails, HOUR_IN_SECONDS );

    }

    /**
     * Track order count per IP.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     Client IP.
     */
    private function track_order_count( $ip ) {

        $key   = 'mshield_orders_' . md5( $ip );
        $count = (int) get_transient( $key );
        $count++;

        // Store for 15 minutes.
        set_transient( $key, $count, 15 * MINUTE_IN_SECONDS );

    }

    /**
     * Check velocity thresholds and block if exceeded.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     Client IP.
     */
    private function check_thresholds( $ip ) {

        // Check unique emails threshold.
        $email_threshold = (int) settings::get( 'mshield_velocity_email_threshold' );
        $email_key       = 'mshield_emails_' . md5( $ip );
        $emails          = get_transient( $email_key );

        if( is_array( $emails ) && count( $emails ) > $email_threshold ) {
            rate_limiter::temp_block_ip( $ip, "Velocity: {$email_threshold}+ unique emails in 1 hour" );
            return;
        }

        // Check order count threshold.
        $order_threshold = (int) settings::get( 'mshield_velocity_order_threshold' );
        $order_key       = 'mshield_orders_' . md5( $ip );
        $order_count     = (int) get_transient( $order_key );

        if( $order_count > $order_threshold ) {
            rate_limiter::temp_block_ip( $ip, "Velocity: {$order_threshold}+ orders in 15 minutes" );
            return;
        }

    }

}
