<?php
/**
 * Honeypot.
 *
 * Adds an invisible field to the checkout form that only bots fill in.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;

class honeypot {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        if( settings::get( 'mshield_honeypot_enabled' ) !== 'yes' ) return;

        add_action( 'woocommerce_after_checkout_billing_form', [ $this, 'render_field' ] );
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'block_field' ], 1, 2 );
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'flag_field' ], 5, 3 );

    }

    /**
     * Render hidden honeypot field in checkout form.
     *
     * @since   1.0.0
     */
    public function render_field() {

        echo '<div class="mshield-hp-wrap" aria-hidden="true" style="position:absolute;left:-9999px;top:-9999px;overflow:hidden;">';
        echo '<label for="mshield_hp_field">' . esc_html__( 'Leave this empty', 'mighty-shield' ) . '</label>';
        echo '<input type="text" name="mshield_hp_field" id="mshield_hp_field" value="" tabindex="-1" autocomplete="off" />';
        echo '</div>';

    }

    /**
     * Block checkout when the honeypot field is filled.
     *
     * Runs before order creation. Only active when the configured action is
     * "block".
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function block_field( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        if( settings::get( 'mshield_honeypot_action' ) !== 'block' ) return;

        if( ! $this->is_triggered() ) return;

        $ip    = ip_utils::get_client_ip();
        $value = $this->get_value();
        db::log_event( $ip, 'classic_checkout', 'blocked', 'Honeypot field filled (bot detected): "' . substr( $value, 0, 100 ) . '"' );

        // Temp-block the IP.
        $duration = (int) settings::get( 'mshield_temp_block_duration' );
        set_transient( 'mshield_tempblock_' . md5( $ip ), true, $duration );

        $errors->add( 'mighty_shield_honeypot', __( 'This order could not be processed. Please contact support.', 'mighty-shield' ) );

    }

    /**
     * Flag an order when the honeypot field is filled.
     *
     * Runs after order creation. Active when the configured action is "flag"
     * or "notify".
     *
     * @since   1.0.0
     *
     * @param   int     $order_id   Order ID.
     * @param   array   $posted     Posted data.
     * @param   object  $order      WC_Order object.
     */
    public function flag_field( $order_id, $posted, $order ) {

        if( \MightyShield\Includes\exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $action = settings::get( 'mshield_honeypot_action' );
        if( $action === 'block' ) return;

        if( ! $this->is_triggered() ) return;

        $ip     = ip_utils::get_client_ip();
        $value  = $this->get_value();
        $reason = 'Honeypot field filled (bot detected): "' . substr( $value, 0, 100 ) . '"';

        db::log_event( $ip, 'classic_checkout', 'flagged', $reason );
        $order->add_order_note( 'MightyShield: ' . $reason );
        $order->update_meta_data( '_mshield_flagged', 'honeypot' );
        $order->save();

        if( $action === 'notify' ) {
            $this->send_admin_notification( $order, $reason );
        }

    }

    /**
     * Whether the honeypot field was filled in.
     *
     * @since   1.0.0
     *
     * @return  bool
     */
    private function is_triggered() {

        if( \MightyShield\Includes\test_mode::should_trip( 'honeypot', 'Forced honeypot trip' ) ) return true;

        return $this->get_value() !== '';

    }

    /**
     * Get the submitted honeypot value.
     *
     * @since   1.0.0
     *
     * @return  string
     */
    private function get_value() {

        return isset( $_POST['mshield_hp_field'] ) ? sanitize_text_field( wp_unslash( $_POST['mshield_hp_field'] ) ) : '';

    }

    /**
     * Send admin notification email.
     *
     * @since   1.0.0
     *
     * @param   object  $order  WC_Order object.
     * @param   string  $reason Reason for flagging.
     */
    private function send_admin_notification( $order, $reason ) {

        $admin_email = get_option( 'admin_email' );
        $subject     = sprintf( '[MightyShield] Honeypot triggered on order #%d', $order->get_id() );
        $message     = sprintf(
            "The checkout honeypot field was filled on an order flagged by MightyShield (likely a bot).\n\nOrder: #%d\nReason: %s\nCustomer: %s (%s)\nIP: %s\n\nReview this order: %s",
            $order->get_id(),
            $reason,
            $order->get_formatted_billing_full_name(),
            $order->get_billing_email(),
            $order->get_customer_ip_address(),
            $order->get_edit_order_url()
        );

        wp_mail( $admin_email, $subject, $message );

    }

}
