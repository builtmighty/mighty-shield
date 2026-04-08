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
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'check_field' ], 1, 2 );

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
     * Check honeypot field — if filled, it's a bot.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function check_field( $data, $errors ) {

        $honeypot_value = isset( $_POST['mshield_hp_field'] ) ? sanitize_text_field( $_POST['mshield_hp_field'] ) : '';

        if( ! empty( $honeypot_value ) ) {

            $ip = ip_utils::get_client_ip();
            db::log_event( $ip, 'classic_checkout', 'blocked', 'Honeypot field filled (bot detected): "' . substr( $honeypot_value, 0, 100 ) . '"' );

            // Temp-block the IP.
            $duration = (int) settings::get( 'mshield_temp_block_duration' );
            set_transient( 'mshield_tempblock_' . md5( $ip ), true, $duration );

            $errors->add( 'mighty_shield_honeypot', __( 'This order could not be processed. Please contact support.', 'mighty-shield' ) );

        }

    }

}
