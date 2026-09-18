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
use MightyShield\Includes\risk_context;

class honeypot {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        if( settings::get( 'mshield_honeypot_enabled' ) !== 'yes' ) return;

        add_action( 'woocommerce_after_checkout_billing_form', [ $this, 'render_field' ] );
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess_checkout' ], 1, 2 );

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
     * Score the honeypot. Runs before any order exists, and only scores.
     *
     * Whether a filled trap field turns a customer away is not decided here any
     * more. This emits the signal; the honeypot signal carries a `rejected`
     * floor, so risk_recorder refuses the checkout at priority 99 — the one
     * place in the plugin that refuses anything.
     *
     * The temp block stays, because it is not a refusal: it is a fact about the
     * address recorded for the next request to score against, and honeypot is
     * the least ambiguous evidence the plugin has. No person can see the field.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object, unused — this layer does not refuse.
     */
    public function assess_checkout( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        if( ! $this->is_triggered() ) return;

        $ip    = ip_utils::get_client_ip();
        $value = $this->get_value();

        risk_context::add( 'honeypot', 'Honeypot field filled (bot detected)' );

        db::log_event( $ip, 'classic_checkout', 'flagged', 'Honeypot field filled (bot detected): "' . substr( $value, 0, 100 ) . '"' );

        // Temp-block the IP, through rate_limiter rather than by hand: the
        // hand-rolled version stored a bare true with no reason and wrote no log
        // entry, so this block left nothing behind to explain itself.
        rate_limiter::temp_block_ip( $ip, __( 'Filled the hidden trap field on checkout', 'mighty-shield' ) );

    }

    /**
     * Whether the honeypot field was filled in.
     *
     * @since   1.0.0
     *
     * @return  bool
     */
    private function is_triggered() {

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

}
