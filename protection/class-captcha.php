<?php
/**
 * CAPTCHA / Bot Challenge.
 *
 * Adds a Cloudflare Turnstile or Google reCAPTCHA v3 challenge to the classic
 * checkout and verifies the token server-side. Strong defense against automated
 * card-runners, unaffected by IP rotation.
 *
 * @package MightyShield
 * @since   1.2.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;

class captcha {

    /**
     * Turnstile siteverify endpoint.
     *
     * @since   1.2.0
     */
    private const TURNSTILE_VERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

    /**
     * reCAPTCHA siteverify endpoint.
     *
     * @since   1.2.0
     */
    private const RECAPTCHA_VERIFY = 'https://www.google.com/recaptcha/api/siteverify';

    /**
     * Minimum passing score for reCAPTCHA v3 (0.0 - 1.0).
     *
     * @since   1.2.0
     */
    private const RECAPTCHA_MIN_SCORE = 0.5;

    /**
     * Memoized verification result for this request.
     *
     * @since   1.2.0
     */
    private $verified = null;

    /**
     * Active provider.
     *
     * @since   1.2.0
     */
    private $provider = 'off';

    /**
     * Construct.
     *
     * @since   1.2.0
     */
    public function __construct() {

        $this->provider = settings::get( 'mshield_captcha_provider' );

        if( $this->provider !== 'turnstile' && $this->provider !== 'recaptcha_v3' ) return;
        if( settings::get( 'mshield_captcha_site_key' ) === '' || settings::get( 'mshield_captcha_secret_key' ) === '' ) return;

        add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
        add_action( 'woocommerce_after_checkout_billing_form', [ $this, 'render_field' ] );
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'block_checkout' ], 20, 2 );
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'flag_order' ], 5, 3 );

    }

    /**
     * Enqueue the provider script + our helper.
     *
     * @since   1.2.0
     */
    public function enqueue_scripts() {

        if( ! is_checkout() ) return;

        $site_key = settings::get( 'mshield_captcha_site_key' );

        if( $this->provider === 'turnstile' ) {
            wp_enqueue_script( 'mshield-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', [], null, [ 'in_footer' => true ] );
        } else {
            wp_enqueue_script( 'mshield-recaptcha', 'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $site_key ), [], null, [ 'in_footer' => true ] );
        }

        wp_enqueue_script( 'mshield-captcha', MSHIELD_URI . 'assets/js/mshield-captcha.js', [], MSHIELD_VERSION, [ 'in_footer' => true ] );
        wp_localize_script( 'mshield-captcha', 'mshieldCaptcha', [
            'provider' => $this->provider,
            'siteKey'  => $site_key,
        ] );

    }

    /**
     * Render the challenge widget / token field.
     *
     * @since   1.2.0
     */
    public function render_field() {

        // Hidden token field used by reCAPTCHA v3 (Turnstile injects its own field).
        echo '<input type="hidden" name="mshield_captcha_token" id="mshield_captcha_token" value="" />';

        if( $this->provider === 'turnstile' ) {
            echo '<div class="cf-turnstile" data-sitekey="' . esc_attr( settings::get( 'mshield_captcha_site_key' ) ) . '"></div>';
        }

    }

    /**
     * Block checkout on a failed challenge (action = block).
     *
     * @since   1.2.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function block_checkout( $data, $errors ) {

        if( settings::get( 'mshield_captcha_action' ) !== 'block' ) return;

        if( $this->is_verified() ) return;

        $ip = ip_utils::get_client_ip();
        db::log_event( $ip, 'classic_checkout', 'blocked', 'CAPTCHA challenge failed (' . $this->provider . ')' );

        $errors->add( 'mighty_shield_captcha', __( 'Bot verification failed. Please reload the page and try again.', 'mighty-shield' ) );

    }

    /**
     * Flag an order on a failed challenge (action = flag / notify).
     *
     * @since   1.2.0
     *
     * @param   int     $order_id   Order ID.
     * @param   array   $posted     Posted data.
     * @param   object  $order      WC_Order object.
     */
    public function flag_order( $order_id, $posted, $order ) {

        $action = settings::get( 'mshield_captcha_action' );
        if( $action === 'block' ) return;

        if( $this->is_verified() ) return;

        $ip     = ip_utils::get_client_ip();
        $reason = 'CAPTCHA challenge failed (' . $this->provider . ')';

        db::log_event( $ip, 'classic_checkout', 'flagged', $reason );
        $order->add_order_note( 'MightyShield: ' . $reason );
        $order->update_meta_data( '_mshield_flagged', 'captcha' );
        $order->save();

        if( $action === 'notify' ) {
            $this->send_admin_notification( $order, $reason );
        }

    }

    /**
     * Verify the submitted challenge token (memoized per request).
     *
     * @since   1.2.0
     *
     * @return  bool
     */
    private function is_verified() {

        if( $this->verified !== null ) return $this->verified;

        $field = $this->provider === 'turnstile' ? 'cf-turnstile-response' : 'mshield_captcha_token';
        $token = isset( $_POST[ $field ] ) ? sanitize_text_field( wp_unslash( $_POST[ $field ] ) ) : '';

        if( $token === '' ) {
            $this->verified = false;
            return false;
        }

        $endpoint = $this->provider === 'turnstile' ? self::TURNSTILE_VERIFY : self::RECAPTCHA_VERIFY;

        $response = wp_remote_post( $endpoint, [
            'timeout' => 5,
            'body'    => [
                'secret'   => settings::get( 'mshield_captcha_secret_key' ),
                'response' => $token,
                'remoteip' => ip_utils::get_client_ip(),
            ],
        ] );

        // On a network/API error, fail open so a provider outage can't block all
        // legitimate checkouts.
        if( is_wp_error( $response ) ) {
            $this->verified = true;
            return true;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if( ! is_array( $body ) || empty( $body['success'] ) ) {
            $this->verified = false;
            return false;
        }

        // reCAPTCHA v3 returns a score; enforce a minimum threshold.
        if( $this->provider === 'recaptcha_v3' && isset( $body['score'] ) ) {
            $this->verified = ( (float) $body['score'] >= self::RECAPTCHA_MIN_SCORE );
            return $this->verified;
        }

        $this->verified = true;
        return true;

    }

    /**
     * Send admin notification email.
     *
     * @since   1.2.0
     *
     * @param   object  $order  WC_Order object.
     * @param   string  $reason Reason for flagging.
     */
    private function send_admin_notification( $order, $reason ) {

        $admin_email = get_option( 'admin_email' );
        $subject     = sprintf( '[MightyShield] CAPTCHA failure on order #%d', $order->get_id() );
        $message     = sprintf(
            "An order failed the MightyShield bot challenge.\n\nOrder: #%d\nReason: %s\nCustomer: %s (%s)\nIP: %s\n\nReview this order: %s",
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
