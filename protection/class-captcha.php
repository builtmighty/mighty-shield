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

        add_action( 'woocommerce_after_checkout_billing_form', [ $this, 'render_field' ] );
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'block_checkout' ], 20, 2 );
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'flag_order' ], 5, 3 );

        if( is_admin() ) {
            add_action( 'admin_notices', [ $this, 'render_degraded_notice' ] );
        }

    }

    /**
     * Enqueue the provider script + our helper (idempotent by handle).
     *
     * Called from render_field() so it loads wherever the checkout billing form
     * actually renders (classic, shortcode, and one-page checkouts), not only
     * when is_checkout() is true.
     *
     * @since   1.2.0
     */
    public function enqueue_scripts() {

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

        // Only render once per request (one-page checkouts may re-render the form).
        static $done = false;
        if( $done ) return;
        $done = true;

        $this->enqueue_scripts();

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

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

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

        if( \MightyShield\Includes\exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

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
     * Verify a challenge token server-side (self-contained, reusable by the
     * Store API/block checkout). Fails open on transport error or a provider
     * misconfiguration so it never blocks all legitimate checkouts.
     *
     * @since   1.8.0
     *
     * @param   string  $provider   'turnstile' or 'recaptcha_v3'.
     * @param   string  $secret     Provider secret key.
     * @param   string  $token      Submitted challenge token.
     * @return  bool
     */
    public static function verify( $provider, $secret, $token ) {

        if( $token === '' || $secret === '' ) return false;

        $endpoint = $provider === 'turnstile' ? self::TURNSTILE_VERIFY : self::RECAPTCHA_VERIFY;

        $response = wp_remote_post( $endpoint, [
            'timeout' => 5,
            'body'    => [ 'secret' => $secret, 'response' => $token, 'remoteip' => ip_utils::get_client_ip() ],
        ] );

        if( is_wp_error( $response ) ) return true; // fail open on outage

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if( ! is_array( $body ) || empty( $body['success'] ) ) {
            $codes = ( is_array( $body ) && ! empty( $body['error-codes'] ) ) ? (array) $body['error-codes'] : [];
            if( array_intersect( $codes, [ 'invalid-input-secret', 'missing-input-secret', 'bad-request' ] ) ) {
                return true; // fail open on misconfiguration
            }
            return false;
        }

        if( $provider === 'recaptcha_v3' && isset( $body['score'] ) ) {
            return ( (float) $body['score'] >= self::RECAPTCHA_MIN_SCORE );
        }

        return true;

    }

    private function is_verified() {

        if( $this->verified !== null ) return $this->verified;

        // Test-mode force-trip (enforce mode); simulate mode logs and passes.
        if( \MightyShield\Includes\test_mode::should_trip( 'captcha', 'Forced CAPTCHA failure' ) ) {
            $this->verified = false;
            return false;
        }

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

            // Distinguish a genuine failed challenge from a plugin
            // misconfiguration (wrong/missing secret). A misconfiguration must
            // NOT block every checkout — fail open and alert the admin instead.
            $codes  = ( is_array( $body ) && ! empty( $body['error-codes'] ) ) ? (array) $body['error-codes'] : [];
            $config = array_intersect( $codes, [ 'invalid-input-secret', 'missing-input-secret', 'bad-request' ] );

            if( ! empty( $config ) ) {
                $this->alert_degraded( implode( ', ', $config ) );
                $this->verified = true;
                return true;
            }

            $this->verified = false;
            return false;

        }

        // A successful verification means configuration is healthy — clear any
        // lingering degraded flag so the admin notice disappears.
        if( get_option( 'mshield_captcha_degraded' ) ) {
            delete_option( 'mshield_captcha_degraded' );
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
     * Record and (once per day) alert on a CAPTCHA misconfiguration.
     *
     * @since   1.7.0
     *
     * @param   string  $error  The provider error code(s) that triggered it.
     */
    private function alert_degraded( $error ) {

        update_option( 'mshield_captcha_degraded', [ 'time' => time(), 'message' => $error ], false );

        if( get_transient( 'mshield_captcha_alerted' ) ) return;
        set_transient( 'mshield_captcha_alerted', 1, DAY_IN_SECONDS );

        $admin_email = get_option( 'admin_email' );
        $subject     = '[MightyShield] Bot challenge is misconfigured';
        $message     = sprintf(
            "MightyShield's bot challenge (%s) is rejecting all tokens because of a configuration error: %s.\n\n" .
            "To avoid blocking legitimate checkouts, the challenge is temporarily failing open (allowing orders) until this is fixed.\n\n" .
            "Check the Site Key and Secret Key under MightyShield > Fraud Checks > Bot Challenge.\n\n" .
            "This alert is sent at most once per day.",
            $this->provider,
            $error
        );

        wp_mail( $admin_email, $subject, $message );

    }

    /**
     * Show an admin notice while the bot challenge is misconfigured.
     *
     * @since   1.7.0
     */
    public function render_degraded_notice() {

        if( ! current_user_can( 'manage_woocommerce' ) ) return;

        $degraded = get_option( 'mshield_captcha_degraded' );
        if( empty( $degraded ) || empty( $degraded['time'] ) ) return;
        if( ( time() - (int) $degraded['time'] ) > DAY_IN_SECONDS ) return;

        printf(
            '<div class="notice notice-error"><p><strong>%s</strong> %s</p></div>',
            esc_html__( 'MightyShield:', 'mighty-shield' ),
            esc_html( sprintf(
                /* translators: %s: provider error code. */
                __( 'The bot challenge is misconfigured (%s) and is failing open so it does not block checkout. Verify your Site Key and Secret Key under Fraud Checks.', 'mighty-shield' ),
                $degraded['message']
            ) )
        );

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
