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
use MightyShield\Includes\risk_context;

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
        // Priority 20, so the signal is in the context well before
        // risk_recorder::refuse_classic() reads it at 99.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess' ], 20, 2 );

        if( is_admin() ) {
            add_action( 'admin_notices', [ $this, 'render_degraded_notice' ] );
        }

    }

    /**
     * Render the challenge widget on the classic checkout.
     *
     * @since   1.2.0
     */
    public function render_field() {

        // Once per request: a one-page checkout may re-render the billing form.
        static $done = false;
        if( $done ) return;
        $done = true;

        self::widget( 'checkout' );

    }

    /**
     * Record a failed challenge against the order's score.
     *
     * Emitting the signal is the whole job. It used to also refuse or flag the
     * checkout itself, driven by its own mshield_captcha_action setting -- a
     * second route to the same outcome, because captcha_failed already floors
     * to Rejected. Two systems deciding one thing is how they come to disagree,
     * so the setting is gone and the ladder decides.
     *
     * @since   1.2.0
     *
     * @param   array       $data   Checkout posted data.
     * @param   \WP_Error   $errors
     */
    public function assess( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        if( $this->is_verified() ) return;

        $reason = 'Bot challenge failed (' . $this->provider . ')';

        risk_context::add( 'captcha_failed', $reason );

        db::log_event( ip_utils::get_client_ip(), 'classic_checkout', 'flagged', $reason );

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
    public static function verify( $provider, $secret, $token, $action = '' ) {

        if( $token === '' || $secret === '' ) return false;

        $endpoint = $provider === 'turnstile' ? self::TURNSTILE_VERIFY : self::RECAPTCHA_VERIFY;

        $response = wp_remote_post( $endpoint, [
            'timeout' => 5,
            'body'    => [ 'secret' => $secret, 'response' => $token, 'remoteip' => ip_utils::get_client_ip() ],
        ] );

        if( is_wp_error( $response ) ) return true; // fail open on outage

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if( ! is_array( $body ) || empty( $body['success'] ) ) {
            // A genuine failed challenge and a wrong secret key look almost
            // identical here. Only the second must fail open, and it has to say
            // so out loud -- a challenge silently passing everyone is exactly
            // as bad as one silently refusing everyone.
            $codes  = ( is_array( $body ) && ! empty( $body['error-codes'] ) ) ? (array) $body['error-codes'] : [];
            $config = array_intersect( $codes, [ 'invalid-input-secret', 'missing-input-secret', 'bad-request' ] );

            if( ! empty( $config ) ) {
                self::alert_degraded( implode( ', ', $config ) );
                return true;
            }

            return false;
        }

        // The action binds a token to the form it came from. Without this a
        // token minted on the checkout page is a valid token everywhere, so
        // protecting the login form would have bought nothing: a script loads
        // checkout once, keeps the token, and posts it at wp-login.
        //
        // Only reCAPTCHA returns an action to check. Turnstile scopes its
        // tokens to the widget and burns them on first verification, which is
        // the same guarantee by a different route.
        if( $action !== '' && $provider === 'recaptcha_v3' && isset( $body['action'] ) ) {
            if( (string) $body['action'] !== $action ) return false;
        }

        if( $provider === 'recaptcha_v3' && isset( $body['score'] ) ) {
            return ( (float) $body['score'] >= self::RECAPTCHA_MIN_SCORE );
        }

        return true;

    }

    /**
     * Whether a challenge can actually be issued.
     *
     * A provider AND both keys. Every caller checks this before rendering a
     * widget or refusing a request — a half-configured challenge that refuses
     * everyone is worse than no challenge at all.
     *
     * @since   1.9.4
     *
     * @return  bool
     */
    public static function is_ready() {

        $provider = settings::get( 'mshield_captcha_provider' );

        if( $provider !== 'turnstile' && $provider !== 'recaptcha_v3' ) return false;

        return settings::get( 'mshield_captcha_site_key' ) !== ''
            && settings::get( 'mshield_captcha_secret_key' ) !== '';

    }

    /**
     * The reCAPTCHA action name for a surface.
     *
     * @since   1.9.4
     *
     * @param   string  $surface    checkout | login | register | lostpassword | comment.
     * @return  string
     */
    public static function action_for( $surface ) {

        // reCAPTCHA only accepts [A-Za-z/_] in an action.
        return 'mshield_' . preg_replace( '/[^a-z_]/', '', strtolower( (string) $surface ) );

    }

    /**
     * Load the provider script and the widget renderer for one surface.
     *
     * One handle per provider, always with explicit rendering. Two callers used
     * to register the same handle with different URLs -- store_api with
     * ?render=explicit and this class without -- and whichever ran second was a
     * silent no-op, so on a classic checkout with Store API checks enabled the
     * Turnstile widget never rendered, no token was posted, and the checkout was
     * refused for having failed a challenge it was never shown.
     *
     * @since   1.9.4
     *
     * @param   string  $surface
     */
    public static function enqueue( $surface ) {

        if( ! self::is_ready() ) return;

        $provider = settings::get( 'mshield_captcha_provider' );
        $site_key = settings::get( 'mshield_captcha_site_key' );

        if( $provider === 'turnstile' ) {
            wp_enqueue_script( 'mshield-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit', [], null, [ 'in_footer' => true ] );
        } else {
            wp_enqueue_script( 'mshield-recaptcha', 'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $site_key ), [], null, [ 'in_footer' => true ] );
        }

        wp_enqueue_script( 'mshield-challenge', MSHIELD_URI . 'assets/js/mshield-challenge.js', [], MSHIELD_VERSION, [ 'in_footer' => true ] );
        wp_localize_script( 'mshield-challenge', 'mshieldChallenge', [
            'provider' => $provider,
            'siteKey'  => $site_key,
            'action'   => self::action_for( $surface ),
        ] );

    }

    /**
     * Print the widget host and token field for one surface.
     *
     * @since   1.9.4
     *
     * @param   string  $surface
     */
    public static function widget( $surface ) {

        if( ! self::is_ready() ) return;

        self::enqueue( $surface );

        // One field name for both providers. Turnstile would inject its own
        // cf-turnstile-response, but rendering explicitly means the token comes
        // back through a callback, so it can go wherever we like -- and every
        // surface then reads the same key.
        printf(
            '<div class="mshield-challenge" data-surface="%s"></div>'
            . '<input type="hidden" name="mshield_captcha_token" class="mshield-challenge-token" value="" />',
            esc_attr( $surface )
        );

    }

    /**
     * Whether the challenge submitted with this request passes.
     *
     * Memoized per surface: a surface can be checked by more than one hook
     * (registration_errors and woocommerce_register_post both fire on a
     * WooCommerce signup) and a token is single-use at the provider, so
     * verifying twice would fail the second time.
     *
     * Returns TRUE when no challenge is configured. A half-configured captcha
     * that refuses everyone is worse than no captcha.
     *
     * @since   1.9.4
     *
     * @param   string  $surface
     * @return  bool    True when the request may proceed.
     */
    public static function passes( $surface ) {

        static $seen = [];

        if( isset( $seen[ $surface ] ) ) return $seen[ $surface ];

        if( ! self::is_ready() ) return $seen[ $surface ] = true;

        // Turnstile still posts its own field when a theme or another plugin
        // renders a widget implicitly, so accept either.
        $token = '';
        foreach( [ 'mshield_captcha_token', 'cf-turnstile-response', 'g-recaptcha-response' ] as $field ) {
            if( ! empty( $_POST[ $field ] ) ) {
                $token = sanitize_text_field( wp_unslash( $_POST[ $field ] ) );
                break;
            }
        }

        if( $token === '' ) return $seen[ $surface ] = false;

        $ok = self::verify(
            settings::get( 'mshield_captcha_provider' ),
            settings::get( 'mshield_captcha_secret_key' ),
            $token,
            self::action_for( $surface )
        );

        return $seen[ $surface ] = $ok;

    }

    /**
     * Whether this request's checkout challenge passed.
     *
     * Was a second, near-duplicate copy of verify() that had drifted from it —
     * different empty-token handling, its own degraded-alert bookkeeping. It
     * now defers, so there is one verification path and one set of fail-open
     * rules for every surface.
     *
     * @since   1.2.0
     *
     * @return  bool
     */
    private function is_verified() {

        if( $this->verified !== null ) return $this->verified;

        $this->verified = self::passes( 'checkout' );

        // A verified challenge means the configuration is healthy; clear any
        // lingering degraded flag so the admin notice goes away.
        if( $this->verified && get_option( 'mshield_captcha_degraded' ) ) {
            delete_option( 'mshield_captcha_degraded' );
        }

        return $this->verified;

    }

    /**
     * Record and (once per day) alert on a CAPTCHA misconfiguration.
     *
     * @since   1.7.0
     *
     * @param   string  $error  The provider error code(s) that triggered it.
     */
    private static function alert_degraded( $error ) {

        update_option( 'mshield_captcha_degraded', [ 'time' => time(), 'message' => $error ], false );

        if( get_transient( 'mshield_captcha_alerted' ) ) return;
        set_transient( 'mshield_captcha_alerted', 1, DAY_IN_SECONDS );

        $admin_email = get_option( 'admin_email' );
        $subject     = '[MightyShield] Bot challenge is misconfigured';
        $message     = sprintf(
            "MightyShield's bot challenge (%s) is rejecting all tokens because of a configuration error: %s.\n\n" .
            "To avoid blocking legitimate checkouts, the challenge is temporarily failing open (allowing orders) until this is fixed.\n\n" .
            "Check the Site Key and Secret Key under MightyShield > Blocking > Bot Challenge.\n\n" .
            "This alert is sent at most once per day.",
            settings::get( 'mshield_captcha_provider' ),
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


}
