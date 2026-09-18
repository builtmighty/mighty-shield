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
     * What judge() can conclude about a request.
     *
     * Only FAILED is the provider positively saying the token is not genuine.
     * Everything between PASSED and FAILED is an ABSENCE of evidence, and an
     * absence of evidence must never refuse a person -- that is the whole
     * lesson of the lost-password lockout, and of a customer being turned away
     * for pressing Place order twice.
     *
     * LOW_SCORE sits on its own because reCAPTCHA v3 returns a probability
     * rather than a verdict: it is strong enough to cost a checkout trust, and
     * nowhere near strong enough to lock somebody out of their own account.
     *
     * @since   2.0.1
     */
    /**
     * The provider's own error codes from the last judgement, and the hostname
     * it says the token came from.
     *
     * Kept because throwing this away is what made the last two outages
     * guesswork. "The provider judged the token not genuine" is not a diagnosis;
     * "invalid-input-response, hostname sandbox.test" is one.
     *
     * @since   2.0.2
     */
    private static $last_said = '';

    /**
     * What the provider said about the most recent token, for the log.
     *
     * @since   2.0.2
     *
     * @return  string
     */
    public static function last_said() {

        return self::$last_said;

    }

    const PASSED        = 'passed';
    const FAILED        = 'failed';
    const LOW_SCORE     = 'low_score';
    const STALE         = 'stale';
    const UNANSWERED    = 'unanswered';
    const NOT_ASKED     = 'not_asked';
    const UNAVAILABLE   = 'unavailable';
    const MISCONFIGURED = 'misconfigured';


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

        // Registered before the feature's own guards, not after. A merchant who
        // reacts to a credentials error by clearing the bad key stops the class
        // short at the guard below -- and used to stop seeing the warning about
        // the very key they had just cleared, which reads as fixed.
        if( is_admin() ) {
            add_action( 'admin_notices', [ $this, 'render_degraded_notice' ] );
        }

        if( $this->provider !== 'turnstile' && $this->provider !== 'recaptcha_v3' ) return;
        if( settings::get( 'mshield_captcha_site_key' ) === '' || settings::get( 'mshield_captcha_secret_key' ) === '' ) return;

        add_action( 'woocommerce_after_checkout_billing_form', [ $this, 'render_field' ] );
        // Priority 20, so the signal is in the context well before
        // risk_recorder::refuse_classic() reads it at 99.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess' ], 20, 2 );

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

        $verdict = self::assess_surface( 'checkout' );

        if( $verdict === self::PASSED ) {
            if( get_option( 'mshield_captcha_degraded' ) ) self::clear_degraded();
            return;
        }

        $reason = sprintf(
            /* translators: 1: provider, 2: plain explanation of the verdict. */
            __( 'Bot challenge (%1$s): %2$s', 'mighty-shield' ),
            $this->provider,
            self::explain( $verdict )
        );

        // The provider positively judged this not a person -- unless nothing has
        // passed in a long time, in which case the provider's judgement is the
        // thing in question, not the shopper.
        if( self::is_automation( $verdict ) && ! self::breaker_tripped( 'checkout' ) ) {

            risk_context::add( 'captcha_failed', $reason );
            db::log_event( ip_utils::get_client_ip(), 'classic_checkout', 'flagged', $reason );

            return;

        }

        // Neither passed nor failed. Costs a little trust, refuses nobody. A
        // judged failure lands here too once the breaker is open.
        if( self::is_unconfirmed( $verdict ) || self::is_automation( $verdict ) ) {

            risk_context::add( 'captcha_unverified', $reason );
            db::log_event( ip_utils::get_client_ip(), 'classic_checkout', 'flagged', $reason );

            return;

        }

        // NOT_ASKED, UNAVAILABLE and MISCONFIGURED are all our end, not the
        // shopper's. They are recorded by report_missing() and alert_degraded()
        // where they happen, and cost the order nothing at all.

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

        return self::judge( $provider, $secret, $token, $action ) === self::PASSED;

    }

    /**
     * What the provider actually said about this visitor.
     *
     * verify() used to answer yes or no, and everything that was not a yes was
     * treated as a bot. That is wrong, and it locks real people out:
     *
     *  - Both providers burn a token on first verification. A customer whose
     *    card is declined and who presses Place order again sends the same
     *    token, the provider answers "timeout-or-duplicate", and the order was
     *    REJECTED. Same for anyone who sat on the form past the two minute
     *    token expiry.
     *  - reCAPTCHA v3 returns a SCORE, not a verdict. A real person on a VPN, a
     *    corporate proxy or a datacenter IP routinely scores below 0.5, and a
     *    brand new site key with no traffic history scores everybody low.
     *  - Cloudflare or Google being unreachable, or our own secret being wrong,
     *    says nothing whatsoever about the visitor.
     *
     * So this reports which of those happened and lets the caller decide. Only
     * FAILED is the provider positively saying the token is not genuine.
     *
     * @since   2.0.1
     *
     * @param   string  $provider
     * @param   string  $secret
     * @param   string  $token
     * @param   string  $action
     * @return  string  One of the verdict constants.
     */
    public static function judge( $provider, $secret, $token, $action = '' ) {

        if( $secret === '' ) return self::MISCONFIGURED;
        if( $token === '' )  return self::UNANSWERED;

        $endpoint = $provider === 'turnstile' ? self::TURNSTILE_VERIFY : self::RECAPTCHA_VERIFY;

        $response = wp_remote_post( $endpoint, [
            'timeout' => 5,
            'body'    => [ 'secret' => $secret, 'response' => $token, 'remoteip' => ip_utils::get_client_ip() ],
        ] );

        // The provider is unreachable from this server. Nothing about the
        // visitor is in question.
        if( is_wp_error( $response ) ) return self::UNAVAILABLE;

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if( ! is_array( $body ) ) return self::UNAVAILABLE;

        self::$last_said = '';

        if( empty( $body['success'] ) ) {

            $codes = ! empty( $body['error-codes'] ) ? (array) $body['error-codes'] : [];

            // Keep the provider's own words. reCAPTCHA also returns the hostname
            // it saw, which is the one thing that tells a key registered for the
            // wrong domain apart from a genuinely forged token -- and the two
            // otherwise arrive as the identical invalid-input-response.
            $said = array_map( 'sanitize_text_field', $codes );

            if( ! empty( $body['hostname'] ) ) {
                $said[] = 'hostname ' . sanitize_text_field( (string) $body['hostname'] );
            }

            self::$last_said = implode( ', ', $said );

            // Our configuration, not their humanity. Says so out loud, because a
            // challenge silently passing everyone is as bad as one silently
            // refusing everyone.
            if( array_intersect( $codes, [ 'invalid-input-secret', 'missing-input-secret', 'bad-request' ] ) ) {
                self::alert_degraded( implode( ', ', $codes ) );
                return self::MISCONFIGURED;
            }

            // The provider's own outage.
            if( \in_array( 'internal-error', $codes, true ) ) return self::UNAVAILABLE;

            // Already used, or expired. This is what a resubmit looks like and
            // it is not evidence of anything.
            if( \in_array( 'timeout-or-duplicate', $codes, true ) ) return self::STALE;

            // Anything left is the provider saying this token is not genuine.
            return self::FAILED;

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

            if( (string) $body['action'] !== $action ) {

                self::$last_said = sprintf(
                    /* translators: 1: action the token carried, 2: action expected. */
                    __( 'token was signed for "%1$s" but this form expects "%2$s"', 'mighty-shield' ),
                    sanitize_text_field( (string) $body['action'] ),
                    $action
                );

                return self::FAILED;

            }

        }

        // A pass still carries the hostname, so a merchant checking a working
        // setup can see which domain the provider thinks this is.
        if( ! empty( $body['hostname'] ) ) {
            self::$last_said = 'hostname ' . sanitize_text_field( (string) $body['hostname'] );
        }

        if( $provider === 'recaptcha_v3' && isset( $body['score'] ) ) {
            return ( (float) $body['score'] >= self::min_score() ) ? self::PASSED : self::LOW_SCORE;
        }

        return self::PASSED;

    }

    /**
     * The reCAPTCHA v3 score at or above which a visitor is treated as a person.
     *
     * A setting rather than a constant. 0.5 is Google's own suggested starting
     * point, but the right number depends entirely on a store's traffic: a shop
     * whose customers are largely on corporate VPNs needs it lower, and one
     * being hammered by card testers may want it higher.
     *
     * @since   2.0.1
     *
     * @return  float
     */
    public static function min_score() {

        $score = (float) settings::get( 'mshield_captcha_min_score' );

        return ( $score > 0 && $score <= 1 ) ? $score : 0.5;

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

        wp_enqueue_script( 'mshield-challenge', MSHIELD_URI . 'assets/js/mshield-challenge.js', [], \MightyShield\asset_version( 'assets/js/mshield-challenge.js' ), [ 'in_footer' => true ] );

        // Every surface's action, every time -- not just this call's surface.
        //
        // wp_localize_script concatenates, so a page carrying two forms declared
        // mshieldChallenge twice and the LAST one won. WooCommerce's My Account
        // page is exactly that page: it renders the login and registration forms
        // together, register goes second, and so the login form's token was
        // minted signed "mshield_register". The server then checked it against
        // mshield_login, the actions disagreed, and a real customer was told
        // they could not be verified as a person.
        //
        // The action belongs to the widget, not to the page. This payload is now
        // identical whichever surface asks for it, so a second declaration
        // cannot change the first one's meaning.
        $actions = [];

        foreach( array_keys( \MightyShield\Protection\challenge::SURFACES ) as $known ) {
            $actions[ $known ] = self::action_for( $known );
        }

        $actions['checkout'] = self::action_for( 'checkout' );

        wp_localize_script( 'mshield-challenge', 'mshieldChallenge', [
            'provider' => $provider,
            'siteKey'  => $site_key,
            'actions'  => $actions,
            // Kept for a widget rendered without a surface by something older.
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
            . '<input type="hidden" name="mshield_captcha_token" class="mshield-challenge-token" value="" />'
            . '<input type="hidden" name="mshield_captcha_shown" value="%s" />',
            esc_attr( $surface ),
            esc_attr( self::shown_marker( $surface ) )
        );

    }

    /**
     * A signed note that a challenge really was put in front of this visitor.
     *
     * The problem this solves: verification and rendering are registered
     * separately, per surface, and they can disagree. When they do — a hook that
     * was never added, a theme that overrides the form, a provider script the
     * browser blocked — the visitor is shown nothing and then refused for not
     * solving it. That is the worst possible outcome: it turns a bot defence
     * into a wall in front of real customers, and it is silent.
     *
     * So passes() distinguishes "asked and got nothing" from "never asked", and
     * this is what tells the two apart. Signed rather than a bare flag, because
     * an unsigned one would just be a field an attacker omits to skip the check.
     * A bot must at least fetch the form to obtain a valid marker, and still has
     * to pass the actual challenge afterwards.
     *
     * @since   2.0.1
     *
     * @param   string  $surface
     * @return  string  "timestamp|signature"
     */
    public static function shown_marker( $surface ) {

        $ts = time();

        return $ts . '|' . hash_hmac( 'sha256', $surface . '|' . $ts, wp_salt( 'auth' ) );

    }

    /**
     * Whether this request carries proof that a challenge was rendered.
     *
     * @since   2.0.1
     *
     * @param   string  $surface
     * @return  bool
     */
    public static function was_shown( $surface ) {

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only; the value carries its own signature.
        $raw = isset( $_POST['mshield_captcha_shown'] ) ? sanitize_text_field( wp_unslash( $_POST['mshield_captcha_shown'] ) ) : '';

        if( $raw === '' || strpos( $raw, '|' ) === false ) return false;

        list( $ts, $sig ) = explode( '|', $raw, 2 );

        if( ! ctype_digit( $ts ) ) return false;

        $expected = hash_hmac( 'sha256', $surface . '|' . $ts, wp_salt( 'auth' ) );
        if( ! hash_equals( $expected, $sig ) ) return false;

        // A form left open overnight is a stale marker, not a forged one, but
        // the token beside it would have expired at the provider anyway.
        $age = time() - (int) $ts;

        return $age >= 0 && $age <= DAY_IN_SECONDS;

    }

    /**
     * Record that a surface verified a challenge it never rendered.
     *
     * Throttled per surface: this is a configuration fault, so it needs saying
     * once a day, not once a request. It is deliberately loud in the log,
     * because the alternative -- the state this replaced -- was a silent wall in
     * front of real customers.
     *
     * @since   2.0.1
     *
     * @param   string  $surface
     */
    private static function report_missing( $surface ) {

        $surface = preg_replace( '/[^a-z_]/', '', (string) $surface );
        $key     = 'mshield_cap_missing_' . $surface;

        if( get_transient( $key ) ) return;

        // Evidence, not a single request.
        //
        // This raises a red banner reading "the bot challenge is misconfigured
        // and is failing open" and emails the merchant. One tokenless POST used
        // to be enough -- which any anonymous visitor can send, on a store where
        // nothing is wrong. The fastest way to make somebody switch a control
        // off is to tell them it is broken.
        //
        // A genuinely unreachable widget produces this on every submission, so
        // waiting for a few costs nothing real and makes the claim true.
        $count = (int) get_transient( $key . '_seen' ) + 1;
        set_transient( $key . '_seen', $count, HOUR_IN_SECONDS );

        if( $count < self::MISSING_BEFORE_ALERT ) return;

        set_transient( $key, 1, DAY_IN_SECONDS );

        db::log_event(
            ip_utils::get_client_ip(),
            'system',
            'degraded',
            sprintf(
                'Bot challenge is switched on for "%s" but no challenge was rendered on the submitted form, so the request was allowed through rather than refused. The widget is not reaching that form.',
                $surface
            )
        );

        self::alert_degraded( sprintf( 'no challenge was rendered on the "%s" form, so it is not being enforced there', $surface ) );

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

        // Only a positive FAILED refuses anybody. A stale token, a low score, a
        // blocked provider script or our own bad secret are all absences of
        // evidence, and this is the gate in front of logging in, registering and
        // resetting a password -- surfaces with no review queue and no way back
        // for somebody wrongly turned away.
        if( self::assess_surface( $surface ) !== self::FAILED ) return true;

        // ...and not even FAILED, once nothing at all has passed for long
        // enough that the credentials themselves are the likelier explanation.
        return self::breaker_tripped( $surface );

    }

    /**
     * The provider's verdict on this request, for one surface.
     *
     * Memoised for the life of the request: a token is single use, so asking
     * twice would answer STALE the second time.
     *
     * @since   2.0.1
     *
     * @param   string  $surface
     * @return  string  One of the verdict constants.
     */
    public static function assess_surface( $surface, $token = null, $shown = null ) {

        static $seen = [];

        if( isset( $seen[ $surface ] ) ) return $seen[ $surface ];

        if( ! self::is_ready() ) return $seen[ $surface ] = self::PASSED;

        if( $token === null ) {

            // Turnstile still posts its own field when a theme or another plugin
            // renders a widget implicitly, so accept either.
            $token = '';
            foreach( [ 'mshield_captcha_token', 'cf-turnstile-response', 'g-recaptcha-response' ] as $field ) {
                if( ! empty( $_POST[ $field ] ) ) {
                    $token = sanitize_text_field( wp_unslash( $_POST[ $field ] ) );
                    break;
                }
            }

        } else {
            $token = sanitize_text_field( (string) $token );
        }

        if( $token === '' ) {

            // "Never asked" is not "asked and failed".
            //
            // If nothing here put a challenge in front of this visitor, refusing
            // them for not solving one locks out every legitimate customer on
            // that surface and gives them no way through -- which is exactly
            // what happened on the WooCommerce lost-password form, where the
            // renderer was never hooked but the verifier was.
            // The block checkout carries no signed marker -- its widget is
            // rendered by script whenever the keys are configured, so the caller
            // states that directly rather than proving it.
            $was_shown = $shown === null ? self::was_shown( $surface ) : (bool) $shown;

            if( ! $was_shown ) {

                self::report_missing( $surface );

                return $seen[ $surface ] = self::NOT_ASKED;

            }

            // A challenge WAS rendered and came back empty. That is an ad
            // blocker, a CSP, a corporate proxy, a provider outage at the edge,
            // or a widget still minting when the form was submitted -- and only
            // rarely somebody stripping the field. It used to be a flat refusal,
            // which is how a real person ends up locked out of their own login
            // with no widget visible and nothing to solve.
            return $seen[ $surface ] = self::UNANSWERED;

        }

        $verdict = self::judge(
            settings::get( 'mshield_captcha_provider' ),
            settings::get( 'mshield_captcha_secret_key' ),
            $token,
            self::action_for( $surface )
        );

        self::record_verdict( $verdict, $surface );

        return $seen[ $surface ] = $verdict;

    }

    /**
     * How many refusals in a row, with nothing getting through, before the
     * challenge concludes the fault is at this end.
     *
     * @since   2.0.2
     */
    const BREAKER_LIMIT = 5;

    /**
     * How many distinct networks those failures must come from.
     *
     * A broken key fails for everybody, so the failures arrive from all over. An
     * attacker is one or two places however many requests they send.
     *
     * @since   2.1.1
     */
    const BREAKER_NETWORKS = 3;

    /**
     * How many tokenless submissions on one form before saying it is broken.
     *
     * @since   2.1.1
     */
    const MISSING_BEFORE_ALERT = 5;

    /**
     * The counter's lifetime. Long enough to span a quiet night on a small
     * store, short enough that a genuine attack does not hold the breaker open
     * for ever after it stops.
     *
     * @since   2.0.2
     */
    const BREAKER_WINDOW = 6 * HOUR_IN_SECONDS;

    /**
     * Where the consecutive-failure count lives, keyed to the credentials.
     *
     * Keyed on the site key so that entering new keys starts a fresh count. A
     * merchant fixing a mismatched pair should not inherit the old pair's
     * failures.
     *
     * @since   2.0.2
     *
     * @return  string
     */
    private static function breaker_key( $surface ) {

        return 'mshield_cap_fails_' . substr( md5(
            settings::get( 'mshield_captcha_provider' ) . '|'
            . settings::get( 'mshield_captcha_site_key' ) . '|'
            . $surface
        ), 0, 12 );

    }

    /**
     * Has every recent challenge failed?
     *
     * This is the difference between "bots are hitting this store" and "these
     * keys do not work here", which the provider cannot tell us apart. Google
     * answers invalid-input-response both for a forged token and for a token
     * minted with a site key that does not pair with this secret, or on a domain
     * the key is not registered for. The response is identical; the consequence
     * is not.
     *
     * A real attack is mixed -- some customers get through between the bots. An
     * unbroken run of failures with not one success is a configuration fault,
     * and continuing to refuse everybody on that evidence is how an admin ends
     * up locked out of their own login with no way back but database access.
     *
     * So once the run is long enough the challenge stops refusing anybody and
     * says so, loudly. Getting this wrong in one direction lets some bots
     * through for a few hours while the merchant is emailed about it. Getting it
     * wrong in the other direction turns away every real customer, silently.
     *
     * @since   2.0.2
     *
     * @return  bool
     */
    public static function breaker_tripped( $surface = 'checkout' ) {

        $seen = get_transient( self::breaker_key( $surface ) );

        if( ! is_array( $seen ) ) return false;

        // Enough failures, from enough DIFFERENT networks.
        //
        // Counting bare failures made this a five-request off switch: anybody
        // could post five junk tokens at the registration form and disarm the
        // challenge for every visitor on the site, on every surface, until a
        // real customer happened to pass. Keying on the network as well is what
        // separates the two cases it is supposed to tell apart -- a broken key
        // fails for everybody, so the failures arrive from all over, while one
        // attacker is one or two places however many requests they send.
        return count( $seen ) >= self::BREAKER_LIMIT
            && count( array_unique( $seen ) ) >= self::BREAKER_NETWORKS;

    }

    /**
     * Feed a verdict to the breaker.
     *
     * Only outcomes the provider actually judged count. An unanswered widget or
     * an outage says nothing about whether the credentials work.
     *
     * @since   2.0.2
     *
     * @param   string  $verdict
     */
    private static function record_verdict( $verdict, $surface ) {

        $key = self::breaker_key( $surface );

        if( $verdict === self::PASSED ) {

            // One success proves the configuration works here. Reset, and take
            // the warning down with it.
            if( get_transient( $key ) !== false ) delete_transient( $key );
            if( get_option( 'mshield_captcha_degraded' ) ) self::clear_degraded();

            return;

        }

        // Only a verdict the PROVIDER reached. A low score is our own threshold
        // decision, and feeding it in meant a store whose customers are mostly
        // on corporate VPNs could talk itself into disarming the challenge.
        if( $verdict !== self::FAILED ) return;

        $seen = get_transient( $key );
        if( ! is_array( $seen ) ) $seen = [];

        // Which network this failure came from, so a run of them from one place
        // reads differently from a run from all over.
        $seen[] = self::network_of( ip_utils::get_client_ip() );

        // Keep the window honest. Refreshing the TTL on every increment let a
        // single bad token every few hours hold the breaker open indefinitely.
        if( count( $seen ) === 1 ) {
            set_transient( $key, $seen, self::BREAKER_WINDOW );
        } else {
            self::extend_without_refresh( $key, $seen );
        }

        // Say it once, on the way past the limit.
        if( self::breaker_tripped( $surface ) && count( $seen ) === self::BREAKER_LIMIT ) {

            db::log_event(
                ip_utils::get_client_ip(),
                'system',
                'degraded',
                sprintf(
                    /* translators: 1: number of failures, 2: the form affected. */
                    __( 'The bot challenge on the %2$s form has refused %1$d visitors from several different networks without a single one passing. That pattern is a configuration fault rather than an attack, so it has stopped refusing anybody on that form until one passes. Check that the site key and secret key are from the same provider account and that this domain is registered with them.', 'mighty-shield' ),
                    self::BREAKER_LIMIT,
                    $surface
                )
            );

            self::alert_degraded( sprintf(
                /* translators: 1: number of failures, 2: the form affected. */
                __( '%1$d challenges in a row failed on the %2$s form, from several different networks and with none passing, so it is no longer refusing anybody there. This is usually a mismatched site key and secret key, or a domain that is not registered with the provider.', 'mighty-shield' ),
                self::BREAKER_LIMIT,
                $surface
            ) );

        }

    }

    /**
     * Write the list back without restarting its expiry.
     *
     * WordPress has no "update value, keep TTL", so read the remaining lifetime
     * and set it again with what is left. A window that restarts on every write
     * never closes while anybody keeps poking it.
     *
     * @since   2.1.1
     *
     * @param   string  $key
     * @param   array   $value
     */
    private static function extend_without_refresh( $key, $value ) {

        $timeout = (int) get_option( '_transient_timeout_' . $key, 0 );
        $left    = $timeout > 0 ? $timeout - time() : self::BREAKER_WINDOW;

        set_transient( $key, $value, max( 60, $left ) );

    }

    /**
     * The /24 or /48 a failure arrived from.
     *
     * @since   2.1.1
     *
     * @param   string  $ip
     * @return  string
     */
    private static function network_of( $ip ) {

        if( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            $p = explode( '.', $ip );
            return $p[0] . '.' . $p[1] . '.' . $p[2] . '.0/24';
        }

        if( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            $p = explode( ':', $ip );
            return implode( ':', array_slice( $p, 0, 3 ) ) . '::/48';
        }

        return (string) $ip;

    }

    /**
     * Whether a verdict is strong enough evidence to cost an order trust.
     *
     * @since   2.0.1
     *
     * @param   string  $verdict
     * @return  bool
     */
    public static function is_automation( $verdict ) {

        return $verdict === self::FAILED || $verdict === self::LOW_SCORE;

    }

    /**
     * Whether a verdict means the challenge simply could not be confirmed.
     *
     * Worth a little trust on a checkout, because a run of them is odd. Never
     * worth refusing anybody over.
     *
     * @since   2.0.1
     *
     * @param   string  $verdict
     * @return  bool
     */
    public static function is_unconfirmed( $verdict ) {

        return $verdict === self::STALE || $verdict === self::UNANSWERED;

    }

    /**
     * Plain wording for a verdict, for the log and the order note.
     *
     * The log used to record every one of these as "Bot challenge failed", so a
     * merchant reading it could not tell a card tester from a customer whose
     * second attempt reused a spent token. That ambiguity is what made this
     * whole class of bug invisible.
     *
     * @since   2.0.1
     *
     * @param   string  $verdict
     * @return  string
     */
    public static function explain( $verdict ) {

        switch( $verdict ) {

            case self::FAILED:
                return self::$last_said === ''
                    ? __( 'the provider judged the token not genuine', 'mighty-shield' )
                    : sprintf(
                        /* translators: %s: the provider's own error codes. */
                        __( 'the provider rejected the token and said: %s', 'mighty-shield' ),
                        self::$last_said
                    );

            case self::LOW_SCORE:
                return sprintf(
                    /* translators: %s: the configured minimum score. */
                    __( 'reCAPTCHA scored this visitor below %s', 'mighty-shield' ),
                    number_format_i18n( self::min_score(), 2 )
                );

            case self::STALE:
                return __( 'the token had already been used or had expired, which is what a resubmitted form looks like', 'mighty-shield' );

            case self::UNANSWERED:
                return __( 'a challenge was shown but came back with no answer, which usually means the provider script was blocked', 'mighty-shield' );

            case self::NOT_ASKED:
                return __( 'no challenge was rendered on this form', 'mighty-shield' );

            case self::UNAVAILABLE:
                return __( 'the provider could not be reached', 'mighty-shield' );

            case self::MISCONFIGURED:
                return __( 'the secret key was rejected by the provider', 'mighty-shield' );

        }

        return __( 'the challenge passed', 'mighty-shield' );

    }



    /**
     * What the bot challenge has actually been doing.
     *
     * The plugin calls this its single most effective control and then showed a
     * merchant nothing about it: no status, no last verdict, no Test Connection,
     * while the AI and address integrations each have one. Everything needed was
     * already being recorded and nothing read it back.
     *
     * One grouped query over an indexed column, cached for five minutes, because
     * this renders on a settings screen and not on a checkout.
     *
     * @since   2.1.1
     *
     * @param   int     $days   How far back to look.
     * @return  array   ready, provider, surfaces, refused, unconfirmed, missing, open.
     */
    public static function status( $days = 7 ) {

        $cache = get_transient( 'mshield_captcha_status' );
        if( is_array( $cache ) ) return $cache;

        global $wpdb;

        $table = $wpdb->prefix . 'mshield_log';

        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT reason, COUNT(*) AS n FROM {$table}
             WHERE created_at > DATE_SUB( NOW(), INTERVAL %d DAY )
               AND reason LIKE %s
             GROUP BY reason",
            (int) $days,
            '%' . $wpdb->esc_like( 'Bot challenge' ) . '%'
        ), ARRAY_A );

        $refused = 0;
        $unconfirmed = 0;

        foreach( (array) $rows as $row ) {

            $n = (int) $row['n'];

            // explain() wording, which is why these read as sentences.
            if( strpos( $row['reason'], 'not genuine' ) !== false
                || strpos( $row['reason'], 'rejected the token' ) !== false
                || strpos( $row['reason'], 'scored this visitor' ) !== false ) {
                $refused += $n;
                continue;
            }

            $unconfirmed += $n;

        }

        $surfaces = [];
        $open     = [];

        foreach( array_keys( challenge::SURFACES ) as $surface ) {

            if( ! challenge::on( $surface ) ) continue;

            $surfaces[] = $surface;

            if( self::breaker_tripped( $surface ) ) $open[] = $surface;

        }

        $status = [
            'ready'       => self::is_ready(),
            'provider'    => settings::get( 'mshield_captcha_provider' ),
            'surfaces'    => $surfaces,
            'refused'     => $refused,
            'unconfirmed' => $unconfirmed,
            'open'        => $open,
            'days'        => (int) $days,
        ];

        set_transient( 'mshield_captcha_status', $status, 5 * MINUTE_IN_SECONDS );

        return $status;

    }

    /**
     * Forget the degraded state entirely.
     *
     * The throttle goes with the option. Recovery used to delete the flag alone
     * and leave the daily transient behind, so the next genuine failure recorded
     * the state and emailed nobody about it for up to a day.
     *
     * @since   2.0.1
     */
    public static function clear_degraded() {

        delete_option( 'mshield_captcha_degraded' );
        delete_transient( 'mshield_captcha_alerted' );

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
                __( 'The bot challenge is misconfigured (%s) and is failing open so it does not block checkout. Verify your Site Key and Secret Key on the Shielding tab.', 'mighty-shield' ),
                $degraded['message']
            ) )
        );

    }


}
