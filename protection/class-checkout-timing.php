<?php
/**
 * Checkout Timing.
 *
 * Stamps the checkout form with a signed timestamp token and measures how long
 * the shopper took to submit. Implausibly fast submissions are automated. The
 * token is HMAC-signed so it cannot be forged.
 *
 * Both outcomes are scores, not verdicts: an impossible submit time is worth a
 * lot, a token that never came back is worth a little, and the blocking engine
 * decides what either is worth doing something about.
 *
 * @package MightyShield
 * @since   1.2.0
 */
namespace MightyShield\Protection;

defined( 'ABSPATH' ) || exit;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\risk_context;

class checkout_timing {

    /**
     * Construct.
     *
     * @since   1.2.0
     */
    public function __construct() {

        if( settings::get( 'mshield_timing_enabled' ) !== 'yes' ) return;

        add_action( 'woocommerce_after_checkout_billing_form', [ $this, 'render_field' ] );
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess_checkout' ], 1, 2 );

    }

    /**
     * Render the signed timing token into the checkout form.
     *
     * @since   1.2.0
     */
    public function render_field() {

        echo '<input type="hidden" name="mshield_ct_token" id="mshield_ct_token" value="' . esc_attr( self::generate_token() ) . '" />';

    }

    /**
     * Score the submission time. Runs before any order exists, and only scores.
     *
     * Neither outcome refuses here. timing_fast costs 45 and timing_missing
     * costs 20, and the total decides — which is the right shape for a check
     * whose miss case is a cache plugin stripping a hidden field rather than a
     * bot.
     *
     * The temp block survives, and is now keyed on the layer's own temp_block
     * flag rather than on a setting: a genuinely impossible submit time blocks
     * the address, a missing token never does.
     *
     * @since   1.2.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object, unused — this layer does not refuse.
     */
    public function assess_checkout( $data, $errors ) {

        $result = $this->evaluate();
        if( $result['reason'] === null ) return;

        $ip = ip_utils::get_client_ip();

        db::log_event( $ip, 'classic_checkout', 'flagged', $result['reason'] );

        if( ! empty( $result['temp_block'] ) ) {
            // Through rate_limiter, not by hand. The hand-rolled version
            // stored a bare true with no reason and wrote no log entry, so
            // three of the four ways a shopper gets temporarily blocked left
            // nothing in the Logs at all -- and "why can this customer not
            // check out" is the first question a merchant asks.
            rate_limiter::temp_block_ip( $ip, __( 'Checkout submitted faster than a person can fill it in', 'mighty-shield' ) );
        }

    }

    /**
     * Evaluate the timing token carried on this request.
     *
     * Classic reads it from $_POST; the Store API carries it in the request
     * extensions. Only the transport differs, so only the read lives here and
     * the judgement lives in assess().
     *
     * @since   1.2.0
     *
     * @return  array   [ 'temp_block' => bool, 'reason' => string|null ]
     */
    private function evaluate() {

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- checkout form data on a WooCommerce hook; WooCommerce owns the nonce for its own checkout
        return self::assess( isset( $_POST['mshield_ct_token'] ) ? sanitize_text_field( wp_unslash( $_POST['mshield_ct_token'] ) ) : '' );

    }

    /**
     * Judge a timing token and record what it found.
     *
     * The one place this check turns into a signal, called by both checkouts.
     * The Store API used to carry its own copy of this logic that only recorded
     * anything when the action was set to block, so on the default "flag"
     * setting a missing token produced nothing at all.
     *
     * Emission is unconditional, and emission is all this does. What the store
     * makes of the signal is the blocking engine's business.
     *
     * @since   2.0.0
     *
     * @param   string  $token  Submitted timing token, or '' if absent.
     * @return  array   [ 'temp_block' => bool, 'reason' => string|null ]
     */
    public static function assess( $token ) {

        $elapsed = self::verify_token( (string) $token );

        // Missing / forged / invalid token. A scripted checkout that never
        // rendered our field lands here -- and so does a real shopper behind a
        // page cache that stripped the field, which is why this is the cheap
        // signal and never a temp block.
        if( $elapsed === null ) {
            risk_context::add( 'timing_missing', 'Checkout timing token missing or invalid' );

            return [ 'temp_block' => false, 'reason' => 'Checkout timing token missing or invalid' ];
        }

        $min = (int) settings::get( 'mshield_timing_min_seconds' );

        if( $elapsed < $min ) {

            risk_context::add(
                'timing_fast',
                sprintf( 'Checkout submitted in %ds (minimum %ds) — likely automated', $elapsed, $min )
            );

            return [
                'temp_block' => true,
                'reason'     => sprintf( 'Checkout submitted too fast: %ds (minimum %ds) — likely automated', $elapsed, $min ),
            ];
        }

        return [ 'temp_block' => false, 'reason' => null ];

    }

    /**
     * Generate a signed "timestamp|signature" token.
     *
     * @since   1.2.0
     *
     * @return  string
     */
    public static function generate_token() {

        $ts = time();
        return $ts . '|' . hash_hmac( 'sha256', $ts . '|' . self::session_key(), wp_salt( 'auth' ) );

    }

    /**
     * Something about this visitor's session that a different visitor cannot
     * present.
     *
     * A token that was only a signed timestamp was valid for anyone for two
     * hours: one page load gave a script a token it could replay on every
     * submission after waiting out the minimum once. Binding it to the
     * WooCommerce session means a replay needs the session cookie it was
     * issued to, and a fresh session needs a fresh page load -- which puts the
     * wait back on every attempt.
     *
     * Empty when there is no session to bind to, so a token issued in that
     * state still verifies rather than costing a real shopper trust.
     *
     * @since   2.3.0
     *
     * @return  string
     */
    private static function session_key() {

        if( ! function_exists( 'WC' ) || ! WC()->session || ! method_exists( WC()->session, 'get_customer_id' ) ) return '';

        return (string) WC()->session->get_customer_id();

    }

    /**
     * Verify a token and return elapsed seconds since it was issued.
     *
     * @since   1.2.0
     *
     * @param   string  $token  Submitted token.
     * @return  int|null    Elapsed seconds, or null if missing/forged/invalid.
     */
    public static function verify_token( $token ) {

        // One answer per token per request. Both checkouts may ask more than
        // once in the same submission, and the second ask must not be read
        // as a replay.
        static $seen = [];
        if( array_key_exists( $token, $seen ) ) return $seen[ $token ];

        if( $token === '' || strpos( $token, '|' ) === false ) return $seen[ $token ] = null;

        list( $ts, $sig ) = explode( '|', $token, 2 );

        if( ! ctype_digit( $ts ) ) return $seen[ $token ] = null;

        // Bound to this session: see session_key(). A token from another
        // session -- or from no session -- does not verify.
        $expected = hash_hmac( 'sha256', $ts . '|' . self::session_key(), wp_salt( 'auth' ) );
        if( ! hash_equals( $expected, $sig ) ) return $seen[ $token ] = null;

        $elapsed = time() - (int) $ts;

        // Guard against clock skew (negative) or stale/replayed tokens (>2h).
        if( $elapsed < 0 || $elapsed > 7200 ) return $seen[ $token ] = null;

        // Used once per session. Binding the token to the session stopped a
        // stranger replaying it; it did not stop the session's own script
        // paying the minimum wait once and then submitting every 300 ms on
        // the same token. A token is spent the first time it verifies, and
        // the next submission needs a page load, and the wait, of its own.
        if( function_exists( 'WC' ) && WC()->session && method_exists( WC()->session, 'get' ) ) {

            $spent = (int) WC()->session->get( 'mshield_ct_spent' );
            if( (int) $ts <= $spent ) return $seen[ $token ] = null;

            WC()->session->set( 'mshield_ct_spent', (int) $ts );

        }

        return $seen[ $token ] = $elapsed;

    }

}
