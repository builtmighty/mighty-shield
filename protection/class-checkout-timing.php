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

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

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
        return $ts . '|' . hash_hmac( 'sha256', (string) $ts, wp_salt( 'auth' ) );

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

        if( $token === '' || strpos( $token, '|' ) === false ) return null;

        list( $ts, $sig ) = explode( '|', $token, 2 );

        if( ! ctype_digit( $ts ) ) return null;

        $expected = hash_hmac( 'sha256', $ts, wp_salt( 'auth' ) );
        if( ! hash_equals( $expected, $sig ) ) return null;

        $elapsed = time() - (int) $ts;

        // Guard against clock skew (negative) or stale/replayed tokens (>2h).
        if( $elapsed < 0 || $elapsed > 7200 ) return null;

        return $elapsed;

    }

}
