<?php
/**
 * Checkout Timing.
 *
 * Stamps the checkout form with a signed timestamp token and measures how long
 * the shopper took to submit. Implausibly fast submissions are automated. The
 * token is HMAC-signed so it cannot be forged. A missing/invalid token is
 * flagged by default (protects against page caching stripping the field), but
 * can be set to block via mshield_timing_missing_action when under attack.
 *
 * @package MightyShield
 * @since   1.2.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\risk_context;
use MightyShield\Includes\response;

class checkout_timing {

    /**
     * Construct.
     *
     * @since   1.2.0
     */
    public function __construct() {

        if( settings::get( 'mshield_timing_enabled' ) !== 'yes' ) return;

        add_action( 'woocommerce_after_checkout_billing_form', [ $this, 'render_field' ] );
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'block_field' ], 1, 2 );
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'flag_field' ], 5, 3 );

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
     * Block checkout on an implausibly fast submission (action = block).
     *
     * @since   1.2.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function block_field( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        if( settings::get( 'mshield_timing_action' ) !== 'block' ) return;

        $result = $this->evaluate();
        if( $result['reason'] === null ) return;

        $ip = ip_utils::get_client_ip();

        if( $result['blockable'] ) {

            db::log_event( $ip, 'classic_checkout', 'blocked', $result['reason'] );

            // Only strong signals (genuinely fast submit) escalate to an
            // IP-wide temp-block.
            if( ! empty( $result['temp_block'] ) ) {
                $duration = (int) settings::get( 'mshield_temp_block_duration' );
                set_transient( 'mshield_tempblock_' . md5( $ip ), true, $duration );
            }

            $errors->add( 'mighty_shield_timing', response::with_note( __( 'This order could not be processed. Please try again.', 'mighty-shield' ) ) );
            return;

        }

        // Non-blockable signal (missing/invalid token) — record only.
        db::log_event( $ip, 'classic_checkout', 'flagged', $result['reason'] );

    }

    /**
     * Flag an order on an implausibly fast submission (action = flag / notify).
     *
     * @since   1.2.0
     *
     * @param   int     $order_id   Order ID.
     * @param   array   $posted     Posted data.
     * @param   object  $order      WC_Order object.
     */
    public function flag_field( $order_id, $posted, $order ) {

        if( \MightyShield\Includes\exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $action = settings::get( 'mshield_timing_action' );
        if( $action === 'block' ) return;

        $result = $this->evaluate();
        if( $result['reason'] === null ) return;

        $ip = ip_utils::get_client_ip();

        \MightyShield\Includes\response::flag( $order, 'checkout_timing', $result['reason'], false, 'classic_checkout' );

        if( $action === 'notify' ) {
            $this->send_admin_notification( $order, $result['reason'] );
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
     * @return  array   [ 'blockable' => bool, 'temp_block' => bool, 'reason' => string|null ]
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
     * Emission is unconditional. The action settings decide whether the order
     * is also refused, never whether the evidence is kept.
     *
     * @since   2.0.0
     *
     * @param   string  $token  Submitted timing token, or '' if absent.
     * @return  array   [ 'blockable' => bool, 'temp_block' => bool, 'reason' => string|null ]
     */
    public static function assess( $token ) {

        $elapsed = self::verify_token( (string) $token );

        // Missing / forged / invalid token. A scripted checkout that never
        // rendered our field lands here. Whether that blocks is governed by
        // mshield_timing_missing_action: "flag" (default; guards against page
        // caching stripping the field) or "block" (recommended under attack).
        if( $elapsed === null ) {
            $missing_blockable = ( settings::get( 'mshield_timing_missing_action' ) === 'block' );
            // Weaker signal — reject the order but do not IP temp-block, to
            // avoid locking out a shopper if caching ever strips the field.
            risk_context::add( 'timing_missing', 'Checkout timing token missing or invalid' );

            return [ 'blockable' => $missing_blockable, 'temp_block' => false, 'reason' => 'Checkout timing token missing or invalid' ];
        }

        $min = (int) settings::get( 'mshield_timing_min_seconds' );

        if( $elapsed < $min ) {

            risk_context::add(
                'timing_fast',
                sprintf( 'Checkout submitted in %ds (minimum %ds) — likely automated', $elapsed, $min )
            );

            return [
                'blockable'  => true,
                'temp_block' => true,
                'reason'     => sprintf( 'Checkout submitted too fast: %ds (minimum %ds) — likely automated', $elapsed, $min ),
            ];
        }

        return [ 'blockable' => false, 'temp_block' => false, 'reason' => null ];

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
        $subject     = sprintf( '[MightyShield] Fast checkout on order #%d', $order->get_id() );
        $message     = sprintf(
            "A checkout was submitted implausibly fast (likely automated) on an order flagged by MightyShield.\n\nOrder: #%d\nReason: %s\nCustomer: %s (%s)\nIP: %s\n\nReview this order: %s",
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
