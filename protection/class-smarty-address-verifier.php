<?php
/**
 * Smarty Address Verifier.
 *
 * Verifies US billing addresses against USPS data via Smarty's API.
 * Falls back to ZIP/State mismatch check when API is unavailable.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;

class smarty_address_verifier {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        if( settings::get( 'mshield_smarty_enabled' ) !== 'yes' ) return;
        if( empty( settings::get( 'mshield_smarty_auth_id' ) ) || empty( settings::get( 'mshield_smarty_auth_token' ) ) ) return;

        // Block mode: validate BEFORE order creation.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'block_invalid_address' ], 20, 2 );

        // Flag/notify mode: run AFTER order creation.
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'flag_invalid_address' ], 5, 3 );

        // Surface a persistent warning while verification is degraded.
        if( is_admin() ) {
            add_action( 'admin_notices', [ $this, 'render_degraded_notice' ] );
        }

    }

    /**
     * Record and alert on a degraded (API-unavailable) verification state.
     *
     * The email is throttled to at most once per day; the recorded state
     * powers a persistent admin notice until verification recovers.
     *
     * @since   1.3.0
     *
     * @param   string  $error_message  The API error that triggered fallback.
     */
    private function alert_degraded( $error_message ) {

        // Persist the latest degraded state for the admin notice.
        update_option( 'mshield_smarty_degraded', [
            'time'    => time(),
            'message' => $error_message,
        ], false );

        // Throttle the notification email to once per day.
        if( get_transient( 'mshield_smarty_alerted' ) ) return;
        set_transient( 'mshield_smarty_alerted', 1, DAY_IN_SECONDS );

        $admin_email = get_option( 'admin_email' );
        $subject     = '[MightyShield] Address verification is degraded';
        $message     = sprintf(
            "MightyShield's Smarty address verification is currently unavailable and has fallen back to a basic ZIP/State check.\n\n" .
            "Reason: %s\n\n" .
            "Full USPS address verification is NOT running until this is resolved. Common causes:\n" .
            "- Smarty subscription/quota exhausted (HTTP 402)\n" .
            "- Invalid or expired auth-id / auth-token (HTTP 401/403)\n" .
            "- Network/API outage\n\n" .
            "Check your Smarty account at https://www.smarty.com/account and the MightyShield > Fraud Checks settings.\n\n" .
            "This alert is sent at most once per day.",
            $error_message
        );

        wp_mail( $admin_email, $subject, $message );

    }

    /**
     * Show an admin notice while address verification is degraded.
     *
     * @since   1.3.0
     */
    public function render_degraded_notice() {

        if( ! current_user_can( 'manage_woocommerce' ) ) return;

        $degraded = get_option( 'mshield_smarty_degraded' );
        if( empty( $degraded ) || empty( $degraded['time'] ) ) return;

        // Only surface if a degradation was recorded within the last 24h.
        if( ( time() - (int) $degraded['time'] ) > DAY_IN_SECONDS ) return;

        printf(
            '<div class="notice notice-error"><p><strong>%s</strong> %s</p></div>',
            esc_html__( 'MightyShield:', 'mighty-shield' ),
            esc_html( sprintf(
                /* translators: %s: API error message. */
                __( 'Address verification (Smarty) is degraded and is falling back to a basic ZIP/State check — full USPS verification is NOT running. Last error: %s. Check your Smarty account quota and API keys.', 'mighty-shield' ),
                $degraded['message']
            ) )
        );

    }

    /**
     * Block invalid address before order creation.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function block_invalid_address( $data, $errors ) {

        $action = settings::get( 'mshield_smarty_action' );
        if( $action !== 'block' ) return;

        $country = isset( $data['billing_country'] ) ? $data['billing_country'] : '';
        if( $country !== 'US' ) return;

        $street  = isset( $data['billing_address_1'] ) ? trim( $data['billing_address_1'] ) : '';
        $city    = isset( $data['billing_city'] ) ? trim( $data['billing_city'] ) : '';
        $state   = isset( $data['billing_state'] ) ? trim( $data['billing_state'] ) : '';
        $zipcode = isset( $data['billing_postcode'] ) ? trim( $data['billing_postcode'] ) : '';

        if( empty( $street ) ) return;

        $result = $this->verify_address( $street, $city, $state, $zipcode );

        // Fail open: false means API error, skip blocking.
        if( $result === false ) return;

        if( ! $result['valid'] ) {

            $ip     = ip_utils::get_client_ip();
            $reason = 'Smarty address verification failed: ' . implode( ', ', $result['reasons'] );
            db::log_event( $ip, 'classic_checkout', 'blocked', $reason );
            $errors->add( 'mighty_shield_smarty', __( 'Please verify your billing address and try again.', 'mighty-shield' ) );

        }

    }

    /**
     * Flag invalid address after order creation.
     *
     * @since   1.0.0
     *
     * @param   int     $order_id   Order ID.
     * @param   array   $posted     Posted data.
     * @param   object  $order      WC_Order object.
     */
    public function flag_invalid_address( $order_id, $posted, $order ) {

        $action = settings::get( 'mshield_smarty_action' );
        if( $action === 'block' ) return;

        if( $order->get_billing_country() !== 'US' ) return;

        $street  = $order->get_billing_address_1();
        $city    = $order->get_billing_city();
        $state   = $order->get_billing_state();
        $zipcode = $order->get_billing_postcode();

        if( empty( $street ) ) return;

        $result = $this->verify_address( $street, $city, $state, $zipcode );

        // Fail open.
        if( $result === false ) return;

        if( ! $result['valid'] ) {

            $ip     = ip_utils::get_client_ip();
            $reason = 'Smarty address verification failed: ' . implode( ', ', $result['reasons'] );

            db::log_event( $ip, 'classic_checkout', 'flagged', $reason );
            $order->add_order_note( 'MightyShield: ' . $reason );
            $order->update_meta_data( '_mshield_flagged', 'smarty_address_invalid' );
            $order->save();

            if( $action === 'notify' ) {
                $this->send_admin_notification( $order, $reason );
            }

        }

    }

    /**
     * Verify an address via Smarty API with caching.
     *
     * @since   1.0.0
     *
     * @param   string  $street     Street address.
     * @param   string  $city       City name.
     * @param   string  $state      State abbreviation.
     * @param   string  $zipcode    ZIP code.
     * @return  array|false         Array with 'valid' and 'reasons', or false on API failure.
     */
    private function verify_address( $street, $city, $state, $zipcode ) {

        $cache_key = $this->get_cache_key( $street, $city, $state, $zipcode );
        $cached    = get_transient( $cache_key );

        // Cache hit: 'api_error' means previous API failure, array means cached result.
        if( $cached === 'api_error' ) {
            return $this->fallback_zip_state( $state, $zipcode );
        }
        if( is_array( $cached ) ) {
            return $cached;
        }

        $response = $this->call_smarty_api( $street, $city, $state, $zipcode );

        // API failure — fall back to ZIP/state check.
        if( is_wp_error( $response ) ) {

            $ip = ip_utils::get_client_ip();
            db::log_event( $ip, 'system', 'degraded', 'Smarty address verification unavailable: ' . $response->get_error_message() . ' — falling back to basic ZIP/State check' );

            // Alert the store admin (throttled) that full verification is off.
            $this->alert_degraded( $response->get_error_message() );

            // Cache API error briefly to avoid hammering a failing API.
            set_transient( $cache_key, 'api_error', MINUTE_IN_SECONDS );

            return $this->fallback_zip_state( $state, $zipcode );

        }

        $result = $this->analyze_response( $response, $state );

        // A successful call means verification has recovered — clear any
        // lingering degraded-state flag so the admin notice disappears.
        if( get_option( 'mshield_smarty_degraded' ) ) {
            delete_option( 'mshield_smarty_degraded' );
        }

        // Cache result for 5 minutes.
        set_transient( $cache_key, $result, 5 * MINUTE_IN_SECONDS );

        return $result;

    }

    /**
     * Call Smarty US Street Address API.
     *
     * @since   1.0.0
     *
     * @param   string  $street     Street address.
     * @param   string  $city       City name.
     * @param   string  $state      State abbreviation.
     * @param   string  $zipcode    ZIP code.
     * @return  array|\WP_Error     Decoded response array or WP_Error.
     */
    private function call_smarty_api( $street, $city, $state, $zipcode ) {

        $auth_id    = settings::get( 'mshield_smarty_auth_id' );
        $auth_token = settings::get( 'mshield_smarty_auth_token' );

        $url = add_query_arg( [
            'auth-id'    => $auth_id,
            'auth-token' => $auth_token,
        ], 'https://us-street.api.smarty.com/street-address' );

        $body = wp_json_encode( [ [
            'street'  => $street,
            'city'    => $city,
            'state'   => $state,
            'zipcode' => $zipcode,
        ] ] );

        $response = wp_remote_post( $url, [
            'headers' => [ 'Content-Type' => 'application/json' ],
            'body'    => $body,
            'timeout' => 5,
        ] );

        if( is_wp_error( $response ) ) return $response;

        $code = wp_remote_retrieve_response_code( $response );

        // Out of tokens or rate limited — return error to trigger fallback.
        if( $code === 402 || $code === 429 ) {
            return new \WP_Error( 'smarty_api_limit', sprintf( 'Smarty API returned HTTP %d (limit reached)', $code ) );
        }

        if( $code !== 200 ) {
            return new \WP_Error( 'smarty_api_error', sprintf( 'Smarty API returned HTTP %d', $code ) );
        }

        $decoded = json_decode( wp_remote_retrieve_body( $response ), true );

        if( ! is_array( $decoded ) ) {
            return new \WP_Error( 'smarty_api_parse', 'Failed to parse Smarty API response' );
        }

        return $decoded;

    }

    /**
     * Analyze Smarty API response for fraud indicators.
     *
     * @since   1.0.0
     *
     * @param   array   $response       Decoded API response.
     * @param   string  $input_state    The state submitted by the customer.
     * @return  array                   [ 'valid' => bool, 'reasons' => string[] ]
     */
    private function analyze_response( $response, $input_state ) {

        $reasons = [];

        // Empty response = address completely unrecognized.
        if( empty( $response ) ) {
            return [ 'valid' => false, 'reasons' => [ 'Address not found (no candidates returned)' ] ];
        }

        $candidate = $response[0];
        $analysis  = isset( $candidate['analysis'] ) ? $candidate['analysis'] : [];
        $metadata  = isset( $candidate['metadata'] ) ? $candidate['metadata'] : [];
        $components = isset( $candidate['components'] ) ? $candidate['components'] : [];

        // Check DPV match code.
        $dpv = isset( $analysis['dpv_match_code'] ) ? $analysis['dpv_match_code'] : '';
        if( empty( $dpv ) || ! in_array( $dpv, [ 'Y', 'D', 'S' ], true ) ) {
            $reasons[] = 'DPV match failed (code: ' . ( $dpv ?: 'missing' ) . ')';
        }

        // Check precision.
        $precision = isset( $metadata['precision'] ) ? $metadata['precision'] : '';
        if( $precision === 'Unknown' ) {
            $reasons[] = 'Address precision unknown';
        }

        // Check DPV footnotes for A1 (address not found in USPS data).
        $dpv_footnotes = isset( $analysis['dpv_footnotes'] ) ? $analysis['dpv_footnotes'] : '';
        if( strpos( $dpv_footnotes, 'A1' ) !== false ) {
            $reasons[] = 'Address not found in USPS data (A1)';
        }

        // Check footnotes for F# (address could not be found).
        $footnotes = isset( $analysis['footnotes'] ) ? $analysis['footnotes'] : '';
        if( strpos( $footnotes, 'F#' ) !== false ) {
            $reasons[] = 'Address could not be found (F#)';
        }

        // Check state mismatch.
        $response_state = isset( $components['state_abbreviation'] ) ? $components['state_abbreviation'] : '';
        if( ! empty( $response_state ) && strtoupper( $input_state ) !== strtoupper( $response_state ) ) {
            $reasons[] = sprintf( 'State mismatch: submitted %s, resolved to %s', strtoupper( $input_state ), $response_state );
        }

        // Require 2+ indicators to flag (avoid false positives from single indicator).
        $valid = count( $reasons ) < 2;

        return [ 'valid' => $valid, 'reasons' => $reasons ];

    }

    /**
     * Fallback to ZIP/state validation.
     *
     * @since   1.0.0
     *
     * @param   string  $state      State abbreviation.
     * @param   string  $zipcode    ZIP code.
     * @return  array|false         Verification result or false if unable to verify.
     */
    private function fallback_zip_state( $state, $zipcode ) {

        $result = zip_state_validator::verify_zip_state( $state, $zipcode );

        // null = unable to verify, treat as fail-open.
        if( $result === null ) return false;

        // true = valid.
        if( $result === true ) return [ 'valid' => true, 'reasons' => [] ];

        // String = mismatch reason.
        return [ 'valid' => false, 'reasons' => [ $result . ' (Smarty fallback)' ] ];

    }

    /**
     * Get cache key for an address.
     *
     * @since   1.0.0
     *
     * @param   string  $street     Street address.
     * @param   string  $city       City name.
     * @param   string  $state      State abbreviation.
     * @param   string  $zipcode    ZIP code.
     * @return  string
     */
    private function get_cache_key( $street, $city, $state, $zipcode ) {

        $normalized = strtolower( trim( $street ) . '|' . trim( $city ) . '|' . trim( $state ) . '|' . trim( $zipcode ) );
        return 'mshield_smarty_' . md5( $normalized );

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
        $subject     = sprintf( '[MightyShield] Address verification failed for order #%d', $order->get_id() );
        $message     = sprintf(
            "Smarty address verification failed for an order.\n\nOrder: #%d\nAmount: %s\nReason: %s\nCustomer: %s (%s)\nAddress: %s, %s, %s %s\nIP: %s\n\nReview this order: %s",
            $order->get_id(),
            $order->get_formatted_order_total(),
            $reason,
            $order->get_formatted_billing_full_name(),
            $order->get_billing_email(),
            $order->get_billing_address_1(),
            $order->get_billing_city(),
            $order->get_billing_state(),
            $order->get_billing_postcode(),
            $order->get_customer_ip_address(),
            $order->get_edit_order_url()
        );

        wp_mail( $admin_email, $subject, $message );

    }

}
