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
use MightyShield\Includes\api_error;
use MightyShield\Includes\risk_context;

class smarty_address_verifier {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // The notice registers first, and unconditionally. It used to sit below
        // the two guards, so a merchant who reacted to a credentials error by
        // clearing the bad token stopped being told about the very token they
        // had just cleared -- the warning vanished and read as fixed.
        if( is_admin() ) {
            add_action( 'admin_notices', [ $this, 'render_degraded_notice' ] );
        }

        if( settings::get( 'mshield_smarty_enabled' ) !== 'yes' ) return;
        if( empty( settings::get( 'mshield_smarty_auth_id' ) ) || empty( settings::get( 'mshield_smarty_auth_token' ) ) ) return;

        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess_checkout' ], 20, 2 );

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
    private static function alert_degraded( $error_message ) {

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

        // No "check your quota and API keys" any more. That sentence was on
        // every one of these regardless of the status code, and on a 401 caused
        // by the transport it sent people to rotate perfectly good credentials.
        // The message now carries whatever Smarty itself said (see api_error).
        printf(
            '<div class="notice notice-error"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
            esc_html__( 'MightyShield:', 'mighty-shield' ),
            esc_html( sprintf(
                /* translators: %s: API error message. */
                __( 'Address verification (Smarty) is degraded and is falling back to a basic ZIP and state check. Full USPS verification is NOT running. Last error: %s', 'mighty-shield' ),
                $degraded['message']
            ) ),
            \MightyShield\Admin\admin_page::dismiss_url( 'mshield_smarty_degraded' ),
            esc_html__( 'Dismiss', 'mighty-shield' )
        );

    }

    /**
     * Score the address against USPS records. Runs before any order exists.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object, unused — this layer does not refuse.
     */
    public function assess_checkout( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        $reason = self::assess( $data );
        if( $reason === null ) return;

        db::log_event( ip_utils::get_client_ip(), 'classic_checkout', 'flagged', $reason );

    }

    /**
     * Verify the address against USPS data and record anything it cannot find.
     *
     * The one place this check turns into a signal, called by both checkouts.
     * Until now this check did not exist on the block checkout at all: the
     * class registers classic hooks only, so a store on the block checkout was
     * paying for a Smarty subscription that never verified a single order.
     *
     * Fails open at every step. An API error, an exhausted quota or an
     * unmappable ZIP all return null, which is the same as saying nothing, and
     * a shopper is never refused because a third party was unreachable.
     *
     * @since   2.0.0
     *
     * @param   array   $data   Normalised billing fields.
     * @return  string|null Reason the address could not be verified, or null.
     */
    public static function assess( $data ) {

        // Static, so it carries its own copy of the constructor's gate.
        if( settings::get( 'mshield_smarty_enabled' ) !== 'yes' ) return null;
        if( empty( settings::get( 'mshield_smarty_auth_id' ) ) || empty( settings::get( 'mshield_smarty_auth_token' ) ) ) return null;

        // Smarty covers US addresses only.
        if( ( isset( $data['billing_country'] ) ? $data['billing_country'] : '' ) !== 'US' ) return null;

        $street  = isset( $data['billing_address_1'] ) ? trim( $data['billing_address_1'] ) : '';
        $city    = isset( $data['billing_city'] ) ? trim( $data['billing_city'] ) : '';
        $state   = isset( $data['billing_state'] ) ? trim( $data['billing_state'] ) : '';
        $zipcode = isset( $data['billing_postcode'] ) ? trim( $data['billing_postcode'] ) : '';

        if( empty( $street ) ) return null;

        $result = self::verify_address( $street, $city, $state, $zipcode );

        // Fail open: false means the API could not answer.
        if( $result === false ) return null;
        if( $result['valid'] ) return null;

        $reason = 'Smarty address verification failed: ' . implode( ', ', $result['reasons'] );

        risk_context::add( 'address_unverified', $reason );

        return $reason;

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
    private static function verify_address( $street, $city, $state, $zipcode ) {

        $cache_key = self::get_cache_key( $street, $city, $state, $zipcode );
        $cached    = get_transient( $cache_key );

        // Cache hit: 'api_error' means previous API failure, array means cached result.
        if( $cached === 'api_error' ) {
            return self::fallback_zip_state( $state, $zipcode );
        }
        if( is_array( $cached ) ) {

            // Clearing on the way out of a cache hit too, not only after a live
            // call. The delete used to sit below this return, so once the
            // service recovered the first customer's address cached a success
            // and every checkout for the next five minutes took this branch --
            // leaving the red "verification is degraded" notice up long after
            // verification had come back.
            self::mark_recovered();

            return $cached;

        }

        $response = self::call_smarty_api( $street, $city, $state, $zipcode );

        // API failure — fall back to ZIP/state check.
        if( is_wp_error( $response ) ) {

            $ip = ip_utils::get_client_ip();
            db::log_event( $ip, 'system', 'degraded', 'Smarty address verification unavailable: ' . $response->get_error_message() . ' — falling back to basic ZIP/State check' );

            // Alert the store admin (throttled) that full verification is off.
            self::alert_degraded( $response->get_error_message() );

            // Cache API error briefly to avoid hammering a failing API.
            set_transient( $cache_key, 'api_error', MINUTE_IN_SECONDS );

            return self::fallback_zip_state( $state, $zipcode );

        }

        $result = self::analyze_response( $response, $state );

        self::mark_recovered();

        // Cache result for 5 minutes.
        set_transient( $cache_key, $result, 5 * MINUTE_IN_SECONDS );

        return $result;

    }

    /**
     * Try both credential transports and keep the one that answers.
     *
     * Which transport works is a property of the merchant's own server, not of
     * their Smarty account: Basic is the better choice, but it is undocumented
     * on the US Street page and some hosts and WAFs strip outbound
     * Authorization headers. Guessing produced a second broken release once
     * already. So this asks, from the server that will be making the calls,
     * and stores the answer.
     *
     * Costs the merchant one or two lookups. Basic is tried first and the query
     * transport is only attempted if it fails, so a healthy store pays for one.
     *
     * @since   2.0.1
     *
     * @return  array   [ 'ok' => bool, 'mode' => string|null, 'message' => string,
     *                    'tried' => [ mode => 'HTTP 200' | error ] ]
     */
    public static function ping() {

        $result = [ 'ok' => false, 'mode' => null, 'message' => '', 'tried' => [] ];

        if( settings::get( 'mshield_smarty_auth_id' ) === '' || settings::get( 'mshield_smarty_auth_token' ) === '' ) {

            $result['message'] = __( 'No Smarty Auth ID and Auth Token are saved. Enter them and save the page first: this tests what is stored, not what is typed.', 'mighty-shield' );

            return $result;

        }

        // A real, deliverable address, so a 200 means the account resolved it
        // rather than merely accepting the credentials.
        foreach( [ 'basic', 'query' ] as $mode ) {

            $response = self::send( '1600 Amphitheatre Pkwy', 'Mountain View', 'CA', '94043', $mode );

            if( is_wp_error( $response ) ) {
                $result['tried'][ $mode ] = $response->get_error_message();
                continue;
            }

            $code = (int) wp_remote_retrieve_response_code( $response );

            if( $code === 200 ) {

                $result['tried'][ $mode ] = 'HTTP 200';
                $result['ok']             = true;
                $result['mode']           = $mode;

                settings::update( 'mshield_smarty_auth_mode', $mode );
                self::clear_degraded();

                $result['message'] = $mode === 'basic'
                    ? __( 'Smarty answered. Credentials are being sent as HTTP Basic, which keeps them out of the request URL.', 'mighty-shield' )
                    : __( 'Smarty answered, but only with the credentials in the query string. This server does not deliver the Authorization header, so that is what MightyShield will use.', 'mighty-shield' );

                return $result;

            }

            $result['tried'][ $mode ] = api_error::explain( 'Smarty', $code, api_error::detail( $response ) );

        }

        // Both refused. Report the Basic attempt, which is the one that says
        // something useful about the credentials themselves.
        $result['message'] = $result['tried']['basic'] ?? __( 'Smarty did not answer on either transport.', 'mighty-shield' );

        return $result;

    }

    /**
     * Verification is working again, so stop saying it is not.
     *
     * @since   2.0.1
     */
    private static function mark_recovered() {

        if( get_option( 'mshield_smarty_degraded' ) ) self::clear_degraded();

    }

    /**
     * Forget the degraded state entirely.
     *
     * The throttle goes with the option, or the next real failure would record
     * the state without telling anybody for up to a day.
     *
     * @since   2.0.1
     */
    public static function clear_degraded() {

        delete_option( 'mshield_smarty_degraded' );
        delete_transient( 'mshield_smarty_alerted' );

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
    private static function call_smarty_api( $street, $city, $state, $zipcode ) {

        $response = self::send( $street, $city, $state, $zipcode, self::auth_mode() );

        if( is_wp_error( $response ) ) return $response;

        $code = wp_remote_retrieve_response_code( $response );

        if( $code !== 200 ) {

            $detail = api_error::detail( $response );

            // 401/403 used to fall into the generic arm and arrive as a bare
            // "Smarty API returned HTTP 401", which sent an investigation after
            // the account's quota and its credentials. Neither was the problem:
            // the credentials were being sent in a form Smarty does not accept,
            // and the response body said so. Telling these four codes apart is
            // the difference between a two-minute fix and a lost day.
            $message = api_error::explain( 'Smarty', $code, $detail );

            if( $code === 401 || $code === 403 ) {

                $message .= ' ' . sprintf(
                    /* translators: %s: the transport in use, e.g. "HTTP Basic". */
                    __( 'Credentials were sent as %s. Use Test Connection on the Scoring tab to find the form this server can actually deliver.', 'mighty-shield' ),
                    self::auth_mode() === 'query' ? __( 'query parameters', 'mighty-shield' ) : __( 'HTTP Basic', 'mighty-shield' )
                );

                return new \WP_Error( 'smarty_api_auth', $message );

            }

            if( $code === 402 || $code === 429 ) return new \WP_Error( 'smarty_api_limit', $message );

            return new \WP_Error( 'smarty_api_error', $message );

        }

        $decoded = json_decode( wp_remote_retrieve_body( $response ), true );

        if( ! is_array( $decoded ) ) {
            return new \WP_Error( 'smarty_api_parse', __( 'Smarty replied, but the response could not be read as JSON.', 'mighty-shield' ) );
        }

        return $decoded;

    }

    /**
     * How this store sends its Smarty credentials.
     *
     * @since   2.0.1
     *
     * @return  string  'basic' or 'query'.
     */
    public static function auth_mode() {

        return settings::get( 'mshield_smarty_auth_mode' ) === 'query' ? 'query' : 'basic';

    }

    /**
     * Post one address to Smarty using a named credential transport.
     *
     * Smarty accepts secret keys two ways, and only two: as query parameters,
     * or as HTTP Basic. It does NOT implement the Auth-ID / Auth-Token headers
     * this used to send, so every call returned 401 — the intent behind them,
     * keeping secrets out of URLs where proxies and error reporters record them,
     * was right, but the header names were invented.
     *
     * Basic keeps that intent and is the default. It is not documented on the US
     * Street page though, and some hosts and WAFs strip outbound Authorization
     * headers, so which one works is a per-server question. Test Connection
     * answers it by trying both and storing the winner.
     *
     * Split out from call_smarty_api() so the test can drive either transport
     * without going through the cache or the degraded bookkeeping.
     *
     * @since   2.0.1
     *
     * @param   string  $street
     * @param   string  $city
     * @param   string  $state
     * @param   string  $zipcode
     * @param   string  $mode     'basic' or 'query'.
     * @return  array|\WP_Error   The raw wp_remote_post response.
     */
    public static function send( $street, $city, $state, $zipcode, $mode = 'basic' ) {

        $auth_id    = settings::get( 'mshield_smarty_auth_id' );
        $auth_token = settings::get( 'mshield_smarty_auth_token' );

        $url = 'https://us-street.api.smarty.com/street-address';

        $headers = [ 'Content-Type' => 'application/json' ];

        if( $mode === 'query' ) {
            $url = add_query_arg( [ 'auth-id' => $auth_id, 'auth-token' => $auth_token ], $url );
        } else {
            $headers['Authorization'] = 'Basic ' . base64_encode( $auth_id . ':' . $auth_token );
        }

        $body = wp_json_encode( [ [
            'street'  => $street,
            'city'    => $city,
            'state'   => $state,
            'zipcode' => $zipcode,
        ] ] );

        return wp_remote_post( $url, [
            'headers' => $headers,
            'body'    => $body,
            /**
             * How long to wait on Smarty, in seconds.
             *
             * @since 2.0.1
             * @param int $timeout
             */
            'timeout' => (int) apply_filters( 'mshield_smarty_timeout', 5 ),
        ] );

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
    private static function analyze_response( $response, $input_state ) {

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
    private static function fallback_zip_state( $state, $zipcode ) {

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
    private static function get_cache_key( $street, $city, $state, $zipcode ) {

        $normalized = strtolower( trim( $street ) . '|' . trim( $city ) . '|' . trim( $state ) . '|' . trim( $zipcode ) );
        return 'mshield_smarty_' . md5( $normalized );

    }


}
