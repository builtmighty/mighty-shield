<?php
/**
 * AI Client.
 *
 * Sends a fraud-review prompt to the configured provider and returns a 1-10
 * rating. Every failure path fails open — a provider outage must never hold a
 * legitimate order, so callers receive a WP_Error and take no action.
 *
 * @package MightyShield
 * @since   1.8.0
 */
namespace MightyShield\Includes;

class ai_client {

    /**
     * Request timeout, seconds.
     *
     * Deliberately longer than the plugin's usual 5s: this runs inline on the
     * checkout request and a truncated call is a wasted call. Filterable via
     * mshield_ai_timeout for stores that would rather cap it tighter.
     *
     * @since   1.8.0
     */
    const TIMEOUT = 10;

    /**
     * Output cap. The prompt asks for only an "x/10", so this is a cost guard.
     *
     * @since   1.8.0
     */
    const MAX_TOKENS = 32;

    /**
     * Review a prompt and return the rating.
     *
     * @since   1.8.0
     *
     * @param   string  $prompt
     * @return  int|\WP_Error   Rating 1-10, or WP_Error on any failure.
     */
    public static function review( $prompt ) {

        $provider = settings::get( 'mshield_ai_provider' );

        switch( $provider ) {
            case 'openai':
                $response = self::call_openai( $prompt );
                break;
            case 'gemini':
                $response = self::call_gemini( $prompt );
                break;
            case 'anthropic':
            default:
                $response = self::call_anthropic( $prompt );
                break;
        }

        if( is_wp_error( $response ) ) {
            self::degrade( $response->get_error_message() );
            return $response;
        }

        $rating = self::parse_rating( $response );

        if( is_wp_error( $rating ) ) {
            self::degrade( $rating->get_error_message() );
            return $rating;
        }

        // A successful review means the provider is healthy — clear any
        // lingering degraded flag so the admin notice disappears.
        if( get_option( 'mshield_ai_degraded' ) ) {
            delete_option( 'mshield_ai_degraded' );
        }

        return $rating;

    }

    /**
     * Extract a 1-10 rating from the model's reply.
     *
     * An unparseable reply is an error, never 0 — a zero would read as
     * maximally fraudulent and hold every order on a malformed response.
     *
     * @since   1.8.0
     *
     * @param   string  $text
     * @return  int|\WP_Error
     */
    public static function parse_rating( $text ) {

        $text = trim( (string) $text );

        if( $text === '' ) {
            return new \WP_Error( 'mshield_ai_empty', 'AI returned an empty response' );
        }

        // Preferred shape: "7/10", "7 / 10", "Rating: 3/10".
        if( preg_match( '/\b(\d{1,2})\s*\/\s*10\b/', $text, $m ) ) {
            return self::clamp( (int) $m[1] );
        }

        // Fallback: a bare leading number.
        if( preg_match( '/^\D{0,20}?(\d{1,2})\b/', $text, $m ) ) {
            return self::clamp( (int) $m[1] );
        }

        return new \WP_Error( 'mshield_ai_parse', 'Could not parse a rating from the AI response' );

    }

    /**
     * Clamp a rating into 1-10.
     *
     * @since   1.8.0
     *
     * @param   int     $rating
     * @return  int
     */
    private static function clamp( $rating ) {

        return max( 1, min( 10, $rating ) );

    }

    /**
     * Anthropic Messages API.
     *
     * @since   1.8.0
     *
     * @param   string  $prompt
     * @return  string|\WP_Error
     */
    private static function call_anthropic( $prompt ) {

        $key = settings::get( 'mshield_ai_anthropic_key' );
        if( empty( $key ) ) return new \WP_Error( 'mshield_ai_nokey', 'No Anthropic API key configured' );

        $response = self::post( 'https://api.anthropic.com/v1/messages', [
            'x-api-key'         => $key,
            'anthropic-version' => '2023-06-01',
            'Content-Type'      => 'application/json',
        ], [
            'model'      => settings::get( 'mshield_ai_anthropic_model' ),
            'max_tokens' => self::MAX_TOKENS,
            'messages'   => [ [ 'role' => 'user', 'content' => $prompt ] ],
        ] );

        if( is_wp_error( $response ) ) return $response;

        if( ! isset( $response['content'][0]['text'] ) ) {
            return new \WP_Error( 'mshield_ai_shape', 'Unexpected Anthropic response shape' );
        }

        return $response['content'][0]['text'];

    }

    /**
     * OpenAI Chat Completions API.
     *
     * @since   1.8.0
     *
     * @param   string  $prompt
     * @return  string|\WP_Error
     */
    private static function call_openai( $prompt ) {

        $key = settings::get( 'mshield_ai_openai_key' );
        if( empty( $key ) ) return new \WP_Error( 'mshield_ai_nokey', 'No OpenAI API key configured' );

        $headers = [
            'Authorization' => 'Bearer ' . $key,
            'Content-Type'  => 'application/json',
        ];

        $org = settings::get( 'mshield_ai_openai_org' );
        if( ! empty( $org ) ) {
            $headers['OpenAI-Organization'] = $org;
        }

        $response = self::post( 'https://api.openai.com/v1/chat/completions', $headers, [
            'model'      => settings::get( 'mshield_ai_openai_model' ),
            'max_tokens' => self::MAX_TOKENS,
            'messages'   => [ [ 'role' => 'user', 'content' => $prompt ] ],
        ] );

        if( is_wp_error( $response ) ) return $response;

        if( ! isset( $response['choices'][0]['message']['content'] ) ) {
            return new \WP_Error( 'mshield_ai_shape', 'Unexpected OpenAI response shape' );
        }

        return $response['choices'][0]['message']['content'];

    }

    /**
     * Google Gemini generateContent API.
     *
     * @since   1.8.0
     *
     * @param   string  $prompt
     * @return  string|\WP_Error
     */
    private static function call_gemini( $prompt ) {

        $key = settings::get( 'mshield_ai_gemini_key' );
        if( empty( $key ) ) return new \WP_Error( 'mshield_ai_nokey', 'No Gemini API key configured' );

        $model = rawurlencode( settings::get( 'mshield_ai_gemini_model' ) );
        $url   = add_query_arg( 'key', $key, 'https://generativelanguage.googleapis.com/v1beta/models/' . $model . ':generateContent' );

        $response = self::post( $url, [ 'Content-Type' => 'application/json' ], [
            'contents'         => [ [ 'parts' => [ [ 'text' => $prompt ] ] ] ],
            'generationConfig' => [ 'maxOutputTokens' => self::MAX_TOKENS ],
        ] );

        if( is_wp_error( $response ) ) return $response;

        if( ! isset( $response['candidates'][0]['content']['parts'][0]['text'] ) ) {
            return new \WP_Error( 'mshield_ai_shape', 'Unexpected Gemini response shape' );
        }

        return $response['candidates'][0]['content']['parts'][0]['text'];

    }

    /**
     * Shared JSON POST with error normalization.
     *
     * @since   1.8.0
     *
     * @param   string  $url
     * @param   array   $headers
     * @param   array   $body
     * @return  array|\WP_Error Decoded response body.
     */
    private static function post( $url, $headers, $body ) {

        $response = wp_remote_post( $url, [
            'headers' => $headers,
            'body'    => wp_json_encode( $body ),
            'timeout' => (int) apply_filters( 'mshield_ai_timeout', self::TIMEOUT ),
        ] );

        if( is_wp_error( $response ) ) return $response;

        $code = wp_remote_retrieve_response_code( $response );

        if( $code === 401 || $code === 403 ) {
            return new \WP_Error( 'mshield_ai_auth', sprintf( 'AI provider rejected the API key (HTTP %d)', $code ) );
        }

        if( $code === 429 ) {
            return new \WP_Error( 'mshield_ai_limit', 'AI provider rate limit reached (HTTP 429)' );
        }

        if( $code !== 200 ) {
            return new \WP_Error( 'mshield_ai_http', sprintf( 'AI provider returned HTTP %d', $code ) );
        }

        $decoded = json_decode( wp_remote_retrieve_body( $response ), true );

        if( ! is_array( $decoded ) ) {
            return new \WP_Error( 'mshield_ai_json', 'Failed to parse the AI provider response' );
        }

        return $decoded;

    }

    /**
     * Record a degraded state and alert the admin, throttled to once a day.
     *
     * @since   1.8.0
     *
     * @param   string  $error
     */
    private static function degrade( $error ) {

        db::log_event( ip_utils::get_client_ip(), 'system', 'degraded', 'AI review unavailable: ' . $error . ' — order allowed through unreviewed' );

        update_option( 'mshield_ai_degraded', [
            'time'    => time(),
            'message' => $error,
        ], false );

        if( get_transient( 'mshield_ai_alerted' ) ) return;
        set_transient( 'mshield_ai_alerted', 1, DAY_IN_SECONDS );

        $message = sprintf(
            "MightyShield's AI order review is currently unavailable.\n\n" .
            "Reason: %s\n\n" .
            "Orders are being allowed through WITHOUT AI review until this is resolved. Common causes:\n" .
            "- Invalid or expired API key\n" .
            "- Provider quota exhausted or rate limited\n" .
            "- Network/API outage\n\n" .
            "Check your credentials under MightyShield > AI Detection.\n\n" .
            "This alert is sent at most once per day.",
            $error
        );

        $recipients = class_exists( '\MightyShield\Admin\admin_page' )
            ? \MightyShield\Admin\admin_page::notification_recipients()
            : [ get_option( 'admin_email' ) ];

        wp_mail( $recipients, '[MightyShield] AI order review is unavailable', $message );

    }

    /**
     * Admin notice while the provider is degraded.
     *
     * @since   1.8.0
     */
    public static function render_degraded_notice() {

        if( ! current_user_can( 'manage_woocommerce' ) ) return;

        $degraded = get_option( 'mshield_ai_degraded' );
        if( empty( $degraded ) || empty( $degraded['time'] ) ) return;

        if( ( time() - (int) $degraded['time'] ) > DAY_IN_SECONDS ) return;

        printf(
            '<div class="notice notice-error"><p><strong>%s</strong> %s</p></div>',
            esc_html__( 'MightyShield:', 'mighty-shield' ),
            esc_html( sprintf(
                /* translators: %s: API error message. */
                __( 'AI order review is unavailable and orders are NOT being reviewed. Last error: %s. Check your provider credentials under AI Detection.', 'mighty-shield' ),
                $degraded['message']
            ) )
        );

    }

}
