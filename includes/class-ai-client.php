<?php
/**
 * AI Client.
 *
 * Sends a fraud-review prompt to the configured provider and returns a
 * structured verdict carrying a 1-100 trust rating — the same scale the rest of
 * the plugin uses, so nothing converts it. Every failure path fails open — a provider outage must never hold a
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
     * Output cap.
     *
     * Was 32 back when the model was asked for nothing but a bare number. The
     * structured verdict carries reasons the merchant actually reads, and a
     * truncated response is a wasted call, so this is sized for the schema
     * rather than shaved to the bone.
     *
     * @since   1.8.0
     */
    const MAX_TOKENS = 1024;

    /**
     * The verdict schema every provider is held to.
     *
     * Replaces scraping a number out of prose. A regex over free text fails in
     * ways that matter here: an unparseable reply used to mean the order went
     * through unreviewed, and "rating 8, but note the address is fake" parsed
     * as a clean 8. Constraining the output means the fields are always
     * present and always the right type.
     *
     * NO minimum/maximum, deliberately. A strict tool schema is a restricted
     * subset of JSON Schema, and Anthropic rejects numeric bounds outright:
     *
     *   400 tools.0.custom: For 'integer' type, properties maximum, minimum
     *       are not supported
     *
     * which took the whole AI review offline. The ranges are stated in each
     * description, where the model actually reads them, and enforced in
     * validate(), which clamps both. Nothing was lost by removing them: the
     * bounds were never what kept the values in range.
     *
     * @since   1.9.0
     */
    const VERDICT_SCHEMA = [
        'type'       => 'object',
        'properties' => [
            'trust' => [
                'type'        => 'integer',
                'description' => 'How trustworthy this order looks, 1-100. 100 is a completely ordinary order from a real customer; 1 is blatant fraud.',
            ],
            'verdict' => [
                'type'        => 'string',
                'enum'        => [ 'allow', 'review', 'deny' ],
                'description' => 'allow: nothing here warrants friction. review: a person should look before this ships. deny: this should not go through.',
            ],
            'reasons' => [
                'type'        => 'array',
                'items'       => [ 'type' => 'string' ],
                'description' => 'Short, concrete reasons for the rating, each referring to specific evidence in the order. These are shown to the shop owner, so write them for a person deciding whether to ship.',
            ],
            'confidence' => [
                'type'        => 'number',
                'description' => 'How confident you are in this assessment, 0-1. Be honest: a low confidence is more useful than a confident guess.',
            ],
        ],
        'required'             => [ 'trust', 'verdict', 'reasons', 'confidence' ],
        'additionalProperties' => false,
    ];

    /**
     * Tool name the model fills in to return its verdict.
     *
     * @since   1.9.0
     */
    const VERDICT_TOOL = 'record_fraud_assessment';

    /**
     * Whether AI review can actually run.
     *
     * Switched on AND holding a key for the selected provider. The two are
     * separate settings on separate rows, so "enabled" alone has never been
     * enough — an install with the toggle on and the key blank would queue
     * calls that can only fail.
     *
     * @since   1.9.1
     *
     * @return  bool
     */
    public static function is_ready() {

        if( settings::get( 'mshield_ai_enabled' ) !== 'yes' ) return false;

        return self::provider_key() !== '';

    }

    /**
     * The API key for the currently selected provider.
     *
     * Anthropic is the default arm of the provider switch in review(), so an
     * unrecognised provider resolves to the Anthropic key here too. The two
     * must agree or is_ready() would vouch for a key review() never uses.
     *
     * @since   1.9.1
     *
     * @return  string
     */
    private static function provider_key() {

        switch( settings::get( 'mshield_ai_provider' ) ) {
            case 'openai':
                return trim( (string) settings::get( 'mshield_ai_openai_key' ) );
            case 'gemini':
                return trim( (string) settings::get( 'mshield_ai_gemini_key' ) );
            case 'anthropic':
            default:
                return trim( (string) settings::get( 'mshield_ai_anthropic_key' ) );
        }

    }

    /**
     * Review a prompt and return the rating.
     *
     * @since   1.8.0
     *
     * @param   string  $prompt
     * @return  array|\WP_Error  Verdict [ trust, verdict, reasons, confidence ],
     *                           or WP_Error on any failure.
     */
    public static function review( $prompt ) {

        if( ! self::within_budget() ) {
            return new \WP_Error( 'mshield_ai_capped', 'Daily AI review limit reached' );
        }

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

        $verdict = self::validate( $response );

        if( is_wp_error( $verdict ) ) {
            self::degrade( $verdict->get_error_message() );
            return $verdict;
        }

        // A successful review means the provider is healthy — clear any
        // lingering degraded flag so the admin notice disappears.
        if( get_option( 'mshield_ai_degraded' ) ) {
            delete_option( 'mshield_ai_degraded' );
        }

        return $verdict;

    }

    /**
     * Whether another provider call is allowed today.
     *
     * A cap matters here specifically because the caller is a checkout: an
     * attacker who can submit orders can otherwise spend the store's API
     * budget at will. Counted per UTC day and stored as a plain transient, so
     * hitting the cap costs nothing.
     *
     * Reaching the cap fails open — orders keep going through, unreviewed —
     * which matches how every other external dependency in this plugin
     * behaves, and is logged so the merchant finds out.
     *
     * @since   1.9.0
     *
     * @return  bool
     */
    private static function within_budget() {

        $cap = (int) settings::get( 'mshield_ai_daily_cap' );
        if( $cap <= 0 ) return true;

        $key   = 'mshield_ai_calls_' . gmdate( 'Ymd' );
        $count = (int) get_transient( $key );

        if( $count >= $cap ) {

            // Log once per day rather than on every blocked call.
            if( ! get_transient( 'mshield_ai_cap_logged' ) ) {

                set_transient( 'mshield_ai_cap_logged', 1, DAY_IN_SECONDS );

                db::log_event(
                    ip_utils::get_client_ip(),
                    'system',
                    'degraded',
                    sprintf( 'Daily AI review limit of %d reached — further orders are going through unreviewed today', $cap )
                );

            }

            return false;

        }

        // Two days, so a call late in the day cannot expire the counter early.
        set_transient( $key, $count + 1, 2 * DAY_IN_SECONDS );

        return true;

    }

    /**
     * How many provider calls have been made today.
     *
     * @since   1.9.0
     *
     * @return  int
     */
    public static function calls_today() {

        return (int) get_transient( 'mshield_ai_calls_' . gmdate( 'Ymd' ) );

    }

    /**
     * Validate and normalise a provider verdict.
     *
     * The schema is enforced provider-side, but this is a security boundary
     * and the response comes from a third party over the network — so the
     * shape is checked again here rather than trusted.
     *
     * @since   1.9.0
     *
     * @param   mixed   $verdict
     * @return  array|\WP_Error
     */
    public static function validate( $verdict ) {

        if( ! is_array( $verdict ) ) {
            return new \WP_Error( 'mshield_ai_shape', 'AI returned no usable verdict' );
        }

        foreach( [ 'trust', 'verdict' ] as $field ) {
            if( ! isset( $verdict[ $field ] ) ) {
                return new \WP_Error( 'mshield_ai_shape', 'AI verdict is missing the "' . $field . '" field' );
            }
        }

        if( ! \in_array( $verdict['verdict'], [ 'allow', 'review', 'deny' ], true ) ) {
            return new \WP_Error( 'mshield_ai_shape', 'AI returned an unrecognised verdict' );
        }

        // Clamped rather than rejected: a model that answers 0 or 105 has still
        // told us what it thinks, and failing the whole review over an
        // off-by-one would just send an order through unexamined.
        $trust = (int) $verdict['trust'];

        $reasons = [];
        foreach( (array) ( $verdict['reasons'] ?? [] ) as $reason ) {
            $reason = sanitize_text_field( (string) $reason );
            if( $reason !== '' ) $reasons[] = $reason;
        }

        return [
            'trust'      => max( 1, min( 100, $trust ) ),
            'verdict'    => $verdict['verdict'],
            'reasons'    => $reasons,
            'confidence' => max( 0.0, min( 1.0, (float) ( $verdict['confidence'] ?? 0.5 ) ) ),
        ];

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
            // strict:true on the tool definition guarantees the arguments
            // validate against the schema exactly, and forcing tool_choice
            // means the model cannot answer in prose instead.
            'tools'      => [ [
                'name'         => self::VERDICT_TOOL,
                'description'  => 'Record your fraud assessment of this order.',
                'strict'       => true,
                'input_schema' => self::VERDICT_SCHEMA,
            ] ],
            'tool_choice' => [ 'type' => 'tool', 'name' => self::VERDICT_TOOL ],
            'messages'    => [ [ 'role' => 'user', 'content' => $prompt ] ],
        ] );

        if( is_wp_error( $response ) ) return $response;

        // The verdict comes back as the tool_use block's input, which is
        // already decoded. Never string-match the serialized form: escaping
        // varies between models.
        foreach( (array) ( $response['content'] ?? [] ) as $block ) {

            if( ( $block['type'] ?? '' ) === 'tool_use' && is_array( $block['input'] ?? null ) ) {
                return $block['input'];
            }

        }

        return new \WP_Error( 'mshield_ai_shape', 'Anthropic returned no verdict' );

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
            'model'           => settings::get( 'mshield_ai_openai_model' ),
            'max_tokens'      => self::MAX_TOKENS,
            'response_format' => [
                'type'        => 'json_schema',
                'json_schema' => [
                    'name'   => self::VERDICT_TOOL,
                    'strict' => true,
                    'schema' => self::VERDICT_SCHEMA,
                ],
            ],
            'messages'        => [ [ 'role' => 'user', 'content' => $prompt ] ],
        ] );

        if( is_wp_error( $response ) ) return $response;

        $content = $response['choices'][0]['message']['content'] ?? null;

        if( ! is_string( $content ) ) {
            return new \WP_Error( 'mshield_ai_shape', 'Unexpected OpenAI response shape' );
        }

        $decoded = json_decode( $content, true );

        return is_array( $decoded )
            ? $decoded
            : new \WP_Error( 'mshield_ai_shape', 'OpenAI returned a verdict that was not valid JSON' );

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
        $url   = 'https://generativelanguage.googleapis.com/v1beta/models/' . $model . ':generateContent';

        // Gemini rejects additionalProperties in responseSchema, so it gets a
        // trimmed copy. The schema still pins the field names and types.
        $schema = self::VERDICT_SCHEMA;
        unset( $schema['additionalProperties'] );

        // The key goes in a header, not the query string. A URL ends up in proxy
        // logs, server access logs and error reports; a header does not.
        $response = self::post( $url, [
            'Content-Type'   => 'application/json',
            'x-goog-api-key' => $key,
        ], [
            'contents'         => [ [ 'parts' => [ [ 'text' => $prompt ] ] ] ],
            'generationConfig' => [
                'maxOutputTokens'  => self::MAX_TOKENS,
                'responseMimeType' => 'application/json',
                'responseSchema'   => $schema,
            ],
        ] );

        if( is_wp_error( $response ) ) return $response;

        $content = $response['candidates'][0]['content']['parts'][0]['text'] ?? null;

        if( ! is_string( $content ) ) {
            return new \WP_Error( 'mshield_ai_shape', 'Unexpected Gemini response shape' );
        }

        $decoded = json_decode( $content, true );

        return is_array( $decoded )
            ? $decoded
            : new \WP_Error( 'mshield_ai_shape', 'Gemini returned a verdict that was not valid JSON' );

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
            // Carry the provider's own message through. Without it the admin
            // notice read "AI provider returned HTTP 400" and nothing else,
            // which is unactionable -- the API had said exactly which field of
            // the request it objected to, and the plugin threw it away. That
            // cost a day of AI review being silently off.
            $detail = self::error_detail( $response );

            return new \WP_Error( 'mshield_ai_http', $detail === ''
                ? sprintf( 'AI provider returned HTTP %d', $code )
                : sprintf( 'AI provider returned HTTP %d: %s', $code, $detail ) );
        }

        $decoded = json_decode( wp_remote_retrieve_body( $response ), true );

        if( ! is_array( $decoded ) ) {
            return new \WP_Error( 'mshield_ai_json', 'Failed to parse the AI provider response' );
        }

        return $decoded;

    }

    /**
     * The provider's own explanation of a failed request.
     *
     * Every provider nests it differently, so try each shape and fall back to a
     * truncated body rather than nothing. Truncated because this ends up in an
     * admin notice and an email, and a provider echoing the request back would
     * otherwise paste the whole prompt into both.
     *
     * @since   1.9.7
     *
     * @param   array   $response   Raw wp_remote_post response.
     * @return  string  '' when nothing useful could be read.
     */
    private static function error_detail( $response ) {

        $body = (string) wp_remote_retrieve_body( $response );
        if( $body === '' ) return '';

        $decoded = json_decode( $body, true );

        if( is_array( $decoded ) ) {

            // Anthropic and OpenAI: { error: { message } }. Gemini:
            // { error: { message } } as well, but nested under a status object
            // on some errors.
            $message = $decoded['error']['message']
                ?? $decoded['error']['status']
                ?? $decoded['message']
                ?? '';

            if( is_string( $message ) && $message !== '' ) {
                return self::trim_detail( $message );
            }

        }

        return self::trim_detail( $body );

    }

    /**
     * Keep an error readable in a notice without pasting a prompt into it.
     *
     * @since   1.9.7
     *
     * @param   string  $text
     * @return  string
     */
    private static function trim_detail( $text ) {

        $text = trim( preg_replace( '/\s+/', ' ', wp_strip_all_tags( $text ) ) );

        return strlen( $text ) > 300 ? substr( $text, 0, 297 ) . '...' : $text;

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

        // settings::notification_recipients(), not admin_page — the method was
        // moved there in 1.8.0 precisely because the checkout path needs it,
        // but this call site was left behind. Since admin_page is always loaded
        // the class_exists() guard was always true, so every provider failure
        // called a method that does not exist and fatalled the checkout —
        // turning the deliberate fail-open into a hard failure at exactly the
        // moment it was supposed to get out of the shopper's way.
        wp_mail( settings::notification_recipients(), '[MightyShield] AI order review is unavailable', $message );

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
