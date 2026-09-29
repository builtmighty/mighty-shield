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

defined( 'ABSPATH' ) || exit;

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
     * When the current review has to be done by, as a Unix timestamp.
     *
     * A review is one budget, however many providers it takes. Set by review()
     * and by ping(); read by post(), which never asks for more time than is
     * left. Null outside a review, where post() falls back to the full
     * timeout.
     *
     * @since   3.0.0
     */
    private static $deadline = null;

    /**
     * How long an in-flight outage alert holds the throttle.
     *
     * The gap between claiming the throttle and extending it to a full day.
     * Long enough to cover a slow SMTP handshake and a PHP timeout on top of
     * it; short enough that a genuinely undelivered alert is retried within
     * the hour rather than lost for a day.
     *
     * @since   3.0.0
     */
    const SEND_WINDOW = 600;

    /**
     * The models offered per provider, id => label, default first.
     *
     * One list to update when a provider retires a model, which they do
     * (Google retired the whole Gemini 1.5 series in September 2025 and a
     * merchant on the old default got a 404 on every review). A saved id that
     * is no longer here is still shown and kept, so an upgrade never silently
     * moves a store onto a different model.
     *
     * @since   3.0.0
     */
    const MODELS = [
        'anthropic' => [
            'claude-haiku-4-5' => 'Claude Haiku 4.5 (recommended)',
            'claude-sonnet-5'  => 'Claude Sonnet 5',
            'claude-opus-5'    => 'Claude Opus 5',
        ],
        'openai' => [
            'gpt-4o-mini'  => 'GPT-4o mini (recommended)',
            'gpt-4.1-nano' => 'GPT-4.1 nano',
            'gpt-4.1-mini' => 'GPT-4.1 mini',
            'gpt-4.1'      => 'GPT-4.1',
            'gpt-5-nano'   => 'GPT-5 nano',
            'gpt-5-mini'   => 'GPT-5 mini',
            'gpt-5'        => 'GPT-5',
        ],
        'gemini' => [
            'gemini-2.5-flash'      => 'Gemini 2.5 Flash (recommended)',
            'gemini-2.5-flash-lite' => 'Gemini 2.5 Flash-Lite',
            'gemini-2.5-pro'        => 'Gemini 2.5 Pro',
            'gemini-2.0-flash'      => 'Gemini 2.0 Flash',
        ],
    ];

    /**
     * Models to offer for a provider, with the stored choice kept even when
     * it is not on the list.
     *
     * @since   3.0.0
     *
     * @param   string  $provider   anthropic, openai or gemini.
     * @return  array   id => label.
     */
    public static function models( $provider ) {

        $list  = self::MODELS[ $provider ] ?? [];
        $saved = trim( (string) settings::get( 'mshield_ai_' . $provider . '_model' ) );

        if( $saved !== '' && ! isset( $list[ $saved ] ) ) {
            /* translators: %s: a model id the merchant typed in before the list existed */
            $list = [ $saved => sprintf( __( '%s (custom)', 'mighty-shield' ), $saved ) ] + $list;
        }

        return $list;

    }

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
    private static function provider_key( $provider = null ) {

        if( $provider === null ) $provider = settings::get( 'mshield_ai_provider' );

        switch( $provider ) {
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
     * The model to ask, for one provider.
     *
     * Filtered so a site can point at a model that did not exist when this
     * version shipped, or at a fine-tune, without editing the plugin.
     *
     * @since   3.0.0
     *
     * @param   string  $provider
     * @return  string
     */
    private static function model( $provider ) {

        $model = (string) settings::get( 'mshield_ai_' . $provider . '_model' );

        /**
         * Filter the model used for one provider.
         *
         * @since 3.0.0
         *
         * @param string $model
         * @param string $provider  anthropic, openai or gemini.
         */
        return (string) apply_filters( 'mshield_ai_model', $model, $provider );

    }

    /**
     * Send one prompt to one named provider.
     *
     * The switch lived in review() and again in ping(), which is how a ping
     * came to differ from a review in the first place.
     *
     * @since   3.0.0
     *
     * @param   string  $provider
     * @param   string  $prompt
     * @return  array|\WP_Error
     */
    private static function dispatch( $provider, $prompt ) {

        switch( $provider ) {
            case 'openai':
                return self::call_openai( $prompt );
            case 'gemini':
                return self::call_gemini( $prompt );
            case 'anthropic':
            default:
                return self::call_anthropic( $prompt );
        }

    }

    /**
     * The provider to fall back to, or '' when none is configured or usable.
     *
     * @since   3.0.0
     *
     * @param   string  $primary
     * @return  string
     */
    private static function fallback_provider( $primary ) {

        $fallback = (string) settings::get( 'mshield_ai_fallback_provider' );

        if( $fallback === '' || $fallback === $primary ) return '';
        if( ! isset( self::MODELS[ $fallback ] ) )       return '';

        // A fallback with no key is not a fallback. Better to report the
        // primary's own error than a second one about a key nobody set.
        return self::provider_key( $fallback ) === '' ? '' : $fallback;

    }

    /**
     * The HTTP status behind a failure, or 0 when the request never landed.
     *
     * @since   3.0.0
     *
     * @param   \WP_Error   $error
     * @return  int
     */
    private static function status_of( $error ) {

        $data = $error->get_error_data();

        return is_array( $data ) && isset( $data['status'] ) ? (int) $data['status'] : 0;

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
            return new \WP_Error( 'mshield_ai_capped', __( 'Daily AI review limit reached', 'mighty-shield' ) );
        }

        $primary = settings::get( 'mshield_ai_provider' );

        // One deadline for the whole review, not one per attempt. The shopper
        // is waiting at the checkout: a fallback that starts its own ten
        // seconds turns a slow review into twice as slow a review, which is
        // the failure the fallback was supposed to prevent.
        //
        // Cleared in the finally, so nothing that runs later in this process
        // -- ai_async reviewing the next order, a WP-CLI command, a filter
        // callback -- inherits a deadline that expired, which seconds_left()
        // would floor to a 1 second HTTP timeout and read as a flaky provider.
        self::$deadline = time() + (int) apply_filters( 'mshield_ai_timeout', self::TIMEOUT );

        try {

            $verdict = self::attempt( $primary, $prompt );

            if( ! is_wp_error( $verdict ) ) {
                self::succeeded();
                return $verdict;
            }

            $fallback = self::fallback_provider( $primary );

            // Only when this provider is having a bad time, rather than this
            // request being wrong. A malformed request fails identically
            // twice; see api_error::retryable(). And only with time left.
            if( $fallback !== ''
                && self::worth_retrying( $verdict )
                && self::seconds_left() >= 2 ) {

                $second = self::attempt( $fallback, $prompt );

                if( ! is_wp_error( $second ) ) {

                    // Logged rather than silent: a store quietly running on
                    // its second provider for a week is a bill nobody is
                    // expecting.
                    self::log_quietly( sprintf(
                        '%s failed (%s), %s answered instead',
                        self::provider_name( $primary ),
                        $verdict->get_error_message(),
                        self::provider_name( $fallback )
                    ) );

                    // The flag goes, because a verdict came back. The alert
                    // throttle does NOT: a primary that flaps produces a
                    // success between every pair of failures, and clearing the
                    // throttle on each one turned "at most one email a day"
                    // into one every few orders.
                    self::clear_flag();

                    return $second;

                }

                // Both are down, so the merchant is told about both. Reporting
                // only the second sends them to check credentials they never
                // set.
                $verdict = new \WP_Error( $verdict->get_error_code(), sprintf(
                    /* translators: 1: primary provider and its error. 2: fallback provider and its error. */
                    __( '%1$s, then %2$s', 'mighty-shield' ),
                    self::provider_name( $primary ) . ': ' . $verdict->get_error_message(),
                    self::provider_name( $fallback ) . ': ' . $second->get_error_message()
                ), $second->get_error_data() );

            }

            self::degrade( $verdict->get_error_message() );

            return $verdict;

        } finally {

            self::$deadline = null;

        }

    }

    /**
     * Whether a second provider is worth paying for after this failure.
     *
     * api_error::retryable() answers for an HTTP status, and treats 0 as
     * "never reached the provider, try another one". But only post()'s non-200
     * arm attaches a status, so every error raised on OUR side of the
     * conversation -- a verdict that failed validate(), a response shape we
     * did not recognise, a Gemini content filter, a truncated answer -- also
     * arrived as 0 and was retried.
     *
     * That is backwards, and provably so: an HTTP 400 for a malformed request
     * is correctly not retried, while the identical misconfiguration caught
     * client-side bought a second paid call on every single review, forever,
     * with nothing in the admin to say so.
     *
     * So the transport case is the one that has to be positively identified,
     * rather than inferred from an absent status.
     *
     * @since   3.0.0
     *
     * @param   \WP_Error   $error
     * @return  bool
     */
    private static function worth_retrying( $error ) {

        $data = $error->get_error_data();

        if( is_array( $data ) && isset( $data['status'] ) ) {
            return api_error::retryable( (int) $data['status'] );
        }

        // No status and marked as transport: DNS, TLS, a socket that never
        // opened. Another provider genuinely may answer.
        if( is_array( $data ) && ! empty( $data['transport'] ) ) return true;

        // A WP_Error straight out of wp_remote_post() carries WordPress's own
        // data, not ours, and never landed on a provider either.
        return in_array( $error->get_error_code(), [ 'http_request_failed', 'connect_error' ], true );

    }

    /**
     * One provider, asked once, with its answer checked.
     *
     * @since   3.0.0
     *
     * @param   string  $provider
     * @param   string  $prompt
     * @return  array|\WP_Error
     */
    private static function attempt( $provider, $prompt ) {

        $response = self::dispatch( $provider, $prompt );

        return is_wp_error( $response ) ? $response : self::validate( $response );

    }

    /**
     * A review came back. The provider is healthy, so drop the warning.
     *
     * @since   3.0.0
     */
    private static function succeeded() {

        if( get_option( 'mshield_ai_degraded' ) ) self::clear_degraded();

    }

    /**
     * Drop the warning banner without re-arming the alert.
     *
     * For a review the fallback answered. Something came back, so the banner
     * is stale and has to go — but the configured provider is still down, and
     * clearing the daily throttle as well would mean the next failure emails
     * the merchant again. A primary that flaps between two providers produces
     * a success in between every pair of failures, which turned "at most one a
     * day" into one every few orders.
     *
     * @since   3.0.0
     */
    private static function clear_flag() {

        delete_option( 'mshield_ai_degraded' );

    }

    /**
     * One real request to the configured provider, to prove it answers.
     *
     * Deliberately the same call review() makes, minimal prompt aside. A ping
     * that skipped the tool definition and the strict schema would pass while
     * real reviews returned HTTP 400 -- which is exactly the failure this store
     * hit, and exactly what a Test connection button is for.
     *
     * It does not count against the daily budget and does not record a degraded
     * state: the merchant is standing at the screen watching the result, so
     * emailing them about it would be noise, and a deliberate test with a key
     * half-typed should not raise a store-wide alarm.
     *
     * @since   2.0.1
     *
     * @return  true|\WP_Error
     */
    public static function ping() {

        if( self::provider_key() === '' ) {
            return new \WP_Error( 'mshield_ai_nokey', sprintf(
                /* translators: %s: provider name. */
                __( 'No %s API key is saved. Enter one and save the page first: the key fields are write-only, so this tests what is stored, not what is typed.', 'mighty-shield' ),
                self::provider_name()
            ) );
        }

        $prompt = 'Connection test. Record a verdict of clean with trust 100 and confidence 0.';

        // Its own deadline, and no fallback: the merchant asked whether THIS
        // provider answers. A test that silently passed because a different
        // provider picked it up would be worse than no test.
        self::$deadline = time() + (int) apply_filters( 'mshield_ai_timeout', self::TIMEOUT );

        // finally, not a bare assignment after the call: dispatch() runs three
        // third-party filters now (mshield_ai_model, mshield_ai_request_body,
        // mshield_ai_timeout), and a callback that throws would leave the
        // deadline set for the rest of the process.
        try {
            $response = self::dispatch( settings::get( 'mshield_ai_provider' ), $prompt );
        } finally {
            self::$deadline = null;
        }

        if( is_wp_error( $response ) ) return $response;

        // The verdict's content does not matter -- the model was asked for a
        // fixed answer about nothing. That it came back in the agreed shape is
        // the whole result.
        $verdict = self::validate( $response );

        return is_wp_error( $verdict ) ? $verdict : true;

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

        // One atomic increment in the rate-limit table, not a transient read
        // followed by a write: two checkouts arriving together each read the
        // same count and the cap overshot by however many were in flight,
        // and a persistent object cache could drop the transient outright.
        // The window is a rolling day, which is what "daily" has to mean
        // when nothing resets it at midnight anyway.
        $count = (int) db::increment_rate_limit( md5( 'ai|calls' ), 'ai_calls', DAY_IN_SECONDS );

        if( $count > $cap ) {

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

        // The rolling-day counter within_budget() increments.
        return (int) db::check_rate_limit( md5( 'ai|calls' ), 'ai_calls' );

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
            return new \WP_Error( 'mshield_ai_shape', __( 'AI returned no usable verdict', 'mighty-shield' ) );
        }

        foreach( [ 'trust', 'verdict' ] as $field ) {
            if( ! isset( $verdict[ $field ] ) ) {
                return new \WP_Error( 'mshield_ai_shape', sprintf(
                    /* translators: %s: the name of the missing field. */
                    __( 'AI verdict is missing the "%s" field', 'mighty-shield' ),
                    $field
                ) );
            }
        }

        if( ! \in_array( $verdict['verdict'], [ 'allow', 'review', 'deny' ], true ) ) {
            return new \WP_Error( 'mshield_ai_shape', __( 'AI returned an unrecognised verdict', 'mighty-shield' ) );
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
        if( empty( $key ) ) return new \WP_Error( 'mshield_ai_nokey', __( 'No Anthropic API key configured', 'mighty-shield' ) );

        $response = self::post( 'https://api.anthropic.com/v1/messages', [
            'x-api-key'         => $key,
            'anthropic-version' => '2023-06-01',
            'Content-Type'      => 'application/json',
        ], [
            'model'      => self::model( 'anthropic' ),
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
        ], 'anthropic' );

        if( is_wp_error( $response ) ) return $response;

        // The verdict comes back as the tool_use block's input, which is
        // already decoded. Never string-match the serialized form: escaping
        // varies between models.
        foreach( (array) ( $response['content'] ?? [] ) as $block ) {

            if( ( $block['type'] ?? '' ) === 'tool_use' && is_array( $block['input'] ?? null ) ) {
                return $block['input'];
            }

        }

        return new \WP_Error( 'mshield_ai_shape', __( 'Anthropic returned no verdict', 'mighty-shield' ) );

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
        if( empty( $key ) ) return new \WP_Error( 'mshield_ai_nokey', __( 'No OpenAI API key configured', 'mighty-shield' ) );

        $headers = [
            'Authorization' => 'Bearer ' . $key,
            'Content-Type'  => 'application/json',
        ];

        $org = settings::get( 'mshield_ai_openai_org' );
        if( ! empty( $org ) ) {
            $headers['OpenAI-Organization'] = $org;
        }

        $response = self::post( 'https://api.openai.com/v1/chat/completions', $headers, [
            'model'           => self::model( 'openai' ),
            // max_completion_tokens, not max_tokens: the newer models reject
            // the old name outright, and every current one accepts the new.
            'max_completion_tokens' => self::MAX_TOKENS,
            'response_format' => [
                'type'        => 'json_schema',
                'json_schema' => [
                    'name'   => self::VERDICT_TOOL,
                    'strict' => true,
                    'schema' => self::VERDICT_SCHEMA,
                ],
            ],
            'messages'        => [ [ 'role' => 'user', 'content' => $prompt ] ],
        ], 'openai' );

        if( is_wp_error( $response ) ) return $response;

        $content = $response['choices'][0]['message']['content'] ?? null;

        if( ! is_string( $content ) ) {
            return new \WP_Error( 'mshield_ai_shape', __( 'Unexpected OpenAI response shape', 'mighty-shield' ) );
        }

        $decoded = json_decode( $content, true );

        return is_array( $decoded )
            ? $decoded
            : new \WP_Error( 'mshield_ai_shape', __( 'OpenAI returned a verdict that was not valid JSON', 'mighty-shield' ) );

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
        if( empty( $key ) ) return new \WP_Error( 'mshield_ai_nokey', __( 'No Gemini API key configured', 'mighty-shield' ) );

        $model = self::model( 'gemini' );
        $url   = 'https://generativelanguage.googleapis.com/v1beta/models/' . rawurlencode( $model ) . ':generateContent';

        // Gemini rejects additionalProperties in responseSchema, so it gets a
        // trimmed copy. The schema still pins the field names and types.
        $schema = self::VERDICT_SCHEMA;
        unset( $schema['additionalProperties'] );

        $config = [
            'maxOutputTokens'  => self::MAX_TOKENS,
            'responseMimeType' => 'application/json',
            'responseSchema'   => $schema,
        ];

        // 2.5 models think by default, and the reasoning comes out of
        // maxOutputTokens before a single character of the verdict does. A
        // verdict is a number and a sentence; it does not need deliberation,
        // and an unbudgeted thinker can spend the entire cap and hand back a
        // candidate with no parts in it at all.
        if( self::gemini_allows_no_thinking( $model ) ) {
            $config['thinkingConfig'] = [ 'thinkingBudget' => 0 ];
        }

        // The key goes in a header, not the query string. A URL ends up in proxy
        // logs, server access logs and error reports; a header does not.
        $response = self::post( $url, [
            'Content-Type'   => 'application/json',
            'x-goog-api-key' => $key,
        ], [
            'contents'         => [ [ 'parts' => [ [ 'text' => $prompt ] ] ] ],
            'generationConfig' => $config,
        ], 'gemini' );

        if( is_wp_error( $response ) ) return $response;

        $content = $response['candidates'][0]['content']['parts'][0]['text'] ?? null;

        if( ! is_string( $content ) ) return self::gemini_no_content( $response );

        $decoded = json_decode( $content, true );

        return is_array( $decoded )
            ? $decoded
            : new \WP_Error( 'mshield_ai_shape', __( 'Gemini returned a verdict that was not valid JSON', 'mighty-shield' ) );

    }

    /**
     * Whether a Gemini model accepts a zero thinking budget.
     *
     * 2.5 Flash and Flash-Lite do. 2.5 Pro always thinks and rejects a zero
     * budget outright, 2.0 has no thinkingConfig at all, and a model id the
     * merchant typed in by hand could be either — so all three get exactly the
     * request they got before, rather than a 400 they cannot act on.
     *
     * @since   3.0.0
     *
     * @param   string  $model
     * @return  bool
     */
    private static function gemini_allows_no_thinking( $model ) {

        $model = strtolower( trim( (string) $model ) );

        return $model === 'gemini-2.5-flash' || $model === 'gemini-2.5-flash-lite';

    }

    /**
     * Explain a Gemini response that carried no verdict text.
     *
     * Gemini says why it stopped, and an absent candidate part almost always
     * means the output cap ran out or a filter fired — not that the response
     * was shaped oddly. Reporting the shape sends the merchant to check their
     * model name when the real answer is in finishReason.
     *
     * @since   3.0.0
     *
     * @param   array   $response
     * @return  \WP_Error
     */
    private static function gemini_no_content( $response ) {

        // is_string, not a bare cast. json_decode($body, true) rules out
        // objects, but an API gateway or a future v1beta shape can put an
        // array here, and (string) [] emits an Array-to-string warning on the
        // shopper's own checkout request.
        $raw_reason = $response['candidates'][0]['finishReason'] ?? '';
        $raw_block  = $response['promptFeedback']['blockReason'] ?? '';

        $reason = is_string( $raw_reason ) ? $raw_reason : '';
        $block  = is_string( $raw_block ) ? $raw_block : '';

        // The filter is checked before the token cap. A response can be both
        // filtered and truncated, and telling the merchant to change models
        // when a content filter fired sends them to fix the wrong thing.
        if( $block !== '' || in_array( $reason, [ 'SAFETY', 'RECITATION', 'PROHIBITED_CONTENT', 'BLOCKLIST' ], true ) ) {
            return new \WP_Error( 'mshield_ai_blocked', sprintf(
                /* translators: %s: the reason Gemini gave, e.g. SAFETY. */
                __( 'Gemini declined to answer (%s). Something in the order details tripped a content filter.', 'mighty-shield' ),
                $block !== '' ? $block : $reason
            ) );
        }

        if( $reason === 'MAX_TOKENS' ) {
            return new \WP_Error( 'mshield_ai_truncated', sprintf(
                /* translators: %d: the output token cap. */
                __( 'Gemini used its whole output budget of %d tokens without returning a verdict. Thinking models spend that budget on reasoning first — try Gemini 2.5 Flash.', 'mighty-shield' ),
                self::MAX_TOKENS
            ) );
        }

        if( $reason !== '' ) {
            return new \WP_Error( 'mshield_ai_shape', sprintf(
                /* translators: %s: the finish reason Gemini gave. */
                __( 'Gemini returned no verdict, and stopped because: %s', 'mighty-shield' ),
                $reason
            ) );
        }

        return new \WP_Error( 'mshield_ai_shape', __( 'Unexpected Gemini response shape', 'mighty-shield' ) );

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
    private static function post( $url, $headers, $body, $provider = '' ) {

        if( $provider === '' ) $provider = (string) settings::get( 'mshield_ai_provider' );

        /**
         * Filter the request body sent to an AI provider.
         *
         * Everything the provider is asked for is in here: the prompt, the
         * tool definition, the token cap, and whatever else that provider's
         * shape carries. A site can add a parameter this version does not
         * know about -- or trim one -- without editing the plugin.
         *
         * The verdict still has to come back in the shape validate() accepts,
         * so a filter that removes the tool or the schema will simply cause
         * every review to fail.
         *
         * @since 3.0.0
         *
         * @param array  $body
         * @param string $provider  anthropic, openai or gemini.
         * @param string $url       The endpoint it is going to.
         */
        $body = (array) apply_filters( 'mshield_ai_request_body', $body, $provider, $url );

        $response = wp_remote_post( $url, [
            'headers' => $headers,
            'body'    => wp_json_encode( $body ),
            'timeout' => self::seconds_left(),
        ] );

        // No status to report: DNS, TLS or a connection that never opened.
        // api_error::retryable() reads that as 0, and a second provider is
        // worth trying.
        if( is_wp_error( $response ) ) return $response;

        $code = wp_remote_retrieve_response_code( $response );

        if( $code !== 200 ) {

            // Carry the provider's own message through on every arm, not just
            // the generic one. The 401 and 429 arms used to report the status
            // code alone, which is backwards: those two are the ones a merchant
            // can actually act on, and the body says which of the several keys
            // on this screen was rejected.
            $message = api_error::explain( self::provider_name( $provider ), $code, api_error::detail( $response ) );

            // The status travels with the error so review() can tell a
            // provider having a bad time from a request that was wrong.
            $data = [ 'status' => (int) $code ];

            if( $code === 401 || $code === 403 ) return new \WP_Error( 'mshield_ai_auth', $message, $data );
            if( $code === 429 )                  return new \WP_Error( 'mshield_ai_limit', $message, $data );

            return new \WP_Error( 'mshield_ai_http', $message, $data );

        }

        $decoded = json_decode( wp_remote_retrieve_body( $response ), true );

        if( ! is_array( $decoded ) ) {
            return new \WP_Error( 'mshield_ai_json', __( 'The AI provider replied, but the response could not be read as JSON.', 'mighty-shield' ) );
        }

        return $decoded;

    }

    /**
     * How long this request may take, in whole seconds.
     *
     * Inside a review it is whatever is left of the one deadline; outside one
     * it is the full timeout. Never below 1: wp_remote_post reads 0 as "no
     * timeout at all", which on a checkout request is the worst answer
     * available.
     *
     * @since   3.0.0
     *
     * @return  int
     */
    private static function seconds_left() {

        $full = (int) apply_filters( 'mshield_ai_timeout', self::TIMEOUT );

        if( self::$deadline === null ) return max( 1, $full );

        return max( 1, min( $full, self::$deadline - time() ) );

    }

    /**
     * What to call the configured provider in a message a merchant reads.
     *
     * @since   2.0.1
     *
     * @return  string
     */
    public static function provider_name( $provider = null ) {

        if( $provider === null ) $provider = settings::get( 'mshield_ai_provider' );

        switch( $provider ) {
            case 'openai':
                return 'OpenAI';
            case 'gemini':
                return 'Google Gemini';
            case 'anthropic':
            default:
                return 'Anthropic';
        }

    }

    /**
     * Record a degraded state and alert the admin, throttled to once a day.
     *
     * @since   1.8.0
     *
     * @param   string  $error
     */
    private static function degrade( $error ) {

        // Everything in here is a side effect on the shopper's own checkout
        // request: review() calls it inline, after the order exists and before
        // payment is taken. In 1.8.0 one line of it called a method that did
        // not exist, and because an Error is not an Exception WooCommerce
        // never caught it: the deliberate fail-open became a dead checkout at
        // exactly the moment it was meant to get out of the way. Fixing that
        // one call was not enough. Nothing here is worth a lost sale, so
        // nothing here is allowed to escape.
        try {

            db::log_event( ip_utils::get_client_ip(), 'system', 'degraded', 'AI review unavailable: ' . $error . ' — order allowed through unreviewed' );

            update_option( 'mshield_ai_degraded', [
                'time'    => time(),
                'message' => $error,
            ], false );

            self::alert_degraded( $error );

        } catch( \Throwable $e ) {

            // Recording or announcing the outage failed. The outage itself is
            // already handled -- review() fails open with or without this --
            // so there is nothing to do but let the sale through.
            //
            // alert_degraded() belongs INSIDE this try, not after it. Left
            // outside, its own get_transient(), alerts_enabled() and
            // set_transient() calls were unguarded, and an object cache that
            // throws on a dropped connection -- which is exactly the kind of
            // infrastructure trouble that takes an AI provider down in the
            // first place -- would have killed the checkout through the very
            // method written to stop that happening.

        }

    }

    /**
     * Email the admin about an AI outage, at most once a day.
     *
     * Split out of degrade() so the throttle can be set after the mail is
     * attempted rather than before it. Setting it first meant any failure in
     * between silenced outage alerts for 24 hours, which is how the 1.8.0
     * fatal went unnoticed: the crash happened on the first failure of the
     * day, the transient was already set, and the email was never sent on any
     * day at all.
     *
     * @since   3.0.0
     *
     * @param   string  $error
     */
    private static function alert_degraded( $error ) {

        if( get_transient( 'mshield_ai_alerted' ) ) return;

        // Checked before the throttle is touched, so a store with alerts
        // switched off does not burn a day's worth of it on nothing.
        if( ! settings::alerts_enabled() ) return;

        // Claimed BEFORE the send, released to a full day after it.
        //
        // Setting the day-long throttle only after wp_mail() returns sounds
        // safer and is worse. wp_mail() on a refused or black-holed SMTP host
        // does not throw, it blocks -- PHPMailer's own timeout is 300 seconds
        // -- so every checkout that started while the first was still in that
        // socket also passed the check above and also blocked. A store taking
        // a few orders a minute parked its entire checkout flow in SMTP. And
        // if PHP's max_execution_time fired in there it is an E_ERROR, not a
        // Throwable, so the catch below never ran and the next order repeated
        // the whole thing.
        //
        // The short claim closes both: a crash or a stall costs one attempt
        // per SEND_WINDOW rather than one per order, and a genuinely failed
        // send still retries the same day instead of going quiet for 24 hours.
        set_transient( 'mshield_ai_alerted', 1, self::SEND_WINDOW );

        try {

            self::mail_degraded( $error );

        } catch( \Throwable $e ) {

            self::log_quietly( 'The AI outage alert could not be sent: ' . $e->getMessage() );

        }

        set_transient( 'mshield_ai_alerted', 1, DAY_IN_SECONDS );

    }

    /**
     * Compose and send the outage email.
     *
     * @since   3.0.0
     *
     * @param   string  $error
     */
    private static function mail_degraded( $error ) {

        $message = sprintf(
            /* translators: %s: the error the AI provider returned. */
            __(
                "MightyShield's AI order review is currently unavailable.\n\n" .
                "Reason: %s\n\n" .
                "Orders are being allowed through WITHOUT AI review until this is resolved. Common causes:\n" .
                "- Invalid or expired API key\n" .
                "- Provider quota exhausted or rate limited\n" .
                "- Network/API outage\n\n" .
                "Check your credentials under MightyShield > AI Review.\n\n" .
                "This alert is sent at most once per day.",
                'mighty-shield'
            ),
            $error
        );

        // settings::notification_recipients(), not admin_page — the method was
        // moved there in 1.8.0 precisely because the checkout path needs it,
        // but this call site was left behind. Since admin_page is always loaded
        // the class_exists() guard was always true, so every provider failure
        // called a method that does not exist and fatalled the checkout —
        // turning the deliberate fail-open into a hard failure at exactly the
        // moment it was supposed to get out of the shopper's way.
        wp_mail( settings::notification_recipients(), __( '[MightyShield] AI order review is unavailable', 'mighty-shield' ), $message );

    }

    /**
     * Log something without ever being the reason a sale failed.
     *
     * Used from the catch blocks on the checkout path, where the database is
     * a plausible cause of whatever is being logged. Swallowing the second
     * failure is the entire point of the method.
     *
     * @since   3.0.0
     *
     * @param   string  $reason
     */
    private static function log_quietly( $reason ) {

        try {

            db::log_event( ip_utils::get_client_ip(), 'system', 'degraded', $reason );

        } catch( \Throwable $e ) {

            // Nothing left to try.

        }

    }

    /**
     * Forget the degraded state entirely.
     *
     * The throttle goes with the option, or the next real failure would record
     * the state without emailing anybody about it for up to a day.
     *
     * @since   2.0.1
     */
    public static function clear_degraded() {

        delete_option( 'mshield_ai_degraded' );
        delete_transient( 'mshield_ai_alerted' );

    }

    /**
     * Admin notice while the provider is degraded.
     *
     * @since   1.8.0
     */
    public static function render_degraded_notice() {

        if( ! current_user_can( 'manage_woocommerce' ) ) return;

        // Switched off is not degraded. Left on with a key cleared still is.
        if( settings::get( 'mshield_ai_enabled' ) !== 'yes' ) return;

        $degraded = get_option( 'mshield_ai_degraded' );
        if( empty( $degraded ) || empty( $degraded['time'] ) ) return;

        if( ( time() - (int) $degraded['time'] ) > DAY_IN_SECONDS ) return;

        printf(
            '<div class="notice notice-error"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
            esc_html__( 'MightyShield:', 'mighty-shield' ),
            esc_html( sprintf(
                /* translators: 1: how long ago the error happened, e.g. "12 mins". 2: API error message. */
                __( 'AI order review is unavailable and orders are NOT being reviewed. %1$s ago: %2$s', 'mighty-shield' ),
                human_time_diff( (int) $degraded['time'] ),
                $degraded['message']
            ) ),
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- value is escaped where it is built, or is a literal
            \MightyShield\Admin\admin_page::dismiss_url( 'mshield_ai_degraded' ),
            esc_html__( 'Dismiss', 'mighty-shield' )
        );

    }

}
