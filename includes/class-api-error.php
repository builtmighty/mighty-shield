<?php
/**
 * What a third-party API actually said when it refused us.
 *
 * Every provider this plugin talks to explains itself in the response body, and
 * the plugin used to throw that away and report the status code alone. "Smarty
 * API returned HTTP 401" sent an investigation after the merchant's quota and
 * their credentials, neither of which was the problem; the body would have said
 * so. The AI client learned this first and grew its own copy of these helpers,
 * with a comment noting the omission "cost a day of AI review being silently
 * off". Smarty then cost another day the same way.
 *
 * One implementation, because two would drift — the plugin already carries two
 * versions of the same degraded-notice sentence for exactly that reason.
 *
 * @package MightyShield
 * @since   2.0.1
 */
namespace MightyShield\Includes;

defined( 'ABSPATH' ) || exit;

class api_error {

    /**
     * How much of a provider's message is worth keeping.
     *
     * Long enough to carry a real explanation, short enough to sit in an admin
     * notice and an email without swamping either.
     *
     * @since   2.0.1
     */
    const MAX = 300;

    /**
     * Whether a second provider is worth trying after this failure.
     *
     * The distinction is between "this provider is having a bad time" and
     * "this request was wrong". A timeout, a 5xx, a rate limit or a dead key
     * are all facts about one provider, and another one may well answer. A
     * malformed request, a schema the provider rejected, or a model name that
     * does not exist will fail in exactly the same way twice, and trying again
     * only spends the shopper's time and a second provider's quota.
     *
     * A WP_Error from the HTTP layer -- DNS, TLS, a connection timeout --
     * never reached the provider at all, so it always qualifies.
     *
     * @since   3.0.0
     *
     * @param   int     $code   HTTP status, or 0 when the request never landed.
     * @return  bool
     */
    public static function retryable( $code ) {

        $code = (int) $code;

        if( $code === 0 )   return true;   // transport: DNS, TLS, timeout
        if( $code === 401 ) return true;   // this provider's key is bad
        if( $code === 403 ) return true;
        if( $code === 408 ) return true;
        if( $code === 429 ) return true;   // this provider's quota

        return $code >= 500;

    }

    /**
     * Pull the provider's own explanation out of a response.
     *
     * Handles the shapes the supported providers actually use: Anthropic and
     * OpenAI nest it under `error.message`, Gemini sometimes under
     * `error.status`, and Smarty returns a bare `errors` array. Anything
     * unrecognised falls back to the raw body, trimmed, which is still more
     * than a status code.
     *
     * @since   2.0.1
     *
     * @param   array|\WP_Error $response   A wp_remote_* response.
     * @return  string  The provider's message, or '' if it offered none.
     */
    public static function detail( $response ) {

        if( is_wp_error( $response ) ) return self::trim( $response->get_error_message() );

        $body = (string) wp_remote_retrieve_body( $response );
        if( $body === '' ) return '';

        $decoded = json_decode( $body, true );

        if( is_array( $decoded ) ) {

            $message = $decoded['error']['message']
                ?? $decoded['error']['status']
                ?? $decoded['message']
                ?? '';

            if( is_string( $message ) && $message !== '' ) return self::trim( $message );

            // Smarty: { "errors": [ { "message": "..." } ] } on some codes, and
            // a bare list of strings on others.
            if( ! empty( $decoded['errors'] ) && is_array( $decoded['errors'] ) ) {

                $parts = [];

                foreach( $decoded['errors'] as $err ) {
                    if( is_string( $err ) ) { $parts[] = $err; continue; }
                    if( is_array( $err ) && ! empty( $err['message'] ) ) $parts[] = (string) $err['message'];
                }

                if( ! empty( $parts ) ) return self::trim( implode( '; ', $parts ) );

            }

        }

        return self::trim( $body );

    }

    /**
     * Flatten a message to one line and cap it.
     *
     * Providers return HTML error pages as readily as JSON, and an unflattened
     * one turns an admin notice into a wall.
     *
     * @since   2.0.1
     *
     * @param   string  $text
     * @return  string
     */
    public static function trim( $text ) {

        $text = trim( preg_replace( '/\s+/', ' ', wp_strip_all_tags( (string) $text ) ) );

        return strlen( $text ) > self::MAX ? substr( $text, 0, self::MAX - 3 ) . '...' : $text;

    }

    /**
     * A sentence naming what a status code means for the merchant.
     *
     * The point is that the four codes worth telling apart are told apart. A
     * rejected key and an exhausted quota need completely different actions, and
     * both used to arrive as the same bare number.
     *
     * @since   2.0.1
     *
     * @param   string  $service    Human name of the service, e.g. 'Smarty'.
     * @param   int     $code       HTTP status.
     * @param   string  $detail     The provider's own message, if any.
     * @return  string
     */
    public static function explain( $service, $code, $detail = '' ) {

        switch( true ) {

            case ( $code === 401 || $code === 403 ):
                $line = sprintf(
                    /* translators: 1: service name, 2: HTTP status code. */
                    __( '%1$s rejected the credentials (HTTP %2$d). The key or token is wrong, or it is not being sent in a form %1$s accepts.', 'mighty-shield' ),
                    $service,
                    $code
                );
                break;

            case ( $code === 402 ):
                $line = sprintf(
                    /* translators: %s: service name. */
                    __( 'The %s subscription is out of lookups (HTTP 402). The credentials are fine; the account needs topping up.', 'mighty-shield' ),
                    $service
                );
                break;

            // A model that has been retired, or one this account was never
            // able to reach. Worth its own sentence because the providers move
            // faster than any bundled list can, and the reply from Google
            // reads "no longer available to new users, please update your
            // code" -- addressed to a developer, not to the person who has to
            // change a dropdown.
            case ( $code === 404 ):
                $line = sprintf(
                    /* translators: %s: service name. */
                    __( 'The model selected for %s is not available on this account (HTTP 404). Pick a current one under AI Review; the provider usually names its replacement below.', 'mighty-shield' ),
                    $service
                );
                break;

            case ( $code === 429 ):
                $line = sprintf(
                    /* translators: %s: service name. */
                    __( '%s is rate limiting this store (HTTP 429). Nothing is wrong with the configuration; the calls are arriving faster than the plan allows.', 'mighty-shield' ),
                    $service
                );
                break;

            // "Nothing to change here; it should clear on its own", until a
            // store spent ten days losing reviews to this and the sentence was
            // the reason nobody looked. The diagnosis was right and the advice
            // was wrong: the provider's capacity is not the merchant's to fix,
            // but whether an outage costs them a review is. Say what happened
            // and let the caller, which knows what recovery is configured, say
            // what to do about it.
            case ( $code >= 500 ):
                $line = sprintf(
                    /* translators: 1: service name, 2: HTTP status code. */
                    __( '%1$s is having trouble at their end (HTTP %2$d). This is their capacity, not your configuration, and it usually clears on its own.', 'mighty-shield' ),
                    $service,
                    $code
                );
                break;

            default:
                $line = sprintf(
                    /* translators: 1: service name, 2: HTTP status code. */
                    __( '%1$s refused the request (HTTP %2$d).', 'mighty-shield' ),
                    $service,
                    $code
                );

        }

        return $detail === '' ? $line : $line . ' ' . sprintf(
            /* translators: %s: the provider's own error message. */
            __( 'It said: %s', 'mighty-shield' ),
            $detail
        );

    }

}
