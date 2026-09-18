<?php
/**
 * Email intelligence.
 *
 * The built-in disposable list is ~49 hard-coded domains. There are thousands,
 * and new ones appear daily, so a static array of that size is close to
 * decorative against anyone paying attention. Rather than trying to enumerate
 * them, this asks questions a throwaway domain struggles to answer:
 *
 *   - Can the domain receive mail at all?
 *   - Is it on a maintained list, refreshed rather than frozen at release?
 *   - Is it a role address rather than a person?
 *
 * Everything here fails open. DNS is not always reachable from a web server,
 * and an order must never be judged on the basis that a lookup happened to
 * time out.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\exempt;
use MightyShield\Includes\risk_context;

class email_intel {

    /**
     * Where the maintained disposable-domain list is fetched from.
     *
     * A widely-mirrored, frequently-updated public list. Filterable so a store
     * can point at its own mirror, or at nothing.
     *
     * @since   1.9.0
     */
    const LIST_URL = 'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf';

    /**
     * Mailbox names that belong to a function rather than a person.
     *
     * Real customers occasionally order from these, so this is a weak signal
     * on its own and is weighted accordingly.
     *
     * @since   1.9.0
     */
    const ROLE_ADDRESSES = [
        'admin', 'administrator', 'billing', 'contact', 'help', 'info',
        'mail', 'marketing', 'no-reply', 'noreply', 'office', 'orders',
        'postmaster', 'sales', 'support', 'webmaster',
    ];

    /**
     * How long a domain's deliverability result is cached.
     *
     * @since   1.9.0
     */
    const DNS_CACHE = WEEK_IN_SECONDS;

    /**
     * Construct.
     *
     * @since   1.9.0
     */
    public function __construct() {

        // Runs late in validation, after the cheap checks, so a DNS lookup is
        // only ever paid for on an order that got that far.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'evaluate_classic' ], 25, 2 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'evaluate_store_api' ], 25, 2 );

        // Refresh the maintained list on the existing daily cron.
        add_action( 'mshield_daily_cleanup', [ __CLASS__, 'refresh_list' ] );

    }

    /**
     * Classic checkout entry point.
     *
     * @since   1.9.0
     *
     * @param   array       $data
     * @param   \WP_Error   $errors
     */
    public function evaluate_classic( $data, $errors ) {

        $email = $data['billing_email'] ?? '';

        if( exempt::is_exempt( $email ) ) return;

        self::assess( $email );

    }

    /**
     * Store API entry point.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order           $order
     * @param   \WP_REST_Request    $request
     */
    public function evaluate_store_api( $order, $request ) {

        if( exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        self::assess( $order->get_billing_email() );

    }

    /**
     * Emit the email signals for an address.
     *
     * @since   1.9.0
     *
     * @param   string  $email
     */
    public static function assess( $email ) {

        $email = strtolower( trim( (string) $email ) );

        $at = strrpos( $email, '@' );
        if( $at === false ) return;

        $local  = substr( $email, 0, $at );
        $domain = substr( $email, $at + 1 );

        if( $domain === '' ) return;

        if( \in_array( $local, self::ROLE_ADDRESSES, true ) ) {
            risk_context::add(
                'email_role',
                sprintf( 'Ordered from a role address (%s@) rather than a personal one', $local )
            );
        }

        if( self::is_listed( $domain ) ) {
            risk_context::add( 'email_disposable', sprintf( 'Disposable email domain: %s', $domain ) );
        }

        if( self::is_undeliverable( $domain ) ) {
            risk_context::add( 'email_no_mx', sprintf( 'Nothing can receive mail at %s', $domain ) );
        }

    }

    /**
     * Whether a domain appears on the maintained list.
     *
     * @since   1.9.0
     *
     * @param   string  $domain
     * @return  bool
     */
    private static function is_listed( $domain ) {

        $list = get_option( 'mshield_disposable_domains', [] );
        if( ! is_array( $list ) || empty( $list ) ) return false;

        // Stored as a hash map so this is a lookup, not a scan of tens of
        // thousands of entries on every checkout.
        return isset( $list[ $domain ] );

    }

    /**
     * Whether a domain can receive mail at all.
     *
     * Deliberately not just "has no MX record". Under RFC 5321 a domain with no
     * MX but a valid A/AAAA record still accepts mail at that host, and plenty
     * of small legitimate domains are set up exactly that way — treating them
     * as undeliverable would reject real customers. Only a domain with neither
     * is genuinely unable to receive anything.
     *
     * @since   1.9.0
     *
     * @param   string  $domain
     * @return  bool
     */
    public static function is_undeliverable( $domain ) {

        if( settings::get( 'mshield_email_dns_check' ) !== 'yes' ) return false;

        // Never resolve something that is not a hostname.
        if( ! preg_match( '/^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?\.[a-z]{2,}$/i', $domain ) ) return false;

        $key    = 'mshield_mx_' . md5( $domain );
        $cached = get_transient( $key );

        if( $cached !== false ) return $cached === 'no';

        if( ! function_exists( 'checkdnsrr' ) ) return false;

        $deliverable = checkdnsrr( $domain, 'MX' )
                    || checkdnsrr( $domain, 'A' )
                    || checkdnsrr( $domain, 'AAAA' );

        set_transient( $key, $deliverable ? 'yes' : 'no', self::DNS_CACHE );

        return ! $deliverable;

    }

    /**
     * Refresh the maintained disposable-domain list.
     *
     * Failure leaves the previous list in place. A list that is a week stale is
     * far better than no list, so a fetch error is never allowed to empty it.
     *
     * @since   1.9.0
     */
    public static function refresh_list() {

        if( settings::get( 'mshield_email_list_enabled' ) !== 'yes' ) return;

        $url = (string) apply_filters( 'mshield_disposable_list_url', self::LIST_URL );
        if( $url === '' ) return;

        $response = wp_remote_get( $url, [ 'timeout' => 15 ] );

        if( is_wp_error( $response ) || (int) wp_remote_retrieve_response_code( $response ) !== 200 ) {
            return;
        }

        $body = wp_remote_retrieve_body( $response );
        if( $body === '' ) return;

        $map = [];

        foreach( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {

            $line = strtolower( trim( $line ) );
            if( $line === '' || strpos( $line, '#' ) === 0 ) continue;

            // Only accept things shaped like a domain, so a fetch that lands on
            // an error page cannot poison the list with junk.
            if( ! preg_match( '/^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?\.[a-z]{2,}$/', $line ) ) continue;

            $map[ $line ] = 1;

        }

        // A list that suddenly collapses is a sign the source changed shape,
        // not that the world got safer. Keep what we have.
        if( count( $map ) < 100 ) return;

        update_option( 'mshield_disposable_domains', $map, false );
        update_option( 'mshield_disposable_updated', time(), false );

        db::log_event( '', 'system', 'flagged', sprintf( 'Disposable email list refreshed: %d domains', count( $map ) ) );

    }

    /**
     * How many domains the maintained list currently holds.
     *
     * @since   1.9.0
     *
     * @return  int
     */
    public static function list_size() {

        $list = get_option( 'mshield_disposable_domains', [] );

        return is_array( $list ) ? count( $list ) : 0;

    }

}
