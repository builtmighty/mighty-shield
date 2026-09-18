<?php
/**
 * IP Data.
 *
 * Fetches and caches geolocation/ownership data for IP addresses via the free
 * ip-api.com service, over HTTPS — the query carries a customer's IP address and
 * the answer feeds a fraud decision, so neither should be readable or rewritable
 * by anything on the path. Results are cached in the mshield_ip_data table so each
 * IP is only ever fetched once (kept fast, and gentle on the free API).
 *
 * @package MightyShield
 * @since   1.6.0
 */
namespace MightyShield\Includes;

class ip_data {

    /**
     * Fields requested from ip-api for a single lookup.
     *
     * @since   1.6.0
     */
    private const FIELDS = 'status,city,region,countryCode,org,proxy,hosting,mobile,asname';

    /**
     * Fields for a batch lookup (query included so results can be mapped back).
     *
     * @since   1.6.0
     */
    private const BATCH_FIELDS = 'status,city,region,countryCode,org,proxy,hosting,mobile,asname,query';

    /**
     * Fetch and cache data for a single IP, returning the cached row.
     *
     * Returns the existing cached row without a network call when present.
     *
     * @since   1.6.0
     *
     * @param   string  $ip     IP address.
     * @return  array|null       Stored row (array) or null if it could not be fetched.
     */
    public static function get_or_fetch( $ip ) {

        $existing = db::get_ip_data( $ip );
        if( $existing ) return $existing;

        if( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return null;

        $data = self::fetch( $ip );
        if( $data === null ) return null;

        db::save_ip_data( $ip, $data );

        return db::get_ip_data( $ip );

    }

    /**
     * Fetch and cache data for any IPs in the list that are not cached yet.
     *
     * Uses one batched request so a full dashboard refresh costs a single API
     * call, and only when there is at least one uncached IP.
     *
     * @since   1.6.0
     *
     * @param   string[]    $ips    IP addresses.
     */
    public static function enrich( $ips ) {

        $ips = array_values( array_unique( array_filter( (array) $ips, function( $ip ) {
            return filter_var( $ip, FILTER_VALIDATE_IP );
        } ) ) );

        if( empty( $ips ) ) return;

        $have    = db::get_ip_data_map( $ips );
        $missing = array_values( array_diff( $ips, array_keys( $have ) ) );

        if( empty( $missing ) ) return;

        // Back off after a failed attempt so a site that cannot make outbound
        // requests does not pay the API timeout on every dashboard load.
        if( get_transient( 'mshield_ipdata_backoff' ) ) return;

        // Batch endpoint accepts up to 100 IPs per request.
        $missing = array_slice( $missing, 0, 100 );
        $results = self::fetch_batch( $missing );

        $saved = 0;
        foreach( $missing as $ip ) {
            if( isset( $results[ $ip ] ) ) {
                db::save_ip_data( $ip, $results[ $ip ] );
                $saved++;
            }
        }

        if( $saved === 0 ) {
            set_transient( 'mshield_ipdata_backoff', 1, 5 * MINUTE_IN_SECONDS );
        }

    }

    /**
     * Single-IP lookup against ip-api.com.
     *
     * @since   1.6.0
     *
     * @param   string  $ip     IP address.
     * @return  array|null       Normalized data, or null on transport failure.
     */
    private static function fetch( $ip ) {

        $url = 'https://ip-api.com/json/' . rawurlencode( $ip ) . '?fields=' . self::FIELDS;

        /**
         * How long to wait on the IP lookup, in seconds.
         *
         * This call sits on the checkout path, so the ceiling is a tradeoff
         * between the network signals and the sale. A miss costs the three
         * network signals and nothing else, so the shorter side is the safer
         * one on a busy store.
         *
         * @since   2.0.0
         *
         * @param   int     $timeout    Seconds. Default 5.
         * @param   string  $ip         The address being looked up.
         */
        $timeout = (int) apply_filters( 'mighty_shield_ip_lookup_timeout', 5, $ip );
        if( $timeout < 1 ) $timeout = 1;

        $response = wp_remote_get( $url, [ 'timeout' => $timeout ] );
        if( is_wp_error( $response ) ) return null;
        if( (int) wp_remote_retrieve_response_code( $response ) !== 200 ) return null;

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if( ! is_array( $body ) ) return null;

        return self::normalize( $body );

    }

    /**
     * Batch lookup against ip-api.com. Returns normalized data keyed by IP.
     *
     * @since   1.6.0
     *
     * @param   string[]    $ips    IP addresses (max 100).
     * @return  array       ip => normalized data (only for IPs the API returned).
     */
    private static function fetch_batch( $ips ) {

        $url = 'https://ip-api.com/batch?fields=' . self::BATCH_FIELDS;

        $response = wp_remote_post( $url, [
            'timeout' => 6,
            'headers' => [ 'Content-Type' => 'application/json' ],
            'body'    => wp_json_encode( array_values( $ips ) ),
        ] );

        if( is_wp_error( $response ) ) return [];
        if( (int) wp_remote_retrieve_response_code( $response ) !== 200 ) return [];

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if( ! is_array( $body ) ) return [];

        $out = [];
        foreach( $body as $entry ) {
            if( ! is_array( $entry ) || empty( $entry['query'] ) ) continue;
            $out[ $entry['query'] ] = self::normalize( $entry );
        }

        return $out;

    }

    /**
     * Normalize an ip-api response object to our stored shape.
     *
     * @since   1.6.0
     *
     * @param   array   $d      Decoded response.
     * @return  array
     */
    private static function normalize( $d ) {

        return [
            'status'  => isset( $d['status'] ) ? $d['status'] : '',
            'city'    => isset( $d['city'] ) ? $d['city'] : '',
            'region'  => isset( $d['region'] ) ? $d['region'] : '',
            'country' => isset( $d['countryCode'] ) ? $d['countryCode'] : '',
            'org'     => isset( $d['org'] ) ? $d['org'] : '',
            'asname'  => isset( $d['asname'] ) ? $d['asname'] : '',
            // Cast to a tri-state: 1 yes, 0 no, -1 not reported. A plan tier
            // that omits these fields must not read as "definitely not a
            // proxy" — absent data is not evidence of innocence.
            'proxy'   => isset( $d['proxy'] ) ? ( $d['proxy'] ? 1 : 0 ) : -1,
            'hosting' => isset( $d['hosting'] ) ? ( $d['hosting'] ? 1 : 0 ) : -1,
            'mobile'  => isset( $d['mobile'] ) ? ( $d['mobile'] ? 1 : 0 ) : -1,
        ];

    }

}
