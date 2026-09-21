<?php
/**
 * IP Data.
 *
 * Network intelligence for an address: which country it is in, and whether it
 * belongs to a hosting provider rather than a person's home or phone.
 *
 * Everything here is answered from a database file on this server. Nothing is
 * sent anywhere, and nothing on the checkout path makes a network request --
 * which is the whole reason this file was rewritten.
 *
 * What it replaced, and why
 * -------------------------
 * Until 2.3.0 this asked ip-api.com over HTTPS on every uncached address. Two
 * things were wrong with that, and each one alone was fatal:
 *
 *   1. It never worked. TLS is a paid feature there, and the free endpoint
 *      answers an https:// request with 403 and
 *      {"status":"fail","message":"SSL unavailable for this endpoint"}.
 *      fetch() returned null on any non-200, so the three network signals
 *      could never fire on any install -- and because a failure was never
 *      cached and the single-IP path had no backoff, every checkout paid a
 *      blocking round-trip, up to five seconds, forever, to be told no.
 *
 *   2. Even fixed, it was not ours to use. ip-api's free tier is "strictly
 *      limited for a non-commercial purpose", and names fraud prevention for
 *      commercial transactions as a forbidden use. Every store running
 *      MightyShield is a commercial store.
 *
 * Where the data comes from now
 * -----------------------------
 * Country:  WooCommerce's own GeoLite2-Country database, via
 *           WC_Geolocation::geolocate_ip(). Most stores already have it; the
 *           merchant sets a free MaxMind licence key once under
 *           WooCommerce > Settings > Integrations.
 * Network:  GeoLite2-ASN, downloaded here on the daily cron using that same
 *           licence key, and read with the MaxMind reader WooCommerce already
 *           ships (MaxMind\Db\Reader, in its classmap autoloader). Nothing is
 *           vendored into this plugin.
 *
 * Proxy and VPN detection is gone. MaxMind's Anonymous IP database is a paid
 * product and no free source exists, so rather than ship a signal that cannot
 * fire -- which is exactly what the old code did for a year -- ip_proxy is
 * retired. See the note on the tri-state below: absent data is not evidence.
 *
 * @package MightyShield
 * @since   1.6.0
 */
namespace MightyShield\Includes;

defined( 'ABSPATH' ) || exit;

class ip_data {

    /**
     * MaxMind edition we fetch ourselves. WooCommerce downloads
     * GeoLite2-Country for its own purposes; it has no interest in ASN, so
     * this one is on us.
     *
     * @since   2.3.0
     */
    const ASN_EDITION = 'GeoLite2-ASN';

    /**
     * How often to re-download the ASN database. MaxMind republish weekly, so
     * anything shorter is bandwidth spent to learn nothing.
     *
     * @since   2.3.0
     */
    const ASN_TTL_DAYS = 7;

    /**
     * Substrings that identify a hosting provider, matched case-insensitively
     * against the ASN organisation name.
     *
     * This is a heuristic, and deliberately a conservative one. A false
     * positive here costs a real shopper 25 trust, so the list holds only
     * operators whose business is renting servers. Consumer ISPs that also
     * sell hosting are left out, as are CDNs -- a Cloudflare address arriving
     * as the CLIENT address means ip_utils could not see past the edge, which
     * is a configuration problem rather than evidence about the shopper.
     *
     * @since   2.3.0
     */
    const HOSTING_PATTERNS = [
        'amazon', 'aws', 'google cloud', 'microsoft azure', 'azure',
        'digitalocean', 'linode', 'akamai connected cloud', 'vultr', 'choopa',
        'ovh', 'hetzner', 'contabo', 'leaseweb', 'scaleway', 'online s.a.s',
        'colocrossing', 'm247', 'datacamp', 'psychz', 'quadranet', 'hostinger',
        'godaddy', 'bluehost', 'hostgator', 'dreamhost', 'rackspace',
        'oracle cloud', 'alibaba', 'tencent cloud', 'ionos', 'servers.com',
        'worldstream', 'i3d', 'nforce', 'serverius', 'fiberstate',
        'hivelocity', 'phoenixnap', 'zenlayer', 'gcore', 'stark industries',
    ];

    /**
     * Fetch and cache data for a single IP, returning the cached row.
     *
     * Returns the existing cached row without doing the work again when
     * present. The name is now a slight lie -- nothing is "fetched" from
     * anywhere -- but every caller reads db::get_ip_data() afterwards and the
     * signature is load-bearing at five call sites, so it stays.
     *
     * @since   1.6.0
     *
     * @param   string  $ip     IP address.
     * @return  array|null       Stored row (array) or null if it could not be resolved.
     */
    public static function get_or_fetch( $ip ) {

        $existing = db::get_ip_data( $ip );
        if( $existing ) return $existing;

        if( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return null;

        $data = self::resolve( $ip );
        if( $data === null ) return null;

        db::save_ip_data( $ip, $data );

        return db::get_ip_data( $ip );

    }

    /**
     * Resolve data for any IPs in the list that are not cached yet.
     *
     * Used to be one batched HTTP request for the dashboard. It is now a loop
     * of local database reads, so the batching, the 100-address ceiling and
     * the failure backoff that went with it are all gone.
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

        foreach( $missing as $ip ) {

            $data = self::resolve( $ip );
            if( $data === null ) continue;

            db::save_ip_data( $ip, $data );

        }

    }

    /**
     * Resolve one address against whatever databases are present.
     *
     * Returns a row even when both databases are missing. That is deliberate:
     * an all-unknown row still records that we looked, so the checkout path
     * stops re-resolving the same address on every request, and the tri-state
     * below keeps "we do not know" distinct from "no".
     *
     * @since   2.3.0
     *
     * @param   string  $ip     IP address.
     * @return  array|null       Normalized data, or null when the IP is unusable.
     */
    private static function resolve( $ip ) {

        if( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return null;

        $country = self::country( $ip );
        $asn     = self::asn( $ip );

        // 1 yes, 0 no, -1 not known. Only a positive is evidence; an unknown
        // must never read as innocence, which is why this is not a boolean.
        // With no ASN database there is nothing to say either way, so -1.
        $hosting = -1;

        if( $asn !== null && $asn['org'] !== '' ) {
            $hosting = self::looks_like_hosting( $asn['org'] ) ? 1 : 0;
        }

        return [
            'status'  => ( $country !== '' || $asn !== null ) ? 'success' : 'unknown',
            // GeoLite2-Country resolves to a country and no further, so these
            // two are permanently empty. They stay in the shape because the
            // log viewer and the order panel read them.
            'city'    => '',
            'region'  => '',
            'country' => $country,
            'org'     => $asn === null ? '' : $asn['org'],
            'asname'  => $asn === null ? '' : $asn['asname'],
            'hosting' => $hosting,
            // No free source for either. Retired rather than guessed.
            'proxy'   => -1,
            'mobile'  => -1,
        ];

    }

    /**
     * Country code for an address, from WooCommerce's GeoLite2-Country copy.
     *
     * The two false arguments matter more than they look. The third one is
     * $api_fallback, and leaving it at its default sends the address to a
     * third-party HTTP geolocation API when the database is absent -- which is
     * precisely the behaviour this rewrite exists to remove. The second is
     * $fallback, which WooCommerce itself documents as "can be slower"; this
     * runs on checkout.
     *
     * @since   2.3.0
     *
     * @param   string  $ip
     * @return  string  Uppercase ISO country code, or '' when unknown.
     */
    private static function country( $ip ) {

        if( ! class_exists( '\WC_Geolocation' ) ) return '';

        $geo = \WC_Geolocation::geolocate_ip( $ip, false, false );

        if( ! is_array( $geo ) || empty( $geo['country'] ) ) return '';

        return strtoupper( (string) $geo['country'] );

    }

    /**
     * Autonomous system for an address, from our GeoLite2-ASN copy.
     *
     * @since   2.3.0
     *
     * @param   string  $ip
     * @return  array|null  [ 'org' => string, 'asname' => string ], or null.
     */
    private static function asn( $ip ) {

        if( ! class_exists( '\MaxMind\Db\Reader' ) ) return null;

        $path = self::asn_database_path();
        if( ! file_exists( $path ) ) return null;

        $reader = null;

        try {

            $reader = new \MaxMind\Db\Reader( $path );
            $record = $reader->get( $ip );

            if( ! is_array( $record ) ) return null;

            $org = isset( $record['autonomous_system_organization'] )
                 ? (string) $record['autonomous_system_organization']
                 : '';

            $number = isset( $record['autonomous_system_number'] )
                    ? (int) $record['autonomous_system_number']
                    : 0;

            return [
                'org'    => $org,
                'asname' => $number ? 'AS' . $number : '',
            ];

        } catch( \Exception $e ) {

            // A corrupt or half-written database must cost the network signals
            // and nothing else. Same posture as every other external input
            // here: a failure loses evidence, never the sale.
            return null;

        } finally {

            if( $reader instanceof \MaxMind\Db\Reader ) $reader->close();

        }

    }

    /**
     * Whether an ASN organisation name reads as a hosting provider.
     *
     * @since   2.3.0
     *
     * @param   string  $org
     * @return  bool
     */
    private static function looks_like_hosting( $org ) {

        $org = strtolower( $org );

        foreach( self::HOSTING_PATTERNS as $needle ) {
            if( strpos( $org, $needle ) !== false ) return true;
        }

        /**
         * Additional hosting-provider substrings, matched against the
         * lowercased ASN organisation name.
         *
         * @since   2.3.0
         *
         * @param   string[]    $extra  Lowercase substrings. Default empty.
         * @param   string      $org    The organisation name being tested.
         */
        foreach( (array) apply_filters( 'mshield_hosting_patterns', [], $org ) as $needle ) {

            $needle = strtolower( (string) $needle );
            if( $needle !== '' && strpos( $org, $needle ) !== false ) return true;

        }

        return false;

    }

    /**
     * Where our ASN database lives.
     *
     * Alongside WooCommerce's own database, under the same randomised prefix
     * it uses, so the file is not guessable over HTTP on a misconfigured host.
     * Falls back to our own stored prefix when WooCommerce has none yet.
     *
     * @since   2.3.0
     *
     * @return  string
     */
    public static function asn_database_path() {

        $uploads = wp_upload_dir();

        $prefix = (string) self::wc_setting( 'database_prefix' );

        if( $prefix === '' ) {

            $prefix = (string) get_option( 'mshield_asn_prefix', '' );

            if( $prefix === '' ) {
                $prefix = wp_generate_password( 32, false, false );
                update_option( 'mshield_asn_prefix', $prefix, false );
            }

        }

        return trailingslashit( $uploads['basedir'] ) . 'woocommerce_uploads/'
             . $prefix . '-' . self::ASN_EDITION . '.mmdb';

    }

    /**
     * One setting out of WooCommerce's MaxMind integration.
     *
     * Read straight from the option rather than by constructing the
     * integration class, which is only loaded on the settings screen.
     *
     * @since   2.3.0
     *
     * @param   string  $key
     * @return  string
     */
    private static function wc_setting( $key ) {

        $settings = get_option( 'woocommerce_maxmind_geolocation_settings', [] );

        if( ! is_array( $settings ) || ! isset( $settings[ $key ] ) ) return '';

        return (string) $settings[ $key ];

    }

    /**
     * Whether the network signals can say anything at all right now.
     *
     * Used by the admin to explain a quiet signal rather than let a merchant
     * conclude their traffic is clean when nothing is actually being checked.
     *
     * @since   2.3.0
     *
     * @return  array   [ 'country' => bool, 'asn' => bool, 'key' => bool ]
     */
    public static function status() {

        $country_db = class_exists( '\WC_Integration_MaxMind_Database_Service' )
                   || class_exists( '\WC_Geolocation' );

        return [
            'key'     => self::wc_setting( 'license_key' ) !== '',
            'country' => $country_db && self::country( '8.8.8.8' ) !== '',
            'asn'     => file_exists( self::asn_database_path() ),
        ];

    }

    /**
     * Download the ASN database if it is missing or stale.
     *
     * Hooked to the daily cleanup cron. Cheap to call: it is one filemtime in
     * the common case.
     *
     * @since   2.3.0
     *
     * @return  true|\WP_Error|null  Null when there is nothing to do.
     */
    public static function maybe_update_asn_database() {

        $key = self::wc_setting( 'license_key' );
        if( $key === '' ) return null;

        $path = self::asn_database_path();

        if( file_exists( $path ) ) {

            $age = time() - (int) @filemtime( $path );
            if( $age < self::ASN_TTL_DAYS * DAY_IN_SECONDS ) return null;

        }

        return self::download_asn_database( $key );

    }

    /**
     * Fetch and install the ASN database.
     *
     * Modelled on WC_Integration_MaxMind_Database_Service::download_database(),
     * which is hardcoded to the Country edition and so cannot be reused.
     *
     * @since   2.3.0
     *
     * @param   string  $license_key
     * @return  true|\WP_Error
     */
    public static function download_asn_database( $license_key ) {

        require_once ABSPATH . 'wp-admin/includes/file.php';

        $url = add_query_arg(
            [
                'edition_id'  => self::ASN_EDITION,
                'license_key' => rawurlencode( $license_key ),
                'suffix'      => 'tar.gz',
            ],
            'https://download.maxmind.com/app/geoip_download'
        );

        $archive = download_url( esc_url_raw( $url ) );

        if( is_wp_error( $archive ) ) {

            $data = $archive->get_error_data();

            if( isset( $data['code'] ) && (int) $data['code'] === 401 ) {
                return new \WP_Error(
                    'mshield_maxmind_key',
                    __( 'The MaxMind licence key was refused. A newly created key can take a few minutes to become active.', 'mighty-shield' )
                );
            }

            return new \WP_Error(
                'mshield_maxmind_download',
                __( 'Could not download the MaxMind ASN database.', 'mighty-shield' )
            );

        }

        $extracted = null;

        try {

            $tar    = new \PharData( $archive );
            $folder = $tar->current()->getFilename();
            $inner  = trailingslashit( $folder ) . self::ASN_EDITION . '.mmdb';

            $tar->extractTo( dirname( $archive ), $inner, true );

            $extracted = trailingslashit( dirname( $archive ) ) . $inner;

        } catch( \Exception $e ) {

            return new \WP_Error( 'mshield_maxmind_archive', $e->getMessage() );

        } finally {

            @unlink( $archive );

        }

        if( ! $extracted || ! file_exists( $extracted ) ) {
            return new \WP_Error(
                'mshield_maxmind_archive',
                __( 'The MaxMind archive did not contain the expected database.', 'mighty-shield' )
            );
        }

        $target = self::asn_database_path();

        wp_mkdir_p( dirname( $target ) );

        // rename() across the temp and uploads directories can fail on hosts
        // where they sit on different filesystems, so fall back to a copy.
        if( ! @rename( $extracted, $target ) ) {

            if( ! @copy( $extracted, $target ) ) {
                @unlink( $extracted );
                return new \WP_Error(
                    'mshield_maxmind_install',
                    __( 'Could not write the MaxMind ASN database to the uploads directory.', 'mighty-shield' )
                );
            }

            @unlink( $extracted );

        }

        // Drop cached rows that were resolved without ASN data, so addresses
        // already seen get a second look now that there is something to say.
        db::forget_unresolved_ip_data();

        return true;

    }

}
