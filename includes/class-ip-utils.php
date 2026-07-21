<?php
/**
 * IP Utilities.
 *
 * Shared IP detection and validation utility.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Includes;
class ip_utils {

    /**
     * Cloudflare published edge IP ranges (IPv4 + IPv6).
     *
     * Source: https://www.cloudflare.com/ips/ (retrieved 2026-07-21).
     * Used to decide whether the CF-Connecting-IP header can be trusted.
     * Override via the `mshield_trusted_proxies` filter if the origin sits
     * behind a different CDN/reverse proxy.
     *
     * @since   1.3.0
     */
    const CLOUDFLARE_RANGES = [
        // IPv4.
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22',
        // IPv6.
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    ];

    /**
     * Get client IP address.
     *
     * Resolution order (most trustworthy first):
     *   1. A custom header named by the MSHIELD_IP_HEADER constant, if defined
     *      (for non-Cloudflare proxy setups the site owner explicitly trusts).
     *   2. Cloudflare's CF-Connecting-IP header — but ONLY when the connection
     *      actually reached us from a Cloudflare edge IP (REMOTE_ADDR is inside
     *      a trusted-proxy range). This prevents header spoofing.
     *   3. REMOTE_ADDR (the raw TCP peer).
     *
     * The client-suppliable X-Forwarded-For / X-Real-IP headers are NEVER
     * trusted: behind Cloudflare the attacker controls the left-most XFF value
     * (Cloudflare appends, it does not replace), which previously let a spoofed
     * header defeat the blocklist / rate limiter and impersonate whitelisted IPs.
     *
     * @since   1.0.0
     * @since   1.3.0 Cloudflare-aware; stopped trusting X-Forwarded-For/X-Real-IP.
     *
     * @return  string  Client IP address.
     */
    public static function get_client_ip() {

        $remote = isset( $_SERVER['REMOTE_ADDR'] )
            ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
            : '';

        // 1. Explicit override header for bespoke proxy setups.
        if( defined( 'MSHIELD_IP_HEADER' ) && MSHIELD_IP_HEADER ) {
            $key = 'HTTP_' . strtoupper( str_replace( '-', '_', MSHIELD_IP_HEADER ) );
            if( ! empty( $_SERVER[ $key ] ) ) {
                $parts = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) );
                $candidate = trim( $parts[0] );
                if( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
                    return $candidate;
                }
            }
        }

        // 2. Cloudflare connecting IP, trusted only when we sit behind Cloudflare.
        if( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && self::is_trusted_proxy( $remote ) ) {
            $cf = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
            if( filter_var( $cf, FILTER_VALIDATE_IP ) ) {
                return $cf;
            }
        }

        // 3. Raw connection IP.
        if( filter_var( $remote, FILTER_VALIDATE_IP ) ) {
            return $remote;
        }

        return '0.0.0.0';

    }

    /**
     * Determine whether an IP belongs to a trusted upstream proxy (Cloudflare
     * by default). Only requests arriving from these edges may present a
     * trusted CF-Connecting-IP header.
     *
     * @since   1.3.0
     *
     * @param   string  $ip     Connection IP to test (usually REMOTE_ADDR).
     * @return  bool
     */
    public static function is_trusted_proxy( $ip ) {

        if( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return false;

        /**
         * Filter the list of trusted proxy IP ranges (CIDR or bare IPs).
         *
         * @since 1.3.0
         * @param array $ranges Trusted proxy ranges. Defaults to Cloudflare's.
         */
        $ranges = apply_filters( 'mshield_trusted_proxies', self::CLOUDFLARE_RANGES );

        foreach( (array) $ranges as $cidr ) {

            if( strpos( (string) $cidr, '/' ) === false ) {
                if( $cidr === $ip ) return true;
                continue;
            }

            if( self::ip_in_cidr( $ip, $cidr ) ) return true;

        }

        return false;

    }

    /**
     * Check if an IP is within a CIDR range.
     *
     * @since   1.0.0
     * @since   1.3.0 Address families must match; guard against out-of-range
     *                masks (previously a v4 IP vs a v6 CIDR threw an
     *                ArithmeticError and fatally errored checkout).
     *
     * @param   string  $ip     IP address to check.
     * @param   string  $cidr   CIDR notation (e.g., 192.168.1.0/24).
     * @return  bool
     */
    public static function ip_in_cidr( $ip, $cidr ) {

        // Split CIDR.
        $parts = explode( '/', $cidr );
        if( count( $parts ) !== 2 ) return false;

        list( $subnet, $mask ) = $parts;
        $mask = (int) $mask;

        // Validate.
        if( ! filter_var( $subnet, FILTER_VALIDATE_IP ) ) return false;
        if( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return false;

        $ip_is_v6     = (bool) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
        $subnet_is_v6 = (bool) filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );

        // A v4 address is never inside a v6 range and vice versa.
        if( $ip_is_v6 !== $subnet_is_v6 ) return false;

        // Handle IPv6.
        if( $ip_is_v6 ) {
            if( $mask < 0 || $mask > 128 ) return false;
            return self::ipv6_in_cidr( $ip, $subnet, $mask );
        }

        // IPv4 comparison.
        if( $mask < 0 || $mask > 32 ) return false;

        $ip_long     = ip2long( $ip );
        $subnet_long = ip2long( $subnet );
        if( $ip_long === false || $subnet_long === false ) return false;

        $mask_long = ( 0 === $mask ) ? 0 : ( -1 << ( 32 - $mask ) );

        return ( $ip_long & $mask_long ) === ( $subnet_long & $mask_long );

    }

    /**
     * Check if an IPv6 address is within a CIDR range.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     IPv6 address.
     * @param   string  $subnet IPv6 subnet.
     * @param   int     $mask   Subnet mask bits.
     * @return  bool
     */
    private static function ipv6_in_cidr( $ip, $subnet, $mask ) {

        $ip_bin     = inet_pton( $ip );
        $subnet_bin = inet_pton( $subnet );

        if( $ip_bin === false || $subnet_bin === false ) return false;

        // Build bitmask.
        $mask_bin = str_repeat( 'f', intdiv( $mask, 4 ) );
        $remainder = $mask % 4;
        if( $remainder > 0 ) {
            $mask_bin .= dechex( 0xF << ( 4 - $remainder ) & 0xF );
        }
        $mask_bin = str_pad( $mask_bin, 32, '0' );
        $mask_bin = pack( 'H*', $mask_bin );

        return ( $ip_bin & $mask_bin ) === ( $subnet_bin & $mask_bin );

    }

}
