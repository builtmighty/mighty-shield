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
     * Get client IP address.
     *
     * Checks proxy headers first, then falls back to REMOTE_ADDR.
     *
     * @since   1.0.0
     *
     * @return  string  Client IP address.
     */
    public static function get_client_ip() {

        $ip = '';

        if( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
            $ip  = trim( $ips[0] );
        } elseif( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
        } elseif( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }

        if( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return $ip;
        }

        return '0.0.0.0';

    }

    /**
     * Check if an IP is within a CIDR range.
     *
     * @since   1.0.0
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

        // Validate.
        if( ! filter_var( $subnet, FILTER_VALIDATE_IP ) ) return false;
        if( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return false;

        // Handle IPv6.
        if( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            return self::ipv6_in_cidr( $ip, $subnet, (int) $mask );
        }

        // IPv4 comparison.
        $ip_long     = ip2long( $ip );
        $subnet_long = ip2long( $subnet );
        $mask_long   = -1 << ( 32 - (int) $mask );

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
