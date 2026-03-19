<?php
/**
 * IP Whitelist.
 *
 * Manages the IP whitelist for Store API access.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Firewall;

use MightyShield\Includes\ip_utils;

class ip_whitelist {

    /**
     * Option key.
     *
     * @since   1.0.0
     */
    private const OPTION_KEY = 'mshield_ip_whitelist';

    /**
     * Check if an IP is whitelisted.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     IP address to check.
     * @return  bool
     */
    public static function is_whitelisted( $ip ) {

        $whitelist = self::get_whitelist();

        foreach( $whitelist as $entry ) {

            // CIDR check.
            if( strpos( $entry['ip'], '/' ) !== false ) {
                if( ip_utils::ip_in_cidr( $ip, $entry['ip'] ) ) {
                    return true;
                }
            }

            // Exact match.
            if( $entry['ip'] === $ip ) {
                return true;
            }

        }

        return false;

    }

    /**
     * Add an IP to the whitelist.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     IP address or CIDR.
     * @param   string  $label  Description label.
     * @param   bool    $system Whether this is a system-detected IP.
     * @return  bool    True if added, false if already exists.
     */
    public static function add_ip( $ip, $label = '', $system = false ) {

        $whitelist = self::get_whitelist();

        // Check for duplicate.
        foreach( $whitelist as $entry ) {
            if( $entry['ip'] === $ip ) return false;
        }

        $whitelist[] = [
            'ip'     => sanitize_text_field( $ip ),
            'label'  => sanitize_text_field( $label ),
            'system' => (bool) $system,
            'added'  => time(),
        ];

        return update_option( self::OPTION_KEY, $whitelist );

    }

    /**
     * Remove an IP from the whitelist.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     IP address to remove.
     * @return  bool
     */
    public static function remove_ip( $ip ) {

        $whitelist = self::get_whitelist();
        $filtered  = [];

        foreach( $whitelist as $entry ) {
            if( $entry['ip'] !== $ip ) {
                $filtered[] = $entry;
            }
        }

        return update_option( self::OPTION_KEY, $filtered );

    }

    /**
     * Get the full whitelist.
     *
     * @since   1.0.0
     *
     * @return  array
     */
    public static function get_whitelist() {

        $whitelist = get_option( self::OPTION_KEY, [] );
        return is_array( $whitelist ) ? $whitelist : [];

    }

    /**
     * Auto-detect and whitelist server IP addresses.
     *
     * Called on plugin activation.
     *
     * @since   1.0.0
     */
    public static function auto_detect_server_ip() {

        // Method 1: SERVER_ADDR.
        if( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
            $server_ip = sanitize_text_field( $_SERVER['SERVER_ADDR'] );
            if( filter_var( $server_ip, FILTER_VALIDATE_IP ) ) {
                self::add_ip( $server_ip, 'Server IP (SERVER_ADDR)', true );
            }
        }

        // Method 2: Resolve site hostname via DNS.
        $host = wp_parse_url( site_url(), PHP_URL_HOST );
        if( $host ) {
            $resolved = gethostbyname( $host );
            if( $resolved !== $host && filter_var( $resolved, FILTER_VALIDATE_IP ) ) {
                self::add_ip( $resolved, 'Server IP (DNS: ' . $host . ')', true );
            }
        }

        // Method 3: Loopback addresses.
        self::add_ip( '127.0.0.1', 'Loopback IPv4', true );
        self::add_ip( '::1', 'Loopback IPv6', true );

    }

}
