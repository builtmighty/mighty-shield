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

        // NOTE: We deliberately do NOT resolve the site hostname via DNS.
        // Behind a CDN/proxy such as Cloudflare, that resolves to the CDN's
        // edge IP, which would wrongly whitelist the proxy and let any request
        // routed through it bypass the firewall. See remove_dns_whitelist_entries().

        // Method 2: Loopback addresses.
        self::add_ip( '127.0.0.1', 'Loopback IPv4', true );
        self::add_ip( '::1', 'Loopback IPv6', true );

    }

    /**
     * Remove whitelist entries created by the legacy DNS auto-detection.
     *
     * Prior versions resolved the site hostname and whitelisted the result,
     * which behind Cloudflare added an edge IP (e.g. 104.x). Those entries are
     * labelled "Server IP (DNS: ..." and are removed on upgrade.
     *
     * @since   1.3.0
     *
     * @return  bool    True if any entry was removed.
     */
    public static function remove_dns_whitelist_entries() {

        $whitelist = self::get_whitelist();
        $filtered  = [];
        $changed   = false;

        foreach( $whitelist as $entry ) {
            if( isset( $entry['label'] ) && strpos( $entry['label'], 'Server IP (DNS:' ) === 0 ) {
                $changed = true;
                continue;
            }
            $filtered[] = $entry;
        }

        if( $changed ) {
            update_option( self::OPTION_KEY, $filtered );
        }

        return $changed;

    }

}
