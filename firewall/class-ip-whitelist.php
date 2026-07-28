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
     * Only IP-type entries are considered; user/email entries are matched via
     * their dedicated methods.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     IP address to check.
     * @return  bool
     */
    public static function is_whitelisted( $ip ) {

        foreach( self::get_whitelist() as $entry ) {

            if( $entry['type'] !== 'ip' ) continue;

            $value = $entry['value'];

            // CIDR check.
            if( strpos( $value, '/' ) !== false ) {
                if( ip_utils::ip_in_cidr( $ip, $value ) ) {
                    return true;
                }
                continue;
            }

            // Exact match.
            if( $value === $ip ) {
                return true;
            }

        }

        return false;

    }

    /**
     * Check if a WordPress user is whitelisted.
     *
     * @since   1.4.0
     *
     * @param   int  $user_id    WordPress user ID.
     * @return  bool
     */
    public static function is_user_whitelisted( $user_id ) {

        $user_id = (int) $user_id;
        if( $user_id <= 0 ) return false;

        foreach( self::get_whitelist() as $entry ) {
            if( $entry['type'] === 'user' && (int) $entry['value'] === $user_id ) {
                return true;
            }
        }

        return false;

    }

    /**
     * Check if an email address is whitelisted (case-insensitive).
     *
     * @since   1.4.0
     *
     * @param   string  $email  Email address.
     * @return  bool
     */
    public static function is_email_whitelisted( $email ) {

        $email = strtolower( trim( (string) $email ) );
        if( $email === '' ) return false;

        foreach( self::get_whitelist() as $entry ) {
            if( $entry['type'] === 'email' && $entry['value'] === $email ) {
                return true;
            }
        }

        return false;

    }

    /**
     * Check if a user's role is whitelisted.
     *
     * @since   1.4.0
     *
     * @param   int  $user_id    WordPress user ID.
     * @return  bool
     */
    public static function is_role_whitelisted( $user_id ) {

        $user_id = (int) $user_id;
        if( $user_id <= 0 ) return false;

        // Collect whitelisted role slugs.
        $roles = [];
        foreach( self::get_whitelist() as $entry ) {
            if( $entry['type'] === 'role' ) $roles[] = $entry['value'];
        }

        if( empty( $roles ) ) return false;

        $user = get_userdata( $user_id );
        if( ! $user ) return false;

        return (bool) array_intersect( (array) $user->roles, $roles );

    }

    /**
     * Add a typed entry to the whitelist.
     *
     * @since   1.4.0
     *
     * @param   string  $type   Entry type: 'ip', 'user', 'email', or 'role'.
     * @param   string  $value  Match value (IP/CIDR, user ID, email, or role slug).
     * @param   string  $label  Description label.
     * @param   bool    $system Whether this is a system-detected entry.
     * @return  bool    True if added, false if already exists or invalid type.
     */
    public static function add_entry( $type, $value, $label = '', $system = false ) {

        $type = in_array( $type, [ 'ip', 'user', 'email', 'role' ], true ) ? $type : '';
        if( $type === '' ) return false;

        // Normalize the value per type.
        if( $type === 'email' ) {
            $value = strtolower( trim( sanitize_email( $value ) ) );
        } elseif( $type === 'user' ) {
            $value = (string) (int) $value;
        } elseif( $type === 'role' ) {
            $value = sanitize_key( $value );
        } else {
            $value = sanitize_text_field( $value );
        }

        if( $value === '' || $value === '0' ) return false;

        $whitelist = self::get_whitelist();

        // Check for duplicate (same type + value).
        foreach( $whitelist as $entry ) {
            if( $entry['type'] === $type && $entry['value'] === $value ) return false;
        }

        $new = [
            'type'   => $type,
            'value'  => $value,
            'label'  => sanitize_text_field( $label ),
            'system' => (bool) $system,
            'added'  => time(),
        ];

        // Mirror IP entries into the legacy 'ip' key for back-compat.
        if( $type === 'ip' ) $new['ip'] = $value;

        $whitelist[] = $new;

        return update_option( self::OPTION_KEY, $whitelist );

    }

    /**
     * Remove a typed entry from the whitelist.
     *
     * @since   1.4.0
     *
     * @param   string  $type   Entry type.
     * @param   string  $value  Match value.
     * @return  bool
     */
    public static function remove_entry( $type, $value ) {

        if( $type === 'email' ) {
            $value = strtolower( trim( (string) $value ) );
        } elseif( $type === 'user' ) {
            $value = (string) (int) $value;
        } elseif( $type === 'role' ) {
            $value = sanitize_key( $value );
        }

        $filtered = [];

        foreach( self::get_whitelist() as $entry ) {
            if( $entry['type'] === $type && $entry['value'] === $value ) continue;
            $filtered[] = $entry;
        }

        return update_option( self::OPTION_KEY, $filtered );

    }

    /**
     * Add an IP to the whitelist.
     *
     * Back-compat wrapper around add_entry() for the 'ip' type.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     IP address or CIDR.
     * @param   string  $label  Description label.
     * @param   bool    $system Whether this is a system-detected IP.
     * @return  bool    True if added, false if already exists.
     */
    public static function add_ip( $ip, $label = '', $system = false ) {

        return self::add_entry( 'ip', $ip, $label, $system );

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

        return self::remove_entry( 'ip', $ip );

    }

    /**
     * Get the full whitelist, with every entry normalized to the typed shape.
     *
     * Legacy entries (pre-1.4.0) stored only an 'ip' key with no 'type'; they
     * are normalized to type 'ip' on read so old data keeps matching.
     *
     * @since   1.0.0
     *
     * @return  array
     */
    public static function get_whitelist() {

        $whitelist = get_option( self::OPTION_KEY, [] );
        if( ! is_array( $whitelist ) ) return [];

        return array_map( [ __CLASS__, 'normalize' ], $whitelist );

    }

    /**
     * Normalize a stored entry to the typed shape.
     *
     * @since   1.4.0
     *
     * @param   array  $entry   Raw stored entry.
     * @return  array
     */
    private static function normalize( $entry ) {

        if( ! is_array( $entry ) ) return [ 'type' => 'ip', 'value' => '', 'label' => '', 'system' => false, 'added' => 0 ];

        // Legacy entries have no 'type' and store the IP in 'ip'.
        if( empty( $entry['type'] ) ) {
            $entry['type']  = 'ip';
            $entry['value'] = isset( $entry['ip'] ) ? $entry['ip'] : '';
        }

        if( ! isset( $entry['value'] ) ) $entry['value'] = isset( $entry['ip'] ) ? $entry['ip'] : '';
        if( ! isset( $entry['label'] ) ) $entry['label'] = '';
        if( ! isset( $entry['system'] ) ) $entry['system'] = false;
        if( ! isset( $entry['added'] ) ) $entry['added'] = 0;

        return $entry;

    }

    /**
     * Persist all stored entries in the normalized typed shape.
     *
     * One-time upgrade tidy-up so legacy IP-only entries gain an explicit
     * 'type'. Matching already works without this via normalize() on read.
     *
     * @since   1.4.0
     */
    public static function normalize_stored() {

        update_option( self::OPTION_KEY, self::get_whitelist() );

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
