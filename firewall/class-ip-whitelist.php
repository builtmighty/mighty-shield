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

defined( 'ABSPATH' ) || exit;

use MightyShield\Includes\ip_utils;

class ip_whitelist {

    /**
     * Option key.
     *
     * @since   1.0.0
     */
    private const OPTION_KEY = 'mshield_ip_whitelist';

    /**
     * Every kind of thing that can be allowlisted.
     *
     * The first four are about the VISITOR and have been here since 1.4.0:
     * they are answerable from the request itself, and each has its own
     * dedicated is_*_whitelisted() method.
     *
     * The rest arrived in 3.0.0 and are about the ORDER. They cannot be
     * answered from a request alone -- there is no "current postcode" -- so
     * they are matched together by matches_fields() against the order in
     * hand, which is why they have no methods of their own.
     *
     * @since   3.0.0
     */
    const TYPES = [ 'ip', 'user', 'email', 'role', 'phone', 'name', 'postcode', 'city', 'country' ];

    /**
     * What an entry may be exempted from.
     *
     * One allowlist used to mean one verdict: allowlisting a role so the
     * warehouse could place orders without answering a bot challenge also
     * stopped their orders being held, scored against, or refused by the
     * firewall -- and a merchant had no way to say which they meant.
     *
     *   all        everything, and what every existing entry means.
     *   firewall   the IP blocklist and the API firewall.
     *   challenge  the bot challenge on checkout and the login forms.
     *   response   what the risk rating does to an order: flags, holds,
     *              refusals, 3-D Secure step-ups.
     *
     * An entry with no scope stored is read as 'all', so nothing that was
     * allowlisted before this existed changes behaviour, and no migration is
     * needed. That is the reason the default is the broad one rather than the
     * narrow one.
     *
     * @since   3.0.0
     */
    const SCOPES = [ 'all', 'firewall', 'challenge', 'response' ];

    /**
     * Whether an entry's scope covers the thing being asked about.
     *
     * @since   3.0.0
     *
     * @param   array   $entry
     * @param   string  $scope  One of SCOPES, or 'all' to match anything.
     * @return  bool
     */
    public static function in_scope( $entry, $scope = 'all' ) {

        $stored = isset( $entry['scope'] ) ? (string) $entry['scope'] : 'all';

        if( ! in_array( $stored, self::SCOPES, true ) ) $stored = 'all';

        // An entry scoped to everything answers every question, and a question
        // about everything is answered by any entry -- which is what a screen
        // listing exemptions, or an upgrade path calling these without a
        // scope, is asking.
        return $stored === 'all' || $scope === 'all' || $stored === $scope;

    }

    /**
     * The order-field types, and which normalised field each one reads.
     *
     * @since   3.0.0
     */
    const FIELD_TYPES = [
        'phone'    => 'phone',
        'name'     => 'name',
        'postcode' => 'postcode',
        'city'     => 'city',
        'country'  => 'country',
    ];

    /**
     * Put a value into the one shape this type is stored and compared in.
     *
     * Every read and every write goes through here, which is the point. The
     * add and remove paths each used to carry their own copy of this, so a
     * phone number added as "(212) 555-0147" and removed as "212 555 0147"
     * were two different strings and the remove silently did nothing.
     *
     * @since   3.0.0
     *
     * @param   string  $type
     * @param   mixed   $value
     * @return  string  '' when there is nothing usable.
     */
    public static function normalize_value( $type, $value ) {

        $value = trim( (string) $value );

        switch( $type ) {

            case 'email':
                return strtolower( trim( sanitize_email( $value ) ) );

            case 'user':
                return (string) (int) $value;

            case 'role':
                return sanitize_key( $value );

            case 'phone':
                // Digits only, then the last ten. A merchant allowlisting
                // their own trade customer should not have to know whether
                // that customer types a country code.
                $digits = preg_replace( '/[^0-9]/', '', $value );
                return strlen( $digits ) > 10 ? substr( $digits, -10 ) : $digits;

            case 'name':
                // Case and inner spacing only. Deliberately NOT stripping
                // punctuation: O'Brien and Obrien are different people to
                // everyone except a regex, and this list grants trust.
                return strtolower( preg_replace( '/\s+/', ' ', $value ) );

            case 'postcode':
                return strtoupper( preg_replace( '/[^A-Z0-9]/i', '', $value ) );

            case 'city':
                return strtolower( preg_replace( '/\s+/', ' ', $value ) );

            case 'country':
                $code = strtoupper( preg_replace( '/[^A-Z]/i', '', $value ) );
                return strlen( $code ) === 2 ? $code : '';

            default:
                return sanitize_text_field( $value );

        }

    }

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
    public static function is_whitelisted( $ip, $scope = 'all' ) {

        foreach( self::get_whitelist() as $entry ) {

            if( $entry['type'] !== 'ip' ) continue;
            if( ! self::in_scope( $entry, $scope ) ) continue;

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
     * Whether any order-field allowlist entry matches this order.
     *
     * Deliberately one method for five types rather than five methods. These
     * are all answered from the same order and read in the same breath, and
     * the alternative is five passes over the allowlist to ask five questions
     * about the same object.
     *
     * Tries the delivery address first and falls back to billing, the same
     * way order_signals does, because the goods are what matter. A postcode
     * allowlisted for a trade customer should match whichever box they put
     * it in.
     *
     * @since   3.0.0
     *
     * @param   \WC_Order   $order
     * @return  bool
     */
    public static function matches_order( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return false;

        $pick = function( $ship, $bill ) use ( $order ) {
            $v = trim( (string) $order->{$ship}() );
            return $v !== '' ? $v : trim( (string) $order->{$bill}() );
        };

        return self::matches_fields( [
            'phone'    => (string) $order->get_billing_phone(),
            'name'     => trim( $pick( 'get_shipping_first_name', 'get_billing_first_name' )
                              . ' '
                              . $pick( 'get_shipping_last_name', 'get_billing_last_name' ) ),
            'postcode' => $pick( 'get_shipping_postcode', 'get_billing_postcode' ),
            'city'     => $pick( 'get_shipping_city', 'get_billing_city' ),
            'country'  => $pick( 'get_shipping_country', 'get_billing_country' ),
        ] );

    }

    /**
     * Whether any order-field entry matches this set of values.
     *
     * Split from matches_order() so the checkout path, which has posted data
     * rather than an order, can ask the same question.
     *
     * @since   3.0.0
     *
     * @param   array   $fields     type => raw value.
     * @return  bool
     */
    public static function matches_fields( $fields, $scope = 'all' ) {

        // Normalise once, not once per allowlist row.
        $want = [];

        foreach( self::FIELD_TYPES as $type => $key ) {

            if( ! isset( $fields[ $key ] ) ) continue;

            $value = self::normalize_value( $type, $fields[ $key ] );
            if( $value !== '' ) $want[ $type ] = $value;

        }

        if( empty( $want ) ) return false;

        foreach( self::get_whitelist() as $entry ) {

            $type = $entry['type'] ?? '';

            if( ! isset( $want[ $type ] ) ) continue;
            if( ! self::in_scope( $entry, $scope ) ) continue;

            // Stored already normalised by add_entry(), so this is an exact
            // comparison of two values in the same shape.
            if( (string) $entry['value'] === $want[ $type ] ) return true;

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
    public static function is_user_whitelisted( $user_id, $scope = 'all' ) {

        $user_id = (int) $user_id;
        if( $user_id <= 0 ) return false;

        foreach( self::get_whitelist() as $entry ) {
            if( ! self::in_scope( $entry, $scope ) ) continue;
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
    public static function is_email_whitelisted( $email, $scope = 'all' ) {

        $email = strtolower( trim( (string) $email ) );
        if( $email === '' ) return false;

        foreach( self::get_whitelist() as $entry ) {
            if( ! self::in_scope( $entry, $scope ) ) continue;
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
    public static function is_role_whitelisted( $user_id, $scope = 'all' ) {

        $user_id = (int) $user_id;
        if( $user_id <= 0 ) return false;

        // Collect whitelisted role slugs.
        $roles = [];
        foreach( self::get_whitelist() as $entry ) {
            if( ! self::in_scope( $entry, $scope ) ) continue;
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
    public static function add_entry( $type, $value, $label = '', $system = false, $scope = 'all' ) {

        $type = in_array( $type, self::TYPES, true ) ? $type : '';
        if( $type === '' ) return false;

        $value = self::normalize_value( $type, $value );

        if( $value === '' || $value === '0' ) return false;

        $whitelist = self::get_whitelist();

        $scope = in_array( $scope, self::SCOPES, true ) ? $scope : 'all';

        // Same type and value: not a new entry, but the scope may have moved.
        //
        // Returning false outright meant the only way to narrow an existing
        // entry was to remove it and add it again -- and the admin screen
        // reported "added to allowlist" either way, so a merchant following
        // the form's own advice to narrow a scope was told it had worked when
        // nothing had changed.
        foreach( $whitelist as $i => $entry ) {

            if( $entry['type'] !== $type || $entry['value'] !== $value ) continue;

            if( ( $entry['scope'] ?? 'all' ) === $scope ) return false;

            $whitelist[ $i ]['scope'] = $scope;

            return update_option( self::OPTION_KEY, $whitelist );

        }

        $new = [
            'type'   => $type,
            'value'  => $value,
            'label'  => sanitize_text_field( $label ),
            'system' => (bool) $system,
            'scope'  => $scope,
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

        // Through the same normalizer that stored it, or a phone number typed
        // back with different punctuation would not match the row it created.
        $value = self::normalize_value( $type, $value );

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
            $server_ip = sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) );
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
