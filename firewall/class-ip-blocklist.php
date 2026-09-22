<?php
/**
 * IP Blocklist.
 *
 * A persistent, admin-managed list of IP addresses / CIDR ranges that are
 * barred from checkout and the WooCommerce Store API. Unlike the transient
 * temp-blocks set by other checks, blocklist entries never expire until
 * removed. Whitelisted IPs always take precedence.
 *
 * @package MightyShield
 * @since   1.2.0
 */
namespace MightyShield\Firewall;

defined( 'ABSPATH' ) || exit;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\risk_context;
use MightyShield\Includes\response;

class ip_blocklist {

    /**
     * Option key.
     *
     * @since   1.2.0
     */
    private const OPTION_KEY = 'mshield_ip_blocklist';

    /**
     * What can be blocked.
     *
     * 'user' and 'role' are deliberately absent, though the allowlist has
     * them. Blocking a WordPress user is what WordPress's own user management
     * is for, and a role blocklist is a way for a store to lock its own staff
     * out by accident.
     *
     * @since   2.3.0
     */
    const TYPES = [ 'ip', 'email', 'phone', 'name', 'postcode', 'city', 'country' ];

    /**
     * Protected Store API route patterns.
     *
     * @since   1.2.0
     */
    private const PROTECTED_PATTERNS = [
        '#^/wc/store(/v\d+)?/cart#',
        '#^/wc/store(/v\d+)?/checkout#',
    ];

    /**
     * Construct.
     *
     * @since   1.2.0
     */
    public function __construct() {

        add_action( 'woocommerce_checkout_process', [ $this, 'check_checkout' ], 0 );
        add_filter( 'rest_pre_dispatch', [ $this, 'intercept_request' ], 1, 3 );

    }

    /**
     * Block a listed IP from classic checkout.
     *
     * @since   1.2.0
     */
    public function check_checkout() {

        $ip = ip_utils::get_client_ip();

        // is_blocked() already lets a whitelisted IP through, so what remains
        // here is a blocklisted address being used by a whitelisted user, role
        // or proven email.
        if( ! self::is_blocked( $ip ) ) return;

        // Emitted before the allowlist is consulted. "This address is on the
        // blocklist" is true whoever is using it, and the score is where that
        // belongs -- an allowlisted shopper arriving from a banned address is
        // exactly the thing a merchant reading the report wants to see.
        risk_context::add( 'ip_blocklisted', 'IP is on the blocklist' );

        if( \MightyShield\Includes\exempt::suppresses_action( isset( $_POST['billing_email'] ) ? sanitize_email( wp_unslash( $_POST['billing_email'] ) ) : '' ) ) return;

        db::log_event( $ip, 'classic_checkout', 'blocked', 'Blocklisted IP' );
        // Deliberately NOT gated on response::may_refuse(). Every other legacy
        // layer waits for enforce mode, because each of those is a heuristic
        // verdict the merchant may not agree with. A blocklist is not a verdict
        // -- it is the merchant, or a previous ban, naming an address. Observing
        // an instruction you have already given is not a thing anybody asked for.
        wc_add_notice( response::with_note( __( 'Your access has been restricted. Please contact support.', 'mighty-shield' ) ), 'error' );

    }

    /**
     * Block a listed IP from the Store API cart/checkout routes.
     *
     * @since   1.2.0
     *
     * @param   mixed            $result     Response to replace the requested version with.
     * @param   \WP_REST_Server  $server     Server instance.
     * @param   \WP_REST_Request $request    Request used to generate the response.
     * @return  mixed|\WP_Error
     */
    public function intercept_request( $result, $server, $request ) {

        $route = $request->get_route();

        $protected = false;
        foreach( self::PROTECTED_PATTERNS as $pattern ) {
            if( preg_match( $pattern, $route ) ) {
                $protected = true;
                break;
            }
        }

        if( ! $protected ) return $result;

        $ip = ip_utils::get_client_ip();

        // Whitelisted WP user or role bypasses the blocklist (whitelisted IPs
        // already pass via is_blocked()).
        $uid = get_current_user_id();
        if( $uid && ( ip_whitelist::is_user_whitelisted( $uid ) || ip_whitelist::is_role_whitelisted( $uid ) ) ) return $result;

        if( ! self::is_blocked( $ip ) ) return $result;

        risk_context::add( 'ip_blocklisted', 'IP is on the blocklist' );

        db::log_event( $ip, $route, 'blocked', 'Store API access denied — blocklisted IP' );

        return new \WP_Error(
            'mighty_shield_blocked',
            __( 'Access denied.', 'mighty-shield' ),
            [ 'status' => 403 ]
        );

    }

    /**
     * Check if an IP is blocklisted.
     *
     * Whitelisted IPs are never treated as blocked.
     *
     * @since   1.2.0
     *
     * @param   string  $ip     IP address to check.
     * @return  bool
     */
    public static function is_blocked( $ip ) {

        // Whitelist always wins.
        if( ip_whitelist::is_whitelisted( $ip ) ) return false;

        $blocklist = self::get_blocklist();

        foreach( $blocklist as $entry ) {

            $entry = self::normalize_entry( $entry );

            // Since 2.3.0 the list also holds emails, phones and addresses.
            // Those are matched against an ORDER by matches_fields(); here
            // there is only an address, and reading $entry['ip'] on one of
            // them would have been an undefined key on every checkout.
            if( $entry['type'] !== 'ip' || $entry['value'] === '' ) continue;

            // CIDR check.
            if( strpos( $entry['value'], '/' ) !== false ) {
                if( ip_utils::ip_in_cidr( $ip, $entry['value'] ) ) {
                    return true;
                }
                continue;
            }

            // Exact match.
            if( $entry['value'] === $ip ) {
                return true;
            }

        }

        return false;

    }

    /**
     * Add an IP to the blocklist.
     *
     * @since   1.2.0
     *
     * @param   string  $ip     IP address or CIDR.
     * @param   string  $label  Description label.
     * @param   string  $reason Reason the IP was blocked.
     * @return  bool    True if added, false if already exists.
     */
    public static function add_ip( $ip, $label = '', $reason = '' ) {

        return self::add_entry( 'ip', $ip, $label, $reason );

    }

    /**
     * Block anything the allowlist can allow.
     *
     * Same vocabulary as ip_whitelist::TYPES minus 'user' and 'role', which
     * are absent on purpose: blocking a logged-in user is what WordPress's own
     * user management is for, and blocking a role is a way to lock a store's
     * own staff out of it by accident.
     *
     * @since   2.3.0
     *
     * @param   string  $type   ip, email, phone, name, postcode, city, country.
     * @param   string  $value
     * @param   string  $label
     * @param   string  $reason
     * @return  bool    False when the type is unknown, the value is unusable,
     *                  or the entry is already there.
     */
    public static function add_entry( $type, $value, $label = '', $reason = '' ) {

        if( ! in_array( $type, self::TYPES, true ) ) return false;

        // ip keeps sanitize_text_field rather than going through the
        // allowlist's normalizer, because a CIDR has to survive intact.
        $value = $type === 'ip'
            ? sanitize_text_field( $value )
            : ip_whitelist::normalize_value( $type, $value );

        if( $value === '' ) return false;

        $blocklist = self::get_blocklist();

        foreach( $blocklist as $entry ) {
            $entry = self::normalize_entry( $entry );
            if( $entry['type'] === $type && $entry['value'] === $value ) return false;
        }

        $new = [
            'type'   => $type,
            'value'  => $value,
            'label'  => sanitize_text_field( $label ),
            'reason' => sanitize_text_field( $reason ),
            'added'  => time(),
        ];

        // Mirror into the legacy key so anything still reading $entry['ip']
        // — the admin table, and any row written before 2.3.0 — keeps working.
        if( $type === 'ip' ) $new['ip'] = $value;

        $blocklist[] = $new;

        return update_option( self::OPTION_KEY, $blocklist );

    }

    /**
     * Put a stored row into the typed shape.
     *
     * Every row written before 2.3.0 has an 'ip' key and no 'type'. Read
     * rather than migrated, the same way ip_whitelist handles its own legacy
     * rows: a migration that runs once can be interrupted, and this cannot.
     *
     * @since   2.3.0
     *
     * @param   mixed   $entry
     * @return  array
     */
    public static function normalize_entry( $entry ) {

        if( ! is_array( $entry ) ) {
            return [ 'type' => 'ip', 'value' => '', 'label' => '', 'reason' => '', 'added' => 0 ];
        }

        if( empty( $entry['type'] ) ) {
            $entry['type']  = 'ip';
            $entry['value'] = isset( $entry['ip'] ) ? $entry['ip'] : '';
        }

        $entry['value']  = isset( $entry['value'] ) ? (string) $entry['value'] : '';
        $entry['label']  = isset( $entry['label'] ) ? (string) $entry['label'] : '';
        $entry['reason'] = isset( $entry['reason'] ) ? (string) $entry['reason'] : '';
        $entry['added']  = isset( $entry['added'] ) ? (int) $entry['added'] : 0;

        return $entry;

    }

    /**
     * Whether any non-IP blocklist entry matches this order's details.
     *
     * Returns the reason rather than a boolean so the signal can say which
     * entry matched. The allowlist is NOT consulted here, unlike is_blocked():
     * this only emits a signal, and whether to act on it is settled once, at
     * the dispatch boundary, by exempt.
     *
     * @since   2.3.0
     *
     * @param   array   $fields     Normalised order fields from order_signals.
     * @return  string|null
     */
    public static function matches_fields( $fields ) {

        $want = [];

        foreach( ip_whitelist::FIELD_TYPES as $type => $key ) {

            if( ! isset( $fields[ $key ] ) ) continue;

            $value = ip_whitelist::normalize_value( $type, $fields[ $key ] );
            if( $value !== '' ) $want[ $type ] = $value;

        }

        // The email is not in FIELD_TYPES -- the allowlist reaches it through
        // its own method -- but a blocklist very much wants it.
        if( ! empty( $fields['email'] ) ) {
            $email = ip_whitelist::normalize_value( 'email', $fields['email'] );
            if( $email !== '' ) $want['email'] = $email;
        }

        if( empty( $want ) ) return null;

        foreach( self::get_blocklist() as $entry ) {

            $entry = self::normalize_entry( $entry );
            $type  = $entry['type'];

            if( $type === 'ip' || ! isset( $want[ $type ] ) ) continue;

            if( $entry['value'] !== $want[ $type ] ) continue;

            return $entry['reason'] !== ''
                ? sprintf( 'The %s on this order is on your blocklist: %s', $type, $entry['reason'] )
                : sprintf( 'The %s on this order is on your blocklist', $type );

        }

        return null;

    }

    /**
     * Remove an IP from the blocklist.
     *
     * @since   1.2.0
     *
     * @param   string  $ip     IP address to remove.
     * @return  bool
     */
    public static function remove_ip( $ip ) {

        return self::remove_entry( 'ip', $ip );

    }

    /**
     * Remove a typed entry.
     *
     * @since   2.3.0
     *
     * @param   string  $type
     * @param   string  $value
     * @return  bool
     */
    public static function remove_entry( $type, $value ) {

        $value = $type === 'ip'
            ? (string) $value
            : ip_whitelist::normalize_value( $type, $value );

        $filtered = [];

        foreach( self::get_blocklist() as $entry ) {

            $normal = self::normalize_entry( $entry );

            if( $normal['type'] === $type && $normal['value'] === $value ) continue;

            $filtered[] = $entry;

        }

        return update_option( self::OPTION_KEY, $filtered );

    }

    /**
     * Get the full blocklist.
     *
     * @since   1.2.0
     *
     * @return  array
     */
    public static function get_blocklist() {

        $blocklist = get_option( self::OPTION_KEY, [] );
        return is_array( $blocklist ) ? $blocklist : [];

    }

}
