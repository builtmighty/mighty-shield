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

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;

class ip_blocklist {

    /**
     * Option key.
     *
     * @since   1.2.0
     */
    private const OPTION_KEY = 'mshield_ip_blocklist';

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

        if( ! self::is_blocked( $ip ) ) return;

        db::log_event( $ip, 'classic_checkout', 'blocked', 'Blocklisted IP' );
        wc_add_notice( __( 'Your access has been restricted. Please contact support.', 'mighty-shield' ), 'error' );

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

        if( ! self::is_blocked( $ip ) ) return $result;

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

        $blocklist = self::get_blocklist();

        // Check for duplicate.
        foreach( $blocklist as $entry ) {
            if( $entry['ip'] === $ip ) return false;
        }

        $blocklist[] = [
            'ip'     => sanitize_text_field( $ip ),
            'label'  => sanitize_text_field( $label ),
            'reason' => sanitize_text_field( $reason ),
            'added'  => time(),
        ];

        return update_option( self::OPTION_KEY, $blocklist );

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

        $blocklist = self::get_blocklist();
        $filtered  = [];

        foreach( $blocklist as $entry ) {
            if( $entry['ip'] !== $ip ) {
                $filtered[] = $entry;
            }
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
