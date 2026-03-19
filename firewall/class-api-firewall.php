<?php
/**
 * API Firewall.
 *
 * Blocks non-whitelisted IPs from accessing WooCommerce Store API
 * cart and checkout endpoints.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Firewall;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;

class api_firewall {

    /**
     * Protected route patterns.
     *
     * @since   1.0.0
     */
    private const PROTECTED_PATTERNS = [
        '#^/wc/store(/v\d+)?/cart#',
        '#^/wc/store(/v\d+)?/checkout#',
    ];

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Check if Store API blocking is enabled.
        if( settings::get( 'mshield_block_store_api' ) !== 'yes' ) return;

        // Hook into REST API dispatch at earliest priority.
        add_filter( 'rest_pre_dispatch', [ $this, 'intercept_request' ], 1, 3 );

        // Register daily cleanup cron.
        add_action( 'mshield_daily_cleanup', [ '\MightyShield\Includes\db', 'cleanup' ] );

    }

    /**
     * Intercept REST API requests.
     *
     * @since   1.0.0
     *
     * @param   mixed            $result     Response to replace the requested version with.
     * @param   \WP_REST_Server  $server     Server instance.
     * @param   \WP_REST_Request $request    Request used to generate the response.
     * @return  mixed|\WP_Error
     */
    public function intercept_request( $result, $server, $request ) {

        // Get the route.
        $route = $request->get_route();

        // Check if this is a protected route.
        if( ! $this->is_protected_route( $route ) ) {
            return $result;
        }

        // Get client IP.
        $ip = ip_utils::get_client_ip();

        // Check if whitelisted.
        if( ip_whitelist::is_whitelisted( $ip ) ) {
            return $result;
        }

        // Allow logged-in admins/shop managers.
        if( is_user_logged_in() && current_user_can( 'manage_woocommerce' ) ) {
            return $result;
        }

        // Block the request.
        db::log_event( $ip, $route, 'blocked', 'Store API access denied — IP not whitelisted' );

        return new \WP_Error(
            'mighty_shield_blocked',
            __( 'Access denied.', 'mighty-shield' ),
            [ 'status' => 403 ]
        );

    }

    /**
     * Check if a route matches protected patterns.
     *
     * @since   1.0.0
     *
     * @param   string  $route  REST API route.
     * @return  bool
     */
    private function is_protected_route( $route ) {

        foreach( self::PROTECTED_PATTERNS as $pattern ) {
            if( preg_match( $pattern, $route ) ) {
                return true;
            }
        }

        return false;

    }

}
