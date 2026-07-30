<?php
/**
 * Test Mode.
 *
 * Lets an administrator safely exercise the protection layers against their own
 * checkout without real fraudulent traffic. State is stored per-user, so
 * enabling it never affects real customers.
 *
 * @package MightyShield
 * @since   1.7.0
 */
namespace MightyShield\Includes;

class test_mode {

    /**
     * All layer keys that can be force-tripped.
     *
     * @since   1.7.0
     */
    const LAYERS = [
        'firewall', 'blocklist', 'rate_limit', 'velocity', 'failed_payment',
        'email_domain', 'order_amount', 'address', 'zip_state', 'smarty',
        'honeypot', 'timing', 'fingerprint', 'captcha',
    ];

    /**
     * Cached state for the current user this request.
     *
     * @since   1.7.0
     */
    private static $state = null;

    /**
     * Whether the current admin has test mode enabled.
     *
     * @since   1.7.0
     *
     * @return  bool
     */
    public static function active() {

        return (bool) self::state()['on'];

    }

    /**
     * Whether a given layer should be force-tripped for the current admin.
     *
     * @since   1.7.0
     *
     * @param   string  $layer  Layer key (see LAYERS).
     * @return  bool
     */
    public static function forcing( $layer ) {

        $state = self::state();
        return $state['on'] && in_array( $layer, $state['layers'], true );

    }

    /**
     * Whether test mode is in simulate (log-only) mode.
     *
     * @since   1.7.0
     *
     * @return  bool
     */
    public static function simulate() {

        return (bool) self::state()['simulate'];

    }

    /**
     * Resolve and cache the current user's test-mode state.
     *
     * @since   1.7.0
     *
     * @return  array   [ 'on' => bool, 'simulate' => bool, 'layers' => string[] ]
     */
    private static function state() {

        if( self::$state !== null ) return self::$state;

        self::$state = [ 'on' => false, 'simulate' => true, 'layers' => [] ];

        if( ! function_exists( 'get_current_user_id' ) ) return self::$state;

        $uid = (int) get_current_user_id();
        if( $uid <= 0 || ! current_user_can( 'manage_woocommerce' ) ) return self::$state;

        if( get_user_meta( $uid, 'mshield_test_mode', true ) !== 'yes' ) return self::$state;

        $layers = get_user_meta( $uid, 'mshield_test_layers', true );
        $layers = is_array( $layers ) ? array_values( array_intersect( $layers, self::LAYERS ) ) : [];

        self::$state = [
            'on'       => true,
            'simulate' => get_user_meta( $uid, 'mshield_test_simulate', true ) !== 'no',
            'layers'   => $layers,
        ];

        return self::$state;

    }

    /**
     * Decide whether a force-tripped layer should ACTUALLY trip right now.
     *
     * Returns true only when the layer is being forced AND test mode is in
     * enforce mode. In simulate mode it logs a "would trip" event and returns
     * false, so the admin sees the effect without blocking their checkout.
     *
     * @since   1.7.0
     *
     * @param   string  $layer  Layer key.
     * @param   string  $reason Human-readable reason for the log.
     * @return  bool
     */
    public static function should_trip( $layer, $reason ) {

        if( ! self::forcing( $layer ) ) return false;

        if( self::simulate() ) {
            self::log_simulated( $layer, $reason );
            return false;
        }

        return true;

    }

    /**
     * Log a simulated trip for a layer (used when simulate mode is on).
     *
     * @since   1.7.0
     *
     * @param   string  $layer  Layer key.
     * @param   string  $reason Human-readable reason.
     */
    public static function log_simulated( $layer, $reason ) {

        db::log_event( ip_utils::get_client_ip(), 'test_mode', 'test', '[' . $layer . '] ' . $reason );

    }

}
