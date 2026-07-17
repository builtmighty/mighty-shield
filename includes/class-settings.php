<?php
/**
 * Settings.
 *
 * Register default options and handle settings.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Includes;
class settings {

    /**
     * Default option values.
     *
     * @since   1.0.0
     */
    private static $defaults = [
        'mshield_enabled'                   => 'yes',
        'mshield_block_store_api'           => 'yes',
        'mshield_rate_checkout_limit'       => 5,
        'mshield_rate_checkout_window'      => 3600,
        'mshield_velocity_email_threshold'  => 3,
        'mshield_velocity_order_threshold'  => 5,
        'mshield_failed_payment_threshold'  => 5,
        'mshield_temp_block_duration'       => 86400,
        'mshield_blocked_email_domains'     => '',
        'mshield_min_order_amount'          => '1.00',
        'mshield_suspicious_amount_action'  => 'flag',
        'mshield_address_sensitivity'       => 'medium',
        'mshield_smarty_enabled'            => 'no',
        'mshield_smarty_auth_id'            => '',
        'mshield_smarty_auth_token'         => '',
        'mshield_smarty_action'             => 'flag',
        'mshield_zip_state_enabled'         => 'yes',
        'mshield_zip_state_action'          => 'block',
        'mshield_honeypot_enabled'          => 'yes',
        'mshield_honeypot_action'           => 'block',
        'mshield_timing_enabled'            => 'yes',
        'mshield_timing_min_seconds'        => 4,
        'mshield_timing_action'             => 'flag',
        'mshield_fingerprint_enabled'       => 'no',
        'mshield_fingerprint_action'        => 'block',
        'mshield_fingerprint_velocity_threshold' => 5,
        'mshield_captcha_provider'          => 'off',
        'mshield_captcha_site_key'          => '',
        'mshield_captcha_secret_key'        => '',
        'mshield_captcha_action'            => 'block',
        'mshield_log_retention_days'        => 30,
    ];

    /**
     * Get a setting value with default fallback.
     *
     * @since   1.0.0
     *
     * @param   string  $key    Option key.
     * @return  mixed
     */
    public static function get( $key ) {

        $default = isset( self::$defaults[ $key ] ) ? self::$defaults[ $key ] : '';
        return get_option( $key, $default );

    }

    /**
     * Get all default values.
     *
     * @since   1.0.0
     *
     * @return  array
     */
    public static function get_defaults() {

        return self::$defaults;

    }

}
