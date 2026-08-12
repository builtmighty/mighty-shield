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
        'mshield_firewall_mode'             => 'whitelist',
        'mshield_store_api_checks'          => 'no',
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
        'mshield_timing_missing_action'     => 'flag',
        'mshield_fingerprint_enabled'       => 'no',
        'mshield_fingerprint_action'        => 'block',
        'mshield_fingerprint_missing_action' => 'flag',
        'mshield_fingerprint_velocity_threshold' => 5,
        'mshield_captcha_provider'          => 'off',
        'mshield_captcha_site_key'          => '',
        'mshield_captcha_secret_key'        => '',
        'mshield_captcha_action'            => 'block',
        'mshield_log_retention_days'        => 30,

        // AI Detection.
        'mshield_ai_enabled'                => 'no',
        'mshield_ai_provider'               => 'anthropic',
        'mshield_ai_anthropic_key'          => '',
        'mshield_ai_anthropic_model'        => 'claude-haiku-4-5',
        'mshield_ai_openai_key'             => '',
        'mshield_ai_openai_org'             => '',
        'mshield_ai_openai_model'           => 'gpt-4o-mini',
        'mshield_ai_gemini_key'             => '',
        'mshield_ai_gemini_model'           => 'gemini-1.5-flash',
        'mshield_ai_method'                 => 'suspicious',
        'mshield_ai_sensitivity'            => 'medium',
        'mshield_ai_sig_address_velocity'   => 'yes',
        'mshield_ai_velocity_orders'        => 3,
        'mshield_ai_velocity_days'          => 30,
        'mshield_ai_sig_email_mismatch'     => 'yes',
        'mshield_ai_sig_high_value'         => 'yes',
        'mshield_ai_high_value_amount'      => '500.00',
        'mshield_ai_sig_ip_mismatch'        => 'yes',
        'mshield_ai_rating_threshold'       => 4,
        'mshield_ai_verdict_action'         => 'flag',
        'mshield_ai_notify_admin'           => 'yes',
        'mshield_ai_notify_emails'          => '',
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
     * Resolve who should receive MightyShield notifications.
     *
     * Falls back to the site admin when no list is configured. Lives here
     * rather than on the admin page because the checkout path needs it too.
     *
     * @since   1.9.0
     *
     * @return  array   Email addresses.
     */
    public static function notification_recipients() {

        $emails = [];

        foreach( explode( ',', (string) self::get( 'mshield_ai_notify_emails' ) ) as $email ) {

            $email = trim( $email );
            if( ! empty( $email ) && is_email( $email ) ) $emails[] = $email;

        }

        return empty( $emails ) ? [ get_option( 'admin_email' ) ] : $emails;

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
