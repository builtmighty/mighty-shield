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
        // On by default. The Checkout block is WooCommerce's default, and with
        // this off a stock install got the firewall and none of the fraud
        // checks — the single biggest coverage gap in the plugin.
        'mshield_store_api_checks'          => 'yes',
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
        
        // Which surfaces the challenge guards. All gated on a provider being
        // configured at all, so this is opt-in twice over.
        //
        // Login ships OFF while the rest ship on. A misconfigured secret fails
        // open, but a BLOCKED SCRIPT means no token, and no token is a hard
        // fail -- on wp-login that is a lockout with no recovery but database
        // access. The other three surfaces have no such consequence.
        'mshield_captcha_on_login'          => 'no',
        'mshield_captcha_on_register'       => 'yes',
        'mshield_captcha_on_lostpassword'   => 'yes',
        'mshield_captcha_on_comments'       => 'yes',
        'mshield_log_retention_days'        => 30,

        // Email intelligence.
        'mshield_email_dns_check'           => 'yes',
        'mshield_email_list_enabled'        => 'yes',

        // Account, login and coupon behaviour, counted per hour per IP.
        'mshield_registration_threshold'    => 3,
        'mshield_login_failure_threshold'   => 10,
        'mshield_coupon_failure_threshold'  => 5,
        'mshield_new_account_minutes'       => 10,

        // Phase 2 — response ladder.
        // Enforcement is opt-in: an upgrading store keeps its existing
        // behavior and records risk levels until the merchant switches it on.
        'mshield_enforcement_mode'          => 'observe',
        // Trust thresholds, 1-100 (100 = totally trustworthy). Read as
        // "at or below this rating, at least this risk level".
        'mshield_level_rejected_threshold'  => 25,
        'mshield_level_high_threshold'      => 50,
        'mshield_level_elevated_threshold'  => 75,
        'mshield_level_low_threshold'       => 94,

        // What each level does, and whether it is worth an AI call. Defaults
        // reproduce the pre-1.9.1 behaviour exactly, so nothing changes for an
        // upgrading store until a dropdown is touched.
        'mshield_level_trusted_action'      => 'none',
        'mshield_level_low_action'          => 'flag',
        'mshield_level_elevated_action'     => 'verify_3ds',
        'mshield_level_high_action'         => 'hold_unpaid',
        'mshield_level_trusted_ai'          => 'no',
        'mshield_level_low_ai'              => 'no',
        'mshield_level_elevated_ai'         => 'yes',
        'mshield_level_high_ai'             => 'yes',
        'mshield_card_hold_on_mismatch'     => 'yes',
        'mshield_tarpit_enabled'            => 'yes',
        'mshield_tarpit_min_ms'             => 3000,
        'mshield_tarpit_max_ms'             => 8000,
        'mshield_refusal_note'              => '',

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
        // inline: review during checkout (needed for authorize-only holds).
        // async: review immediately after, off the shopper's request.
        // Hard ceiling on provider calls per day. 0 = no cap.
        'mshield_ai_daily_cap'              => 0,
        // Send the shape of the customer's details to the AI provider rather
        // than the details themselves. Off by default: it costs some accuracy,
        // and the choice belongs to the store.
        'mshield_ai_redact_pii'             => 'no',
        'mshield_ai_direction'              => 'lower',
        // Whether to also review Monitored orders. Off by default: that risk level
        // is most orders, so turning it on multiplies the API bill.
        'mshield_ai_velocity_orders'        => 3,
        'mshield_ai_velocity_days'          => 30,
        'mshield_ai_high_value_amount'      => '500.00',
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
     * @since   1.8.0
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
