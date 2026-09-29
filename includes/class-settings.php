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

defined( 'ABSPATH' ) || exit;

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
        'mshield_rate_checkout_limit'       => 20,
        'mshield_rate_checkout_window'      => 3600,
        'mshield_velocity_email_threshold'  => 10,
        // Orders per hour from one email identity, counting dots,
        // plus-tags and alias domains as the same inbox. Tighter than the
        // per-IP limits because it is a far more specific claim: one
        // person, not one network.
        'mshield_velocity_root_threshold'   => 5,
        'mshield_velocity_order_threshold'  => 15,
        'mshield_failed_payment_threshold'  => 10,
        'mshield_temp_block_duration'       => 3600,
        'mshield_blocked_email_domains'     => '',
        'mshield_min_order_amount'          => '1.00',
        // 0 disables, and that is the right default: a ceiling is a statement
        // about one store's normal order, and there is no figure that is
        // sensible for both a coffee shop and a jeweller.
        'mshield_max_order_amount'          => '0',
        // Both empty by default. MightyShield ships no opinion about any
        // country -- a blocked-country list belongs to the merchant's licence,
        // tax position and shipping contracts, not to a fraud plugin, and a
        // shipped "high risk" list is a guess about people that would be wrong
        // somewhere on every store.
        'mshield_blocked_countries'         => '',
        'mshield_high_risk_countries'       => '',
        'mshield_phone_voip_prefixes'       => '',
        // Empty, and it stays empty. A bundled list of "known" forwarder
        // addresses is a list of real warehouses, and one wrong entry
        // refuses every order a legitimate business ever places. The
        // merchant knows which addresses are costing them; MightyShield
        // does not, and guessing on their behalf is not a favour.
        'mshield_reshipper_addresses'       => '',
        'mshield_address_sensitivity'       => 'medium',
        'mshield_smarty_enabled'            => 'no',
        'mshield_smarty_auth_id'            => '',
        'mshield_smarty_auth_token'         => '',
        'mshield_captcha_min_score'         => '0.5',
        'mshield_smarty_auth_mode'          => 'basic',
        'mshield_zip_state_enabled'         => 'yes',
        'mshield_honeypot_enabled'          => 'yes',
        'mshield_timing_enabled'            => 'yes',
        'mshield_timing_min_seconds'        => 4,
        'mshield_fingerprint_enabled'       => 'no',
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
        // A year, not thirty days. This is the memory the scoring reads, and a
        // chargeback the store forgets after a month teaches it nothing.
        'mshield_entity_retention_days'     => 365,

        // Email intelligence.
        // Off by default. It is the one check that leaves the server during a
        // checkout -- up to three DNS lookups through the host's resolver, with
        // no timeout PHP can set -- and the readme promises none. A merchant
        // who wants it can switch it on knowing that.
        'mshield_email_dns_check'           => 'no',
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
        'mshield_tarpit_enabled'            => 'yes',
        'mshield_tarpit_min_ms'             => 3000,
        'mshield_tarpit_max_ms'             => 8000,
        'mshield_refusal_note'              => '',

        // AI Detection.
        'mshield_ai_enabled'                => 'no',
        'mshield_ai_provider'               => 'anthropic',
        // Empty means no fallback, which is the default: a second provider is
        // a second bill and a second set of terms, so nobody gets one by
        // accident. Only consulted when the first provider is the thing that
        // failed -- see api_error::retryable() -- and inside the same timeout,
        // so a fallback cannot make a slow checkout slower.
        'mshield_ai_fallback_provider'      => '',
        // inline: review during checkout, before payment. The only mode that
        //   can hold an authorize-only order before the card is charged.
        // async: review immediately after, off the shopper's request, so a
        //   slow provider cannot slow the checkout down. A hold then arrives
        //   through the post-payment route instead.
        'mshield_ai_mode'                   => 'inline',
        'mshield_ai_anthropic_key'          => '',
        'mshield_ai_anthropic_model'        => 'claude-sonnet-5-5',
        'mshield_ai_openai_key'             => '',
        'mshield_ai_openai_org'             => '',
        'mshield_ai_openai_model'           => 'gpt-6-luna',
        'mshield_ai_gemini_key'             => '',
        // Not 2.5: Google now limits that series to accounts that already
        // used it, so a new project taking the old default could not reach its
        // own model at all. The 1.5 series before it was retired outright in
        // September 2025 and did the same thing -- a 404 on every review.
        'mshield_ai_gemini_model'           => 'gemini-3.5-flash-lite',
        // Hard ceiling on provider calls per day. 0 = no cap.
        'mshield_ai_daily_cap'              => 0,
        // Send the shape of the customer's details to the AI provider rather
        // than the details themselves.
        //
        // ON by default since 3.0.0. It shipped off, on the reasoning that it
        // costs some accuracy and the choice belongs to the store. Both halves
        // of that are still true, but they are the wrong way round for a
        // default: the store is opting somebody ELSE's name, street, email,
        // phone and IP address into being sent to a third party, and a default
        // that quietly does that is not a choice anybody made.
        //
        // The accuracy it costs is small and mostly theoretical. The model is
        // shown which checks fired and what they cost, which is the evidence it
        // actually reasons from; a masked street still supports "billing and
        // shipping disagree", and a masked email still carries its length and
        // whether it contains digits.
        //
        // A store that has ever saved the AI Review tab holds an explicit
        // value and keeps it, because get() only falls back to this default
        // when the option is absent. A store that never opened the tab picks
        // the new default up on upgrade -- deliberately, and there is no
        // migration notice for it because the change only ever sends LESS
        // about a customer than it did yesterday.
        'mshield_ai_redact_pii'             => 'yes',
        'mshield_ai_direction'              => 'lower',
        // Whether to also review Monitored orders. Off by default: that risk level
        // is most orders, so turning it on multiplies the API bill.
        'mshield_ai_velocity_orders'        => 3,
        'mshield_ai_velocity_days'          => 30,
        // 0 means "learn it from this store's own completed orders", which
        // is what the Scoring tab's label and the readme have promised since
        // 3.0.0 -- but the field shipped as 500.00, so the learned figure was
        // computed nightly and never once read. 500.00 still stands in until
        // there are enough orders to learn from; see order_signals.
        'mshield_ai_high_value_amount'      => '0',
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
     * Write a setting.
     *
     * Paired with get() so a caller that stores a setting reads the same key
     * through the same door. Only for settings the plugin discovers for itself
     * -- the transport Test connection finds, say -- never for form input,
     * which goes through the registered sanitizers on the settings group.
     *
     * @since   2.0.1
     *
     * @param   string  $key
     * @param   mixed   $value
     * @return  bool
     */
    public static function update( $key, $value ) {

        return update_option( $key, $value );

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
    /**
     * Whether the merchant wants to hear from MightyShield by email at all.
     *
     * One switch for every alert -- a badly rated AI review, a service that
     * has stopped answering, a bot challenge refusing everybody, a wave of
     * declines -- which is what the setup wizard says it is. Until 3.0.0 only
     * the AI verdict email honoured it and the service alerts went to the
     * site administrator address regardless of what was set.
     *
     * @since   3.0.0
     *
     * @return  bool
     */
    public static function alerts_enabled() {

        return self::get( 'mshield_ai_notify_admin' ) === 'yes';

    }

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
