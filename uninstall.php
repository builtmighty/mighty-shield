<?php
/**
 * Uninstall MightyShield.
 *
 * Removes all plugin data on uninstall.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) { die; }

global $wpdb;

// Remove custom tables.
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}mshield_log" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}mshield_rate_limits" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}mshield_ip_data" );

// Remove options.
$options = [
    'mshield_enabled',
    'mshield_block_store_api',
    'mshield_firewall_mode',
    'mshield_store_api_checks',
    'mshield_ip_whitelist',
    'mshield_rate_checkout_limit',
    'mshield_rate_checkout_window',
    'mshield_velocity_email_threshold',
    'mshield_velocity_order_threshold',
    'mshield_failed_payment_threshold',
    'mshield_temp_block_duration',
    'mshield_blocked_email_domains',
    'mshield_min_order_amount',
    'mshield_suspicious_amount_action',
    'mshield_address_sensitivity',
    'mshield_smarty_enabled',
    'mshield_smarty_auth_id',
    'mshield_smarty_auth_token',
    'mshield_smarty_action',
    'mshield_zip_state_enabled',
    'mshield_zip_state_action',
    'mshield_honeypot_enabled',
    'mshield_honeypot_action',
    'mshield_timing_enabled',
    'mshield_timing_min_seconds',
    'mshield_timing_action',
    'mshield_fingerprint_enabled',
    'mshield_fingerprint_action',
    'mshield_fingerprint_velocity_threshold',
    'mshield_captcha_provider',
    'mshield_captcha_site_key',
    'mshield_captcha_secret_key',
    'mshield_captcha_action',
    'mshield_ip_blocklist',
    'mshield_smarty_degraded',
    'mshield_captcha_degraded',
    'mshield_version',
    'mshield_log_retention_days',
];

// Per-user test-mode preferences.
delete_metadata( 'user', 0, 'mshield_test_mode', '', true );
delete_metadata( 'user', 0, 'mshield_test_layers', '', true );
delete_metadata( 'user', 0, 'mshield_test_simulate', '', true );
delete_metadata( 'user', 0, 'mshield_admin_theme', '', true );

foreach( $options as $option ) {
    delete_option( $option );
}

// Clear scheduled cron events.
wp_clear_scheduled_hook( 'mshield_daily_cleanup' );

// Clean up transients (pattern-based).
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_mshield_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_mshield_%'" );
