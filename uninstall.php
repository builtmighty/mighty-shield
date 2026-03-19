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

// Remove options.
$options = [
    'mshield_enabled',
    'mshield_block_store_api',
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
    'mshield_log_retention_days',
];

foreach( $options as $option ) {
    delete_option( $option );
}

// Clear scheduled cron events.
wp_clear_scheduled_hook( 'mshield_daily_cleanup' );

// Clean up transients (pattern-based).
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_mshield_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_mshield_%'" );
