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
//
// mshield_entities in particular holds hashed customer identities, so leaving
// it behind after an uninstall would mean retaining data the store no longer
// has any reason to keep.
foreach( [ 'mshield_log', 'mshield_rate_limits', 'mshield_ip_data',
           'mshield_risk', 'mshield_entities', 'mshield_entity_links' ] as $table ) {
    $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}{$table}" );
}

// Background reviews were retired in 1.9.2 -- reviews run during checkout, so
// nothing is queued. Still cancelled here: an install upgrading from an older
// version can have jobs sitting in Action Scheduler, and leaving them would
// have it firing at a plugin that no longer exists.
if( function_exists( 'as_unschedule_all_actions' ) ) {
    as_unschedule_all_actions( 'mshield_ai_review_order' );
}

// Remove options.
//
// Matched by prefix rather than listed by name. The list this replaces had to
// be updated by hand every time a setting was added, and had already fallen
// about twenty entries behind — including the entity hashing salt, which is
// exactly the kind of thing that should not outlive the plugin.
$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
        $wpdb->esc_like( 'mshield_' ) . '%'
    )
);

// Site options too, on multisite.
if( is_multisite() ) {
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s",
            $wpdb->esc_like( 'mshield_' ) . '%'
        )
    );
}

// Order meta and order notes are deliberately left alone. They are part of the
// order record — why an order was held, and what was decided about it — and
// deleting them would quietly rewrite the store's own history.

delete_metadata( 'user', 0, 'mshield_admin_theme', '', true );

// Clear scheduled cron events.
wp_clear_scheduled_hook( 'mshield_daily_cleanup' );

// Clean up transients (pattern-based).
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_mshield_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_mshield_%'" );
