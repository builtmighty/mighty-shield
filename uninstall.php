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

/**
 * Everything MightyShield owns on one site.
 *
 * Tables, options, user meta and transients all carry the blog prefix or live
 * in that blog's options table, so on a network this has to run once per site.
 * It used to run once, full stop, which on a ten-site network left nine sites'
 * worth of tables behind -- including mshield_entities, which holds hashed
 * customer identities, and the salt that makes them readable.
 *
 * @since   2.3.0
 */
function mshield_uninstall_site() {

    global $wpdb;

    foreach( [ 'mshield_log', 'mshield_rate_limits', 'mshield_ip_data',
               'mshield_risk', 'mshield_entities', 'mshield_entity_links' ] as $table ) {
        // Table names are built from $wpdb->prefix and a literal; nothing here
        // is user input, and a table name cannot be a bound parameter.
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}{$table}" );
    }

    // Options, matched by prefix rather than listed by name. The list this
    // replaces had to be updated by hand every time a setting was added, and
    // had already fallen about twenty entries behind -- including the entity
    // hashing salt, which is exactly the kind of thing that should not outlive
    // the plugin.
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
            $wpdb->esc_like( 'mshield_' ) . '%'
        )
    );

    // Transients, which are options too but escape the prefix match above
    // because WordPress prepends its own.
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
            '_transient_' . $wpdb->esc_like( 'mshield_' ) . '%',
            '_transient_timeout_' . $wpdb->esc_like( 'mshield_' ) . '%'
        )
    );

    wp_clear_scheduled_hook( 'mshield_daily_cleanup' );

}

if( is_multisite() ) {

    // get_sites() over switch_to_blog() rather than a raw prefix sweep, so
    // $wpdb->prefix and $wpdb->options point at the right site each time and
    // the per-site cron events are cleared on the site that scheduled them.
    foreach( get_sites( [ 'fields' => 'ids', 'number' => 0 ] ) as $mshield_blog_id ) {

        switch_to_blog( $mshield_blog_id );
        mshield_uninstall_site();
        restore_current_blog();

    }

} else {

    mshield_uninstall_site();

}

// Background reviews were retired in 1.9.2 -- reviews run during checkout, so
// nothing is queued. Still cancelled here: an install upgrading from an older
// version can have jobs sitting in Action Scheduler, and leaving them would
// have it firing at a plugin that no longer exists.
if( function_exists( 'as_unschedule_all_actions' ) ) {
    as_unschedule_all_actions( 'mshield_ai_review_order' );
}

// Network options, which live once for the whole network rather than per site.
if( is_multisite() ) {
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s",
            $wpdb->esc_like( 'mshield_' ) . '%'
        )
    );
}

// User meta is network-wide in one table, so it is cleared once, out here,
// rather than once per site.
delete_metadata( 'user', 0, 'mshield_admin_theme', '', true );

// Order meta and order notes are deliberately left alone. They are part of the
// order record — why an order was held, and what was decided about it — and
// deleting them would quietly rewrite the store's own history.
