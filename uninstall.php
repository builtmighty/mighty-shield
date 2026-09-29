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
 * @since   3.0.0
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

    // The downloaded ASN database, before the option that names it goes.
    // WooCommerce is not loaded during an uninstall, so the path is rebuilt
    // here from the same two settings ip_data::asn_database_path() reads.
    $mshield_wc  = get_option( 'woocommerce_maxmind_geolocation_settings', [] );
    $mshield_pfx = is_array( $mshield_wc ) && ! empty( $mshield_wc['database_prefix'] )
        ? (string) $mshield_wc['database_prefix']
        : (string) get_option( 'mshield_asn_prefix', '' );

    if( $mshield_pfx !== '' ) {
        $mshield_uploads = wp_upload_dir();
        $mshield_asn     = trailingslashit( $mshield_uploads['basedir'] ) . 'woocommerce_uploads/' . $mshield_pfx . '-GeoLite2-ASN.mmdb';
        if( file_exists( $mshield_asn ) ) wp_delete_file( $mshield_asn );
    }

    // Options, matched by prefix rather than listed by name. The list this
    // replaces had to be updated by hand every time a setting was added, and
    // had already fallen about twenty entries behind -- including the entity
    // hashing salt, which is exactly the kind of thing that should not outlive
    // the plugin.
    //
    // Selected first and then removed through delete_option(), not with one
    // DELETE. A raw DELETE bypasses the options cache, and on a host with a
    // persistent object cache -- most managed WordPress hosting -- the cached
    // mshield_version and mshield_db_version outlived the tables they
    // described. The next install read them, concluded it was an upgrade with
    // nothing to migrate, and never created a single table.
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $mshield_names = (array) $wpdb->get_col(
        $wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
            $wpdb->esc_like( 'mshield_' ) . '%',
            '_transient_' . $wpdb->esc_like( 'mshield_' ) . '%',
            '_transient_timeout_' . $wpdb->esc_like( 'mshield_' ) . '%'
        )
    );

    foreach( $mshield_names as $mshield_name ) {

        if( strpos( $mshield_name, '_transient_timeout_' ) === 0 ) {
            continue; // delete_transient() removes the timeout with the value.
        }

        if( strpos( $mshield_name, '_transient_' ) === 0 ) {
            delete_transient( substr( $mshield_name, strlen( '_transient_' ) ) );
            continue;
        }

        delete_option( $mshield_name );

    }

    // Belt and braces for the cache: the two aggregate entries WordPress
    // serves option reads from, in case anything above was served stale.
    wp_cache_delete( 'alloptions', 'options' );
    wp_cache_delete( 'notoptions', 'options' );

    wp_clear_scheduled_hook( 'mshield_daily_cleanup' );
    wp_clear_scheduled_hook( 'mshield_backfill_batch' );

    // wp_unschedule_hook(), not wp_clear_scheduled_hook(): a queued review
    // carries its order id as an argument, and the clear_ function only
    // removes events whose args match the ones it is given -- so with no args
    // it would walk straight past every one of them.
    // The literal, not ai_async::HOOK. Nothing in this file is bootstrapped --
    // WordPress loads uninstall.php on its own, with the plugin unloaded --
    // so naming the class here would be a fatal on the one path that has to
    // work without it.
    wp_unschedule_hook( 'mshield_ai_review_order' );

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

// Reviews can be queued again as of 3.0.0: a store set to review just after
// checkout schedules one per order. Cancelled here so nothing fires at a
// plugin that no longer exists -- which also covers jobs left over from the
// background reviews this hook carried before they were retired in 1.9.2.
if( function_exists( 'as_unschedule_all_actions' ) ) {
    as_unschedule_all_actions( 'mshield_ai_review_order' );
    // A back-catalogue rating still in progress.
    as_unschedule_all_actions( 'mshield_backfill_batch' );
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
delete_metadata( 'user', 0, '_mshield_account_changed', '', true );

// Order meta and order notes are deliberately left alone. They are part of the
// order record — why an order was held, and what was decided about it — and
// deleting them would quietly rewrite the store's own history.
