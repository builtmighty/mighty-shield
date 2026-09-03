<?php
/*
Plugin Name: MightyShield
Plugin URI: https://builtmighty.com
Description: WooCommerce firewall for protecting against card spammer orders.
Version: 2.0.0
Author: Built Mighty
Author URI: https://builtmighty.com
Copyright: Built Mighty
Text Domain: mighty-shield
Requires Plugins: woocommerce
Copyright © 2026 Built Mighty. All Rights Reserved.
*/

/**
 * Namespace.
 *
 * @since   1.0.0
 */
namespace MightyShield;

/**
 * Disallow direct access.
 *
 * @since   1.0.0
 */
if( ! defined( 'WPINC' ) ) { die; }

/**
 * Constants.
 *
 * @since   1.0.0
 */
define( 'MSHIELD_VERSION', '2.0.0' );
define( 'MSHIELD_NAME', 'mighty-shield' );
define( 'MSHIELD_PATH', trailingslashit( plugin_dir_path( __FILE__ ) ) );
define( 'MSHIELD_URI', trailingslashit( plugin_dir_url( __FILE__ ) ) );
defined( 'MSHIELD_FILE' ) || define( 'MSHIELD_FILE', __FILE__ );

/**
 * Declare High-Performance Order Storage compatibility.
 *
 * The AI reviewer queries past orders via wc_get_orders(), which routes through
 * whichever data store is active — so the plugin works under HPOS and legacy
 * post storage alike. Declaring it stops WooCommerce listing MightyShield as
 * incompatible on the HPOS settings screen.
 *
 * @since   1.8.0
 */
add_action( 'before_woocommerce_init', function() {

    if( class_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil' ) ) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', MSHIELD_FILE, true );
    }

} );

/**
 * Plugin action links.
 *
 * @since   1.0.0
 */
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), '\MightyShield\plugin_action_links' );
function plugin_action_links( $links ) {
    $settings_link = '<a href="' . esc_url( admin_url( 'admin.php?page=mighty-shield' ) ) . '">' . __( 'Settings', 'mighty-shield' ) . '</a>';
    array_unshift( $links, $settings_link );
    return $links;
}

/**
 * On activation.
 *
 * @since   1.0.0
 */
register_activation_hook( __FILE__, '\MightyShield\activation' );
function activation() {

    // Create database tables and stamp the schema version, so a fresh install
    // does not re-run dbDelta on its first load.
    require_once MSHIELD_PATH . 'includes/class-db.php';
    \MightyShield\Includes\db::create_tables();
    update_option( 'mshield_db_version', \MightyShield\Includes\db::SCHEMA_VERSION, true );

    // Ensure whitelist option exists with autoload enabled.
    if( false === get_option( 'mshield_ip_whitelist' ) ) {
        add_option( 'mshield_ip_whitelist', [], '', 'yes' );
    }

    // Auto-detect and whitelist server IP.
    require_once MSHIELD_PATH . 'includes/class-ip-utils.php';
    require_once MSHIELD_PATH . 'firewall/class-ip-whitelist.php';
    \MightyShield\Firewall\ip_whitelist::auto_detect_server_ip();

    // Schedule cleanup cron.
    if( ! wp_next_scheduled( 'mshield_daily_cleanup' ) ) {
        wp_schedule_event( time(), 'daily', 'mshield_daily_cleanup' );
    }

}

/**
 * Run one-time migrations when the stored version is behind the code version.
 *
 * @since   1.3.0
 */
function maybe_upgrade() {

    $installed = get_option( 'mshield_version', '1.0.0' );
    if( version_compare( $installed, MSHIELD_VERSION, '>=' ) ) return;

    // 1.3.0: drop legacy DNS-resolved whitelist entries (Cloudflare edge IPs).
    if( class_exists( '\MightyShield\Firewall\ip_whitelist' ) ) {
        \MightyShield\Firewall\ip_whitelist::remove_dns_whitelist_entries();
    }

    // 1.4.0: stamp explicit types on legacy IP-only whitelist entries.
    if( version_compare( $installed, '1.4.0', '<' ) && class_exists( '\MightyShield\Firewall\ip_whitelist' ) ) {
        \MightyShield\Firewall\ip_whitelist::normalize_stored();
    }

    // 1.6.0: create the IP data cache table (dbDelta is idempotent).
    if( version_compare( $installed, '1.6.0', '<' ) && class_exists( '\MightyShield\Includes\db' ) ) {
        \MightyShield\Includes\db::create_tables();
    }

    // 1.8.0: purge leftovers from the removed test mode (shipped in 1.7.0).
    if( version_compare( $installed, '1.8.0', '<' ) ) {

        delete_metadata( 'user', 0, 'mshield_test_mode', '', true );
        delete_metadata( 'user', 0, 'mshield_test_layers', '', true );
        delete_metadata( 'user', 0, 'mshield_test_simulate', '', true );

        global $wpdb;
        $wpdb->delete( $wpdb->prefix . 'mshield_log', [ 'endpoint' => 'test_mode' ], [ '%s' ] );

    }

    // Schema changes are no longer handled here — db::maybe_upgrade_schema()
    // owns them, gated on its own counter so they land regardless of what the
    // plugin version already says.

    // 1.9.0: turn on the fraud checks for the block checkout.
    //
    // These shipped off, which meant a store using WooCommerce's default
    // checkout got the firewall and none of the fraud checks. Enabling it does
    // not introduce new policy — each layer still applies the block/flag action
    // the merchant already chose — it applies that choice to the checkout they
    // actually use. Recorded so an admin notice can say what changed, because a
    // security default that flips silently is its own kind of problem.
    if( version_compare( $installed, '1.9.0', '<' ) ) {

        if( get_option( 'mshield_store_api_checks' ) !== 'yes' ) {
            update_option( 'mshield_store_api_checks', 'yes' );
            update_option( 'mshield_store_api_enabled_notice', 1, false );
        }

    }

    update_option( 'mshield_version', MSHIELD_VERSION, false );

}

/**
 * On deactivation.
 *
 * @since   1.0.0
 */
register_deactivation_hook( __FILE__, '\MightyShield\deactivation' );
function deactivation() {

    // Clear scheduled cron events.
    wp_clear_scheduled_hook( 'mshield_daily_cleanup' );

}

/**
 * Load.
 *
 * @since   1.0.0
 */
add_action( 'plugins_loaded', '\MightyShield\load' );
function load() {

    // Check if WooCommerce is active.
    if( ! class_exists( 'WooCommerce' ) ) return;

    /**
     * Require core classes (always loaded when WooCommerce is active).
     *
     * @since   1.1.0
     */
    require_once MSHIELD_PATH . 'includes/class-ip-utils.php';
    require_once MSHIELD_PATH . 'includes/class-db.php';
    require_once MSHIELD_PATH . 'includes/class-ip-data.php';
    require_once MSHIELD_PATH . 'includes/class-settings.php';
    require_once MSHIELD_PATH . 'firewall/class-ip-whitelist.php';
    require_once MSHIELD_PATH . 'firewall/class-ip-blocklist.php';
    require_once MSHIELD_PATH . 'includes/class-exempt.php';
    require_once MSHIELD_PATH . 'includes/class-actions.php';
    require_once MSHIELD_PATH . 'includes/class-risk-levels.php';
    require_once MSHIELD_PATH . 'includes/class-signals.php';
    require_once MSHIELD_PATH . 'includes/class-scoring-profiles.php';
    require_once MSHIELD_PATH . 'includes/class-risk-context.php';
    require_once MSHIELD_PATH . 'includes/gateways/interface-gateway-adapter.php';
    require_once MSHIELD_PATH . 'includes/gateways/class-adapter-null.php';
    require_once MSHIELD_PATH . 'includes/gateways/class-adapter-stripe.php';
    require_once MSHIELD_PATH . 'includes/gateways/class-adapter-skyverge.php';
    require_once MSHIELD_PATH . 'includes/class-gateways.php';
    require_once MSHIELD_PATH . 'includes/class-response.php';
    require_once MSHIELD_PATH . 'includes/class-ai-detection.php';
    require_once MSHIELD_PATH . 'includes/class-entities.php';
    require_once MSHIELD_PATH . 'includes/class-ai-client.php';
    require_once MSHIELD_PATH . 'includes/class-ai-capture.php';
    require_once MSHIELD_PATH . 'includes/class-trust-badge.php';
    require_once MSHIELD_PATH . 'includes/class-rescore.php';
    require_once MSHIELD_PATH . 'admin/class-admin-page.php';
    require_once MSHIELD_PATH . 'admin/class-log-viewer.php';
    require_once MSHIELD_PATH . 'admin/class-order-panel.php';
    require_once MSHIELD_PATH . 'admin/class-order-column.php';
    require_once MSHIELD_PATH . 'admin/class-dashboard-widget.php';
    require_once MSHIELD_PATH . 'admin/class-fraud-review.php';

    // Converge the schema before anything reads or writes a table.
    \MightyShield\Includes\db::maybe_upgrade_schema();

    // Run version migrations if the plugin was just updated.
    maybe_upgrade();

    // Daily cleanup. Registered here rather than inside the Store API firewall,
    // which returns early when that layer is switched off — the cron event is
    // scheduled unconditionally at activation, so a store with Store API
    // blocking disabled was firing the event into no listener and letting the
    // log table grow without bound.
    add_action( 'mshield_daily_cleanup', [ '\MightyShield\Includes\db', 'cleanup' ] );

    // Always load admin page so settings are accessible.
    if( is_admin() ) {
        new \MightyShield\Admin\admin_page();
        new \MightyShield\Admin\log_viewer();
        new \MightyShield\Admin\order_panel();
        new \MightyShield\Admin\order_column();
        new \MightyShield\Admin\dashboard_widget();
        new \MightyShield\Admin\fraud_review();
        add_action( 'admin_notices', [ '\MightyShield\Admin\order_panel', 'render_notice' ] );

        // The panel calls outcomes::set_manual() when a reviewer rules on an
        // order, and outcomes lives with the protection classes below the
        // mshield_enabled guard. A merchant must still be able to record a
        // verdict on a store where protection is switched off.
        require_once MSHIELD_PATH . 'protection/class-outcomes.php';
    }

    // Check if plugin protections are enabled.
    if( get_option( 'mshield_enabled', 'yes' ) !== 'yes' ) return;

    /**
     * Require protection classes.
     *
     * @since   1.0.0
     */
    require_once MSHIELD_PATH . 'firewall/class-api-firewall.php';
    require_once MSHIELD_PATH . 'protection/class-rate-limiter.php';
    require_once MSHIELD_PATH . 'protection/class-velocity-detector.php';
    require_once MSHIELD_PATH . 'protection/class-failed-payment-tracker.php';
    require_once MSHIELD_PATH . 'protection/class-email-domain-blocker.php';
    require_once MSHIELD_PATH . 'protection/class-order-amount-validator.php';
    require_once MSHIELD_PATH . 'protection/class-address-validator.php';
    require_once MSHIELD_PATH . 'protection/class-zip-state-validator.php';
    require_once MSHIELD_PATH . 'protection/class-smarty-address-verifier.php';
    require_once MSHIELD_PATH . 'protection/class-honeypot.php';
    require_once MSHIELD_PATH . 'protection/class-checkout-timing.php';
    require_once MSHIELD_PATH . 'protection/class-device-fingerprint.php';
    require_once MSHIELD_PATH . 'protection/class-cookie-check.php';
    require_once MSHIELD_PATH . 'protection/class-captcha.php';
    require_once MSHIELD_PATH . 'protection/class-challenge.php';
    require_once MSHIELD_PATH . 'protection/class-store-api.php';
    require_once MSHIELD_PATH . 'protection/class-order-signals.php';
    require_once MSHIELD_PATH . 'protection/class-risk-recorder.php';
    require_once MSHIELD_PATH . 'protection/class-outcomes.php';
    require_once MSHIELD_PATH . 'protection/class-card-signals.php';
    require_once MSHIELD_PATH . 'protection/class-email-intel.php';
    require_once MSHIELD_PATH . 'protection/class-account-guard.php';
    require_once MSHIELD_PATH . 'protection/class-ai-reviewer.php';

    /**
     * Initiate.
     *
     * @since   1.0.0
     */
    require_once MSHIELD_PATH . 'init.php';
    \MightyShield\Plugin::get_instance();

}

/**
 * Plugin Updates.
 *
 * @since   1.0.0
 */
require_once MSHIELD_PATH . 'updates/plugin-update-checker.php';
use YahnisElsts\PluginUpdateChecker\v5\PucFactory;
$mshield_updates = PucFactory::buildUpdateChecker(
    'https://github.com/builtmighty/mighty-shield',
    __FILE__,
    'mighty-shield'
);
$mshield_updates->setBranch( 'main' );
$mshield_updates->getVcsApi()->enableReleaseAssets();
