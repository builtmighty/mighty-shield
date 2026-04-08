<?php
/*
Plugin Name: MightyShield
Plugin URI: https://builtmighty.com
Description: WooCommerce firewall for protecting against card spammer orders.
Version: 1.1.2
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
define( 'MSHIELD_VERSION', '1.1.2' );
define( 'MSHIELD_NAME', 'mighty-shield' );
define( 'MSHIELD_PATH', trailingslashit( plugin_dir_path( __FILE__ ) ) );
define( 'MSHIELD_URI', trailingslashit( plugin_dir_url( __FILE__ ) ) );
defined( 'MSHIELD_FILE' ) || define( 'MSHIELD_FILE', __FILE__ );

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

    // Create database tables.
    require_once MSHIELD_PATH . 'includes/class-db.php';
    \MightyShield\Includes\db::create_tables();

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
    require_once MSHIELD_PATH . 'includes/class-settings.php';
    require_once MSHIELD_PATH . 'firewall/class-ip-whitelist.php';
    require_once MSHIELD_PATH . 'admin/class-admin-page.php';
    require_once MSHIELD_PATH . 'admin/class-log-viewer.php';

    // Always load admin page so settings are accessible.
    if( is_admin() ) {
        new \MightyShield\Admin\admin_page();
        new \MightyShield\Admin\log_viewer();
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
    require_once MSHIELD_PATH . 'protection/class-device-fingerprint.php';

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
