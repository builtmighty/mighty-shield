<?php
/**
 * Plugin Name:       MightyShield
 * Plugin URI:        https://builtmighty.com
 * Description:       Scores every WooCommerce order against 44 fraud checks, optionally reviews it with an AI model, and then acts once — hold, challenge, refuse, or let through.
 * Version:           2.3.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Requires Plugins:  woocommerce
 * WC requires at least: 8.0
 * WC tested up to:   11.1
 * Author:            Built Mighty
 * Author URI:        https://builtmighty.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       mighty-shield
 * Domain Path:       /languages
 *
 * MightyShield is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 2 of the License, or (at your option)
 * any later version.
 *
 * MightyShield is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * @package MightyShield
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
define( 'MSHIELD_VERSION', '2.3.0' );
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

        // Cart and Checkout blocks. The work behind this has been done since
        // 1.8.0 -- protection/class-store-api.php runs every check on the Store
        // API path, the collector rides along as extension data, and
        // risk_recorder refuses through a RouteException -- but the declaration
        // itself was never made, so WooCommerce listed MightyShield as
        // incompatible on the Cart & Checkout Blocks screen. A merchant reading
        // that screen would reasonably have concluded the block checkout was
        // unprotected, which was the opposite of true.
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'cart_checkout_blocks', MSHIELD_FILE, true );

    }

} );

/**
 * Plugin action links.
 *
 * Settings, then Onboarding, then whatever WordPress itself put there
 * (Deactivate, and Delete on an inactive plugin). array_unshift prepends its
 * arguments in the order given, so the two arrive the right way round in front
 * of core's own.
 *
 * @since   1.0.0
 */
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), '\MightyShield\plugin_action_links' );
function plugin_action_links( $links ) {

    $ours = [
        '<a href="' . esc_url( admin_url( 'admin.php?page=mighty-shield' ) ) . '">' . esc_html__( 'Settings', 'mighty-shield' ) . '</a>',
    ];

    // Only when the wizard is really there. This filter runs at top level, but
    // the wizard class is required inside load(), which returns early without
    // WooCommerce -- and its screen is registered in the same place. Offering a
    // link to a page that would answer "you are not allowed to access this"
    // helps nobody, and referencing the class unguarded would be a fatal error
    // on the one screen a merchant uses to fix a broken plugin.
    if( class_exists( '\MightyShield\Admin\setup_wizard' ) ) {

        $ours[] = '<a href="' . esc_url( \MightyShield\Admin\setup_wizard::url() ) . '">'
                . esc_html__( 'Onboarding', 'mighty-shield' ) . '</a>';

    }

    array_unshift( $links, ...$ours );

    return $links;

}

/**
 * A cache-busting version for one of our own asset files.
 *
 * The plugin version is the wrong answer for this. It only moves on a release,
 * so any change to a script between releases -- a hotfix, a patched file pushed
 * to a site, an edit during development -- ships to every returning visitor
 * still holding the old file under the identical ?ver=, and they keep running
 * the old one until something unrelated bumps the version.
 *
 * That is not hypothetical: it is how a fix for the My Account sign-in
 * challenge appeared to do nothing at all. The server had been corrected and
 * the browser was still executing the file from before it.
 *
 * Falls back to the plugin version when the file cannot be stat'd, so an
 * opcache-only or read-restricted host still gets something stable.
 *
 * @since   2.0.2
 *
 * @param   string  $relative   Path under the plugin root, e.g. 'assets/js/x.js'.
 * @return  string
 */
function asset_version( $relative ) {

    $stamp = @filemtime( MSHIELD_PATH . $relative );

    return $stamp ? (string) $stamp : MSHIELD_VERSION;

}

/**
 * On activation.
 *
 * @since   1.0.0
 */
register_activation_hook( __FILE__, '\MightyShield\activation' );
function activation() {

    // Has this store ever run MightyShield? Answered BEFORE anything below
    // writes, because everything below writes one of these three.
    //
    // Activation does not fire on a plugin update, so an upgrading store never
    // reaches here at all. What this catches is the other path: deactivate,
    // drop in new files, reactivate. That store has settings and history and
    // must not be handed a first-run wizard, nor have its version stamped
    // forward over migrations it still needs.
    $prior = ( false !== get_option( 'mshield_version', false ) )
          || ( false !== get_option( 'mshield_db_version', false ) )
          || ( false !== get_option( 'mshield_ip_whitelist', false ) );

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

    if( $prior ) return;

    // A fresh install has no history to migrate, so stamp it current. Without
    // this maybe_upgrade() reads the '1.0.0' fallback and runs every branch back
    // to 1.3.0 on a store that has existed for ten seconds -- and the 1.9.0 one
    // then tells that merchant a default "changed on upgrade", which is a
    // migration story about a plugin they have only just installed. Same
    // reasoning as the schema stamp above, which already does this.
    //
    // Conditional on purpose: stamping unconditionally would let a store on old
    // data skip the migrations it genuinely needs.
    add_option( 'mshield_version', MSHIELD_VERSION, '', 'no' );

    // The setup wizard's entire state. Absent on every store that predates it,
    // which is what makes an upgrade structurally unable to see the wizard.
    add_option( 'mshield_onboarding', 'pending', '', 'yes' );

    // Arm the one-shot redirect into the wizard. Not for WP-CLI: a deploy script
    // running `wp plugin activate` must not ambush whoever next opens wp-admin.
    if( ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! is_network_admin() ) {
        add_option( 'mshield_activation_redirect', 1, '', 'no' );
    }

}

/**
 * Send a merchant who has just installed MightyShield to the setup wizard.
 *
 * Registered at top level rather than inside load(), which returns early without
 * WooCommerce -- this still needs to run then, if only to decide not to.
 *
 * @since   2.0.2
 */
add_action( 'admin_init', '\MightyShield\maybe_redirect_to_setup' );
function maybe_redirect_to_setup() {

    if( ! get_option( 'mshield_activation_redirect' ) ) return;

    // Everything before the delete is a reason this request is not the one that
    // should consume the flag.
    if( wp_doing_ajax() || wp_doing_cron() || is_network_admin() ) return;
    if( defined( 'WP_CLI' ) && WP_CLI ) return;

    // Capability first: if a subscriber happens to load wp-admin before the
    // administrator does, burning the flag here means the administrator never
    // sees the wizard at all.
    if( ! current_user_can( 'manage_woocommerce' ) ) return;

    // From this line on, every exit is terminal. A redirect that can fail
    // without clearing its own flag is a redirect loop.
    delete_option( 'mshield_activation_redirect' );

    // Bulk activation: WordPress appends activate-multi to the plugins.php
    // redirect. Hijacking that would drag somebody out of a batch of updates.
    // The flag is spent regardless, so they are not ambushed a page later; the
    // wizard stays reachable from the notice and the plugin action link.
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read to decide what to display, not to act on
    if( isset( $_GET['activate-multi'] ) ) return;

    // The wizard screen is registered inside load(), which needs WooCommerce.
    // Redirecting without it lands on "you are not allowed to access this page".
    if( ! class_exists( 'WooCommerce' ) ) return;

    if( get_option( 'mshield_onboarding' ) !== 'pending' ) return;

    wp_safe_redirect( admin_url( 'admin.php?page=mshield-setup' ) );
    exit;

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
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned table
        $wpdb->delete( $wpdb->prefix . 'mshield_log', [ 'endpoint' => 'test_mode' ], [ '%s' ] );

    }

    // Schema changes are no longer handled here — db::maybe_upgrade_schema()
    // owns them, gated on its own counter so they land regardless of what the
    // plugin version already says.

    // 1.9.0: turn on the fraud checks for the block checkout.
    //
    // These shipped off, which meant a store using WooCommerce's default
    // checkout got the firewall and none of the fraud checks. Enabling it does
    // not introduce new policy -- the same scoring the merchant already has
    // applies to the checkout they actually use. Recorded so an admin notice
    // can say what changed, because a security default that flips silently is
    // its own kind of problem.
    if( version_compare( $installed, '1.9.0', '<' ) ) {

        if( get_option( 'mshield_store_api_checks' ) !== 'yes' ) {
            update_option( 'mshield_store_api_checks', 'yes' );
            update_option( 'mshield_store_api_enabled_notice', 1, false );
        }

    }

    // 2.1.1: relax the shared-IP thresholds, but only where the store is still
    // sitting on the old default.
    //
    // These five decide whether a checkout is refused or an address is blocked,
    // and every one of them was keyed on a bare IP -- which on a carrier NAT, an
    // office or a campus is hundreds of unrelated shoppers. Five checkout
    // attempts an hour is five PEOPLE, not five attempts.
    //
    // Raising the defaults alone would have fixed nothing, because the rows are
    // already written on existing stores. And nobody chose them: the only screen
    // that rendered these fields, admin/views/rates.php, became unreachable when
    // the tab was merged away in 1.9.0. A value nobody could see is a stale
    // default, not a preference -- so it is safe to move, and only where it
    // still matches exactly what shipped.
    if( version_compare( $installed, '2.1.1', '<' ) ) {

        $relax = [
            'mshield_rate_checkout_limit'      => [ 5,     20 ],
            'mshield_velocity_email_threshold' => [ 3,     10 ],
            'mshield_velocity_order_threshold' => [ 5,     15 ],
            'mshield_failed_payment_threshold' => [ 5,     10 ],
            'mshield_temp_block_duration'      => [ 86400, 3600 ],
        ];

        foreach( $relax as $option => $pair ) {

            list( $was, $now ) = $pair;

            // Only an untouched value. Anything else is somebody's decision,
            // even if they had to reach it through the database to make it.
            if( (int) get_option( $option, $was ) === $was ) update_option( $option, $now );

        }

    }

    // 2.2.0: drop the eight per-layer action settings.
    //
    // Each of them decided whether its check refused the order outright, which
    // made every one a second decision engine in front of the real one -- and
    // worse, it decided WHEN the check emitted: "block" at validation, "flag"
    // after the order existed. So half the score arrived after the last moment
    // a checkout could be refused, and the refusal was made on the other half.
    //
    // Every one of these checks now only scores. Deleted rather than left in
    // place, because a stale mshield_zip_state_action = 'block' sitting in the
    // options table is a false trail for whoever reads it next.
    if( version_compare( $installed, '2.2.0', '<' ) ) {

        foreach( [
            'mshield_suspicious_amount_action',
            'mshield_smarty_action',
            'mshield_zip_state_action',
            'mshield_honeypot_action',
            'mshield_timing_action',
            'mshield_timing_missing_action',
            'mshield_fingerprint_action',
            'mshield_fingerprint_missing_action',

            // The ninth, and the one that was hardest to see: a single
            // checkbox on the Blocking tab that held an order when both the
            // address and the security code failed the card check. It decided
            // the fate of five separate findings, around the risk levels rather
            // than through them, and none of them had a weight anywhere. They
            // are five scored rows on the Scoring tab now -- and the defaults
            // add up to the same hold this did.
            'mshield_card_hold_on_mismatch',
        ] as $option ) {
            delete_option( $option );
        }

        // The block checkout counted its own velocity in transients, keyed per
        // IP, and velocity_detector owns both checkouts now. These would never
        // be read again and expire on their own, but they are cheap to clear
        // and confusing to find.
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned table
        $wpdb->query(
            "DELETE FROM {$wpdb->options}
              WHERE option_name LIKE '_transient_mshield_emails_%'
                 OR option_name LIKE '_transient_timeout_mshield_emails_%'
                 OR option_name LIKE '_transient_mshield_orders_%'
                 OR option_name LIKE '_transient_timeout_mshield_orders_%'"
        );

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
    require_once MSHIELD_PATH . 'includes/class-api-error.php';
    require_once MSHIELD_PATH . 'includes/class-ai-client.php';
    require_once MSHIELD_PATH . 'includes/class-ai-capture.php';
    require_once MSHIELD_PATH . 'includes/class-trust-badge.php';
    require_once MSHIELD_PATH . 'includes/class-rescore.php';
    require_once MSHIELD_PATH . 'includes/class-privacy.php';
    require_once MSHIELD_PATH . 'includes/class-backfill.php';
    require_once MSHIELD_PATH . 'admin/class-admin-page.php';
    require_once MSHIELD_PATH . 'admin/class-log-viewer.php';
    require_once MSHIELD_PATH . 'admin/class-order-panel.php';
    require_once MSHIELD_PATH . 'admin/class-order-column.php';
    require_once MSHIELD_PATH . 'admin/class-dashboard-widget.php';
    require_once MSHIELD_PATH . 'admin/class-fraud-review.php';
    require_once MSHIELD_PATH . 'admin/class-setup-wizard.php';

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

    // Keep the MaxMind ASN database current. Registered beside the cleanup for
    // the same reason it is: the cron event is scheduled unconditionally at
    // activation, and the network signals are not something a merchant turns
    // off, so there is no feature guard to hide this behind.
    //
    // Cheap to call. It is one option read and one filemtime unless the
    // database is actually stale, and it does nothing at all on a store that
    // has never set a MaxMind licence key.
    add_action( 'mshield_daily_cleanup', [ '\MightyShield\Includes\ip_data', 'maybe_update_asn_database' ] );

    // Re-learn what a large order looks like on this store. Daily is often
    // enough for a figure derived from a year of orders, and it must not be
    // done on a checkout request: it is two aggregate queries over the whole
    // order table.
    add_action( 'mshield_daily_cleanup', [ '\MightyShield\Includes\db', 'learn_high_value' ] );

    // Personal data export and erasure.
    //
    // Above the mshield_enabled guard, and it has to stay there. Switching
    // protection off stops MightyShield WRITING anything; it does not delete
    // what a store already holds, and a store still has to be able to answer a
    // request about it. A privacy obligation is not a feature to toggle.
    \MightyShield\Includes\privacy::register();

    // The back-catalogue rating pass. Above the mshield_enabled guard for the
    // same reason as privacy: a run already in progress must finish, or
    // resume, whether or not protection is switched on. It takes no action on
    // any order — see includes/class-backfill.php.
    \MightyShield\Includes\backfill::register();

    // Always load admin page so settings are accessible.
    if( is_admin() ) {
        new \MightyShield\Admin\admin_page();
        new \MightyShield\Admin\log_viewer();
        new \MightyShield\Admin\order_panel();
        new \MightyShield\Admin\order_column();
        new \MightyShield\Admin\dashboard_widget();
        new \MightyShield\Admin\fraud_review();

        // Above the mshield_enabled guard further down, and it has to stay
        // there: choosing "Disabled" on the wizard's last step would otherwise
        // make the wizard itself disappear on the very next request, with no way
        // back to it from the UI.
        new \MightyShield\Admin\setup_wizard();
        add_action( 'admin_notices', [ '\MightyShield\Admin\order_panel', 'render_notice' ] );

        // Protection classes the ADMIN needs, loaded before the guard below.
        //
        // Everything under protection/ is required further down, after the
        // mshield_enabled check, and there is no autoloader. So any admin code
        // naming one of those classes fatals the moment a merchant chooses
        // "Disabled" -- on every wp-admin page, with the only route back to the
        // setting being the admin it just killed. Recovery needs database
        // access.
        //
        // That was not hypothetical. register_settings() iterates
        // challenge::SURFACES on every admin_init, so Disabled bricked the admin
        // outright, reachable from the Dashboard control on every tab and from
        // the setup wizard's last step.
        //
        // outcomes was already here for the same reason: a reviewer must still
        // be able to rule on an order with protection switched off. The rule is
        // the file list below, not the reasoning -- if admin code needs a
        // protection class, it belongs here.
        require_once MSHIELD_PATH . 'protection/class-outcomes.php';
        require_once MSHIELD_PATH . 'protection/class-captcha.php';
        require_once MSHIELD_PATH . 'protection/class-challenge.php';
        require_once MSHIELD_PATH . 'protection/class-smarty-address-verifier.php';
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
 * Updates are WordPress.org's job.
 *
 * Until 2.3.0 this file ended by wiring up Plugin Update Checker against the
 * GitHub repository, which fetched release metadata on a schedule and could
 * install a ZIP from there. That is a direct conflict with plugin directory
 * guideline 8 -- a plugin hosted on WordPress.org may not serve its own
 * updates or install code from anywhere else -- so both it and the vendored
 * updates/ library are gone.
 *
 * Nothing replaces it. WordPress updates a directory-hosted plugin itself.
 *
 * @since   2.3.0
 */
