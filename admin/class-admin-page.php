<?php
/**
 * Admin Page.
 *
 * MightyShield admin settings interface under WooCommerce menu.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Admin;

use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Firewall\ip_whitelist;

class admin_page {

    /**
     * Allowed tab slugs.
     *
     * @since   1.0.0
     */
    private const ALLOWED_TABS = [ 'dashboard', 'firewall', 'whitelist', 'rates', 'fraud', 'logs' ];

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        add_action( 'admin_menu', [ $this, 'register_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'admin_init', [ $this, 'handle_actions' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_styles' ] );

    }

    /**
     * Register admin menu.
     *
     * @since   1.0.0
     */
    public function register_menu() {

        add_submenu_page(
            'woocommerce',
            __( 'MightyShield', 'mighty-shield' ),
            __( 'MightyShield', 'mighty-shield' ),
            'manage_woocommerce',
            'mighty-shield',
            [ $this, 'render_page' ]
        );

    }

    /**
     * Register settings with sanitize callbacks.
     *
     * @since   1.0.0
     */
    public function register_settings() {

        // Checkbox settings — default to 'no' when unchecked (not sent in POST).
        register_setting( 'mshield_settings', 'mshield_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_settings', 'mshield_block_store_api', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );

        // Integer settings with min/max bounds.
        register_setting( 'mshield_settings', 'mshield_rate_checkout_limit', [
            'sanitize_callback' => function( $value ) { return max( 1, absint( $value ) ); },
        ] );
        register_setting( 'mshield_settings', 'mshield_rate_checkout_window', [
            'sanitize_callback' => function( $value ) { return max( 60, absint( $value ) ); },
        ] );
        register_setting( 'mshield_settings', 'mshield_velocity_email_threshold', [
            'sanitize_callback' => function( $value ) { return max( 1, absint( $value ) ); },
        ] );
        register_setting( 'mshield_settings', 'mshield_velocity_order_threshold', [
            'sanitize_callback' => function( $value ) { return max( 1, absint( $value ) ); },
        ] );
        register_setting( 'mshield_settings', 'mshield_failed_payment_threshold', [
            'sanitize_callback' => function( $value ) { return max( 1, absint( $value ) ); },
        ] );
        register_setting( 'mshield_settings', 'mshield_temp_block_duration', [
            'sanitize_callback' => function( $value ) { return max( 3600, absint( $value ) ); },
        ] );
        register_setting( 'mshield_settings', 'mshield_log_retention_days', [
            'sanitize_callback' => function( $value ) { return max( 1, min( 365, absint( $value ) ) ); },
        ] );

        // Textarea — sanitize line-by-line.
        register_setting( 'mshield_settings', 'mshield_blocked_email_domains', [
            'sanitize_callback' => 'sanitize_textarea_field',
        ] );

        // Float — minimum order amount.
        register_setting( 'mshield_settings', 'mshield_min_order_amount', [
            'sanitize_callback' => function( $value ) { return max( 0, (float) $value ); },
        ] );

        // Select — whitelist allowed values.
        register_setting( 'mshield_settings', 'mshield_suspicious_amount_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag', 'notify' ], true ) ? $value : 'flag';
            },
        ] );
        register_setting( 'mshield_settings', 'mshield_address_sensitivity', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'low', 'medium', 'high' ], true ) ? $value : 'medium';
            },
        ] );

        // Smarty Address Verification.
        register_setting( 'mshield_settings', 'mshield_smarty_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_settings', 'mshield_smarty_auth_id', [
            'sanitize_callback' => 'sanitize_text_field',
        ] );
        register_setting( 'mshield_settings', 'mshield_smarty_auth_token', [
            'sanitize_callback' => function( $value ) {
                if( empty( $value ) ) {
                    return get_option( 'mshield_smarty_auth_token', '' );
                }
                return sanitize_text_field( $value );
            },
        ] );
        register_setting( 'mshield_settings', 'mshield_smarty_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag', 'notify' ], true ) ? $value : 'flag';
            },
        ] );

        // ZIP/State Mismatch.
        register_setting( 'mshield_settings', 'mshield_zip_state_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_settings', 'mshield_zip_state_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag', 'notify' ], true ) ? $value : 'block';
            },
        ] );

        // Honeypot.
        register_setting( 'mshield_settings', 'mshield_honeypot_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );

        // Device Fingerprinting.
        register_setting( 'mshield_settings', 'mshield_fingerprint_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );

    }

    /**
     * Sanitize checkbox value.
     *
     * Returns 'yes' if checked, 'no' if unchecked (absent from POST).
     *
     * @since   1.0.0
     *
     * @param   mixed   $value  Submitted value.
     * @return  string  'yes' or 'no'.
     */
    public function sanitize_checkbox( $value ) {

        return ( $value === 'yes' ) ? 'yes' : 'no';

    }

    /**
     * Handle admin actions (whitelist add/remove).
     *
     * @since   1.0.0
     */
    public function handle_actions() {

        // Capability check for all actions.
        if( ! current_user_can( 'manage_woocommerce' ) ) return;

        // Add IP to whitelist.
        if( isset( $_POST['mshield_add_ip'] ) && check_admin_referer( 'mshield_whitelist_action' ) ) {

            $ip    = sanitize_text_field( $_POST['mshield_new_ip'] ?? '' );
            $label = sanitize_text_field( $_POST['mshield_new_ip_label'] ?? '' );

            if( ! empty( $ip ) && $this->validate_ip_input( $ip ) ) {
                ip_whitelist::add_ip( $ip, $label );
                set_transient( 'mshield_admin_notice', [ 'ip_added', __( 'IP address added to whitelist.', 'mighty-shield' ), 'success' ], 30 );
            } else {
                set_transient( 'mshield_admin_notice', [ 'ip_invalid', __( 'Invalid IP address or CIDR format.', 'mighty-shield' ), 'error' ], 30 );
            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=whitelist' ) );
            exit;

        }

        // Remove IP from whitelist.
        if( isset( $_GET['mshield_remove_ip'] ) && isset( $_GET['_wpnonce'] ) ) {

            if( wp_verify_nonce( $_GET['_wpnonce'], 'mshield_remove_ip' ) ) {
                $ip = sanitize_text_field( $_GET['mshield_remove_ip'] );
                ip_whitelist::remove_ip( $ip );
                set_transient( 'mshield_admin_notice', [ 'ip_removed', __( 'IP address removed from whitelist.', 'mighty-shield' ), 'success' ], 30 );
            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=whitelist' ) );
            exit;

        }

        // Clear logs.
        if( isset( $_POST['mshield_clear_logs'] ) && check_admin_referer( 'mshield_clear_logs_action' ) ) {

            global $wpdb;
            $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}mshield_log" );
            set_transient( 'mshield_admin_notice', [ 'logs_cleared', __( 'All logs have been cleared.', 'mighty-shield' ), 'success' ], 30 );

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=logs' ) );
            exit;

        }

    }

    /**
     * Validate IP address or CIDR input.
     *
     * @since   1.0.0
     *
     * @param   string  $ip     IP or CIDR string.
     * @return  bool
     */
    private function validate_ip_input( $ip ) {

        // Plain IP address.
        if( filter_var( $ip, FILTER_VALIDATE_IP ) ) return true;

        // CIDR notation.
        if( strpos( $ip, '/' ) !== false ) {
            $parts = explode( '/', $ip, 2 );
            if( count( $parts ) !== 2 ) return false;

            $subnet = $parts[0];
            $mask   = (int) $parts[1];

            if( ! filter_var( $subnet, FILTER_VALIDATE_IP ) ) return false;

            // IPv4 mask: 0-32, IPv6 mask: 0-128.
            if( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
                return $mask >= 0 && $mask <= 32;
            }
            if( filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
                return $mask >= 0 && $mask <= 128;
            }
        }

        return false;

    }

    /**
     * Enqueue admin styles.
     *
     * @since   1.0.0
     */
    public function enqueue_styles( $hook ) {

        if( strpos( $hook, 'mighty-shield' ) === false ) return;

        wp_add_inline_style( 'wp-admin', '
            .mshield-wrap { max-width: 1200px; }
            .mshield-tabs { display: flex; gap: 0; margin-bottom: 20px; border-bottom: 1px solid #c3c4c7; }
            .mshield-tabs a { padding: 10px 20px; text-decoration: none; color: #50575e; border: 1px solid transparent; border-bottom: none; margin-bottom: -1px; }
            .mshield-tabs a.active { background: #fff; border-color: #c3c4c7; border-bottom-color: #fff; color: #1d2327; font-weight: 600; }
            .mshield-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
            .mshield-stat { background: #fff; border: 1px solid #c3c4c7; padding: 20px; border-radius: 4px; }
            .mshield-stat h3 { margin: 0 0 5px; font-size: 14px; color: #50575e; }
            .mshield-stat .number { font-size: 32px; font-weight: 700; color: #1d2327; }
            .mshield-stat .number.blocked { color: #d63638; }
            .mshield-stat .number.limited { color: #dba617; }
            .mshield-stat .number.flagged { color: #2271b1; }
            .mshield-table { width: 100%; border-collapse: collapse; }
            .mshield-table th, .mshield-table td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #c3c4c7; }
            .mshield-table th { background: #f0f0f1; font-weight: 600; }
            .mshield-section { background: #fff; border: 1px solid #c3c4c7; padding: 20px; margin-bottom: 20px; border-radius: 4px; }
            .mshield-section h2 { margin-top: 0; }
        ' );

    }

    /**
     * Render the admin page.
     *
     * @since   1.0.0
     */
    public function render_page() {

        $tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'dashboard';

        // Whitelist allowed tabs to prevent path traversal.
        if( ! \in_array( $tab, self::ALLOWED_TABS, true ) ) {
            $tab = 'dashboard';
        }

        echo '<div class="wrap mshield-wrap">';
        echo '<h1>' . esc_html__( 'MightyShield', 'mighty-shield' ) . '</h1>';

        // Display any transient notices from redirected actions.
        $notice = get_transient( 'mshield_admin_notice' );
        if( $notice && is_array( $notice ) && count( $notice ) === 3 ) {
            delete_transient( 'mshield_admin_notice' );
            add_settings_error( 'mshield', $notice[0], $notice[1], $notice[2] );
        }

        settings_errors( 'mshield' );

        // Tabs.
        $tabs = [
            'dashboard' => __( 'Dashboard', 'mighty-shield' ),
            'firewall'  => __( 'Firewall', 'mighty-shield' ),
            'whitelist' => __( 'IP Whitelist', 'mighty-shield' ),
            'rates'     => __( 'Rate Limits', 'mighty-shield' ),
            'fraud'     => __( 'Fraud Checks', 'mighty-shield' ),
            'logs'      => __( 'Logs', 'mighty-shield' ),
        ];

        echo '<div class="mshield-tabs">';
        foreach( $tabs as $key => $label ) {
            $url   = admin_url( 'admin.php?page=mighty-shield&tab=' . $key );
            $class = ( $tab === $key ) ? 'active' : '';
            echo '<a href="' . esc_url( $url ) . '" class="' . esc_attr( $class ) . '">' . esc_html( $label ) . '</a>';
        }
        echo '</div>';

        // Render active tab.
        include MSHIELD_PATH . 'admin/views/' . $tab . '.php';

        echo '</div>';

    }

}
