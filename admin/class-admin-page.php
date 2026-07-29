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
use MightyShield\Includes\ip_data;
use MightyShield\Firewall\ip_whitelist;
use MightyShield\Firewall\ip_blocklist;

class admin_page {

    /**
     * Allowed tab slugs.
     *
     * @since   1.0.0
     */
    private const ALLOWED_TABS = [ 'dashboard', 'firewall', 'whitelist', 'blocklist', 'rates', 'fraud', 'logs', 'documentation' ];

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
        add_action( 'wp_ajax_mshield_set_theme', [ $this, 'ajax_set_theme' ] );
        add_action( 'wp_ajax_mshield_get_ip', [ $this, 'ajax_get_ip' ] );
        add_action( 'wp_ajax_mshield_chart', [ $this, 'ajax_chart' ] );
        add_filter( 'admin_body_class', [ $this, 'admin_body_class' ] );

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

        // --- Firewall tab settings ---
        register_setting( 'mshield_firewall', 'mshield_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_firewall', 'mshield_block_store_api', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_firewall', 'mshield_log_retention_days', [
            'sanitize_callback' => function( $value ) { return max( 1, min( 365, absint( $value ) ) ); },
        ] );

        // --- Rate Limits tab settings ---
        register_setting( 'mshield_rates', 'mshield_rate_checkout_limit', [
            'sanitize_callback' => function( $value ) { return max( 1, absint( $value ) ); },
        ] );
        register_setting( 'mshield_rates', 'mshield_rate_checkout_window', [
            'sanitize_callback' => function( $value ) { return max( 60, absint( $value ) ); },
        ] );
        register_setting( 'mshield_rates', 'mshield_velocity_email_threshold', [
            'sanitize_callback' => function( $value ) { return max( 1, absint( $value ) ); },
        ] );
        register_setting( 'mshield_rates', 'mshield_velocity_order_threshold', [
            'sanitize_callback' => function( $value ) { return max( 1, absint( $value ) ); },
        ] );
        register_setting( 'mshield_rates', 'mshield_failed_payment_threshold', [
            'sanitize_callback' => function( $value ) { return max( 1, absint( $value ) ); },
        ] );
        register_setting( 'mshield_rates', 'mshield_temp_block_duration', [
            'sanitize_callback' => function( $value ) { return max( 3600, absint( $value ) ); },
        ] );

        // --- Fraud Checks tab settings ---
        register_setting( 'mshield_fraud', 'mshield_blocked_email_domains', [
            'sanitize_callback' => 'sanitize_textarea_field',
        ] );
        register_setting( 'mshield_fraud', 'mshield_min_order_amount', [
            'sanitize_callback' => function( $value ) { return max( 0, (float) $value ); },
        ] );
        register_setting( 'mshield_fraud', 'mshield_suspicious_amount_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag', 'notify' ], true ) ? $value : 'flag';
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_address_sensitivity', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'low', 'medium', 'high' ], true ) ? $value : 'medium';
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_smarty_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_fraud', 'mshield_smarty_auth_id', [
            'sanitize_callback' => 'sanitize_text_field',
        ] );
        register_setting( 'mshield_fraud', 'mshield_smarty_auth_token', [
            'sanitize_callback' => function( $value ) {
                if( empty( $value ) ) {
                    return get_option( 'mshield_smarty_auth_token', '' );
                }
                return sanitize_text_field( $value );
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_smarty_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag', 'notify' ], true ) ? $value : 'flag';
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_zip_state_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_fraud', 'mshield_zip_state_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag', 'notify' ], true ) ? $value : 'block';
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_honeypot_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_fraud', 'mshield_honeypot_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag', 'notify' ], true ) ? $value : 'block';
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_timing_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_fraud', 'mshield_timing_min_seconds', [
            'sanitize_callback' => function( $value ) { return max( 0, absint( $value ) ); },
        ] );
        register_setting( 'mshield_fraud', 'mshield_timing_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag', 'notify' ], true ) ? $value : 'flag';
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_timing_missing_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag' ], true ) ? $value : 'flag';
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_fingerprint_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_fraud', 'mshield_fingerprint_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag', 'notify' ], true ) ? $value : 'block';
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_fingerprint_missing_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag' ], true ) ? $value : 'flag';
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_fingerprint_velocity_threshold', [
            'sanitize_callback' => function( $value ) { return max( 0, absint( $value ) ); },
        ] );

        // Bot challenge (CAPTCHA).
        register_setting( 'mshield_fraud', 'mshield_captcha_provider', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'off', 'turnstile', 'recaptcha_v3' ], true ) ? $value : 'off';
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_captcha_site_key', [
            'sanitize_callback' => 'sanitize_text_field',
        ] );
        register_setting( 'mshield_fraud', 'mshield_captcha_secret_key', [
            'sanitize_callback' => function( $value ) {
                if( empty( $value ) ) {
                    return get_option( 'mshield_captcha_secret_key', '' );
                }
                return sanitize_text_field( $value );
            },
        ] );
        register_setting( 'mshield_fraud', 'mshield_captcha_action', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'block', 'flag', 'notify' ], true ) ? $value : 'block';
            },
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

        // Add a typed entry to the whitelist (IP / user / email / role).
        if( isset( $_POST['mshield_add_ip'] ) && check_admin_referer( 'mshield_whitelist_action' ) ) {

            $type  = sanitize_text_field( $_POST['mshield_new_type'] ?? 'ip' );
            $value = ( $type === 'role' )
                ? sanitize_key( $_POST['mshield_new_role'] ?? '' )
                : sanitize_text_field( wp_unslash( $_POST['mshield_new_value'] ?? '' ) );
            $label = sanitize_text_field( wp_unslash( $_POST['mshield_new_ip_label'] ?? '' ) );

            set_transient( 'mshield_admin_notice', $this->whitelist_add( $type, $value, $label ), 30 );

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=whitelist' ) );
            exit;

        }

        // Remove an entry from the whitelist.
        if( isset( $_GET['mshield_remove_ip'] ) && isset( $_GET['_wpnonce'] ) ) {

            if( wp_verify_nonce( $_GET['_wpnonce'], 'mshield_remove_ip' ) ) {
                $value = sanitize_text_field( wp_unslash( $_GET['mshield_remove_ip'] ) );
                $type  = sanitize_text_field( $_GET['wl_type'] ?? 'ip' );
                if( ! \in_array( $type, [ 'ip', 'user', 'email' ], true ) ) $type = 'ip';
                ip_whitelist::remove_entry( $type, $value );
                set_transient( 'mshield_admin_notice', [ 'ip_removed', __( 'Whitelist entry removed.', 'mighty-shield' ), 'success' ], 30 );
            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=whitelist' ) );
            exit;

        }

        // Add IP to blocklist.
        if( isset( $_POST['mshield_block_add_ip'] ) && check_admin_referer( 'mshield_blocklist_action' ) ) {

            $ip    = sanitize_text_field( $_POST['mshield_block_new_ip'] ?? '' );
            $label = sanitize_text_field( $_POST['mshield_block_new_ip_label'] ?? '' );

            if( ! empty( $ip ) && $this->validate_ip_input( $ip ) ) {
                ip_blocklist::add_ip( $ip, $label, 'Added manually' );
                set_transient( 'mshield_admin_notice', [ 'ip_blocked', __( 'IP address added to blocklist.', 'mighty-shield' ), 'success' ], 30 );
            } else {
                set_transient( 'mshield_admin_notice', [ 'ip_invalid', __( 'Invalid IP address or CIDR format.', 'mighty-shield' ), 'error' ], 30 );
            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=blocklist' ) );
            exit;

        }

        // Remove IP from blocklist.
        if( isset( $_GET['mshield_block_remove_ip'] ) && isset( $_GET['_wpnonce'] ) ) {

            if( wp_verify_nonce( $_GET['_wpnonce'], 'mshield_block_remove_ip' ) ) {
                $ip = sanitize_text_field( $_GET['mshield_block_remove_ip'] );
                ip_blocklist::remove_ip( $ip );
                set_transient( 'mshield_admin_notice', [ 'ip_unblocked', __( 'IP address removed from blocklist.', 'mighty-shield' ), 'success' ], 30 );
            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=blocklist' ) );
            exit;

        }

        // Block an IP directly from the Logs table.
        if( isset( $_GET['mshield_block_ip'] ) && isset( $_GET['_wpnonce'] ) ) {

            if( wp_verify_nonce( $_GET['_wpnonce'], 'mshield_block_ip' ) ) {
                $ip = sanitize_text_field( $_GET['mshield_block_ip'] );
                if( ! empty( $ip ) && $this->validate_ip_input( $ip ) ) {
                    ip_blocklist::add_ip( $ip, '', 'Blocked from logs' );
                    set_transient( 'mshield_admin_notice', [ 'ip_blocked', sprintf( __( 'IP %s added to blocklist.', 'mighty-shield' ), $ip ), 'success' ], 30 );
                }
            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=blocklist' ) );
            exit;

        }

        // Whitelist an IP directly from the Logs table.
        if( isset( $_GET['mshield_whitelist_ip'] ) && isset( $_GET['_wpnonce'] ) ) {

            if( wp_verify_nonce( $_GET['_wpnonce'], 'mshield_whitelist_ip' ) ) {
                $value = sanitize_text_field( wp_unslash( $_GET['mshield_whitelist_ip'] ) );
                set_transient( 'mshield_admin_notice', $this->whitelist_add( 'ip', $value, 'Whitelisted from logs' ), 30 );
            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=whitelist' ) );
            exit;

        }

        // Whitelist an email directly from the Logs table.
        if( isset( $_GET['mshield_whitelist_email'] ) && isset( $_GET['_wpnonce'] ) ) {

            if( wp_verify_nonce( $_GET['_wpnonce'], 'mshield_whitelist_email' ) ) {
                $value = sanitize_text_field( wp_unslash( $_GET['mshield_whitelist_email'] ) );
                set_transient( 'mshield_admin_notice', $this->whitelist_add( 'email', $value, 'Whitelisted from logs' ), 30 );
            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=whitelist' ) );
            exit;

        }

        // Whitelist a WP user directly from the Logs table.
        if( isset( $_GET['mshield_whitelist_user'] ) && isset( $_GET['_wpnonce'] ) ) {

            if( wp_verify_nonce( $_GET['_wpnonce'], 'mshield_whitelist_user' ) ) {
                $value = sanitize_text_field( wp_unslash( $_GET['mshield_whitelist_user'] ) );
                set_transient( 'mshield_admin_notice', $this->whitelist_add( 'user', $value, 'Whitelisted from logs' ), 30 );
            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=whitelist' ) );
            exit;

        }

        // Toggle master protection (dashboard hero switch).
        if( isset( $_GET['mshield_toggle_protection'] ) && isset( $_GET['_wpnonce'] ) ) {

            if( wp_verify_nonce( $_GET['_wpnonce'], 'mshield_toggle_protection' ) ) {
                $new = get_option( 'mshield_enabled', 'yes' ) === 'yes' ? 'no' : 'yes';
                update_option( 'mshield_enabled', $new );
                set_transient( 'mshield_admin_notice', [ 'protection', $new === 'yes' ? __( 'Protection enabled.', 'mighty-shield' ) : __( 'Protection disabled.', 'mighty-shield' ), 'success' ], 30 );
            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=dashboard' ) );
            exit;

        }

        // Bulk actions on selected log rows.
        if( isset( $_POST['mshield_logs_bulk'] ) && check_admin_referer( 'mshield_logs_bulk_action' ) ) {

            $action = sanitize_text_field( $_POST['mshield_bulk_action'] ?? '' );
            $ids    = array_filter( array_map( 'absint', (array) ( $_POST['log_ids'] ?? [] ) ) );

            if( empty( $ids ) || $action === '' ) {

                set_transient( 'mshield_admin_notice', [ 'bulk_none', __( 'No log entries were selected.', 'mighty-shield' ), 'error' ], 30 );

            } elseif( $action === 'delete' ) {

                $n = db::delete_logs_by_ids( $ids );
                set_transient( 'mshield_admin_notice', [ 'bulk_deleted', sprintf( __( 'Deleted %d log entries.', 'mighty-shield' ), $n ), 'success' ], 30 );

            } elseif( \in_array( $action, [ 'block_ip', 'whitelist_ip' ], true ) ) {

                global $wpdb;
                $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
                $ips = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT ip FROM {$wpdb->prefix}mshield_log WHERE id IN ({$placeholders})", $ids ) );

                $count = 0;
                foreach( $ips as $ip ) {
                    if( ! $this->validate_ip_input( $ip ) ) continue;
                    if( $action === 'block_ip' ) {
                        ip_blocklist::add_ip( $ip, '', 'Bulk-blocked from logs' );
                    } else {
                        ip_whitelist::add_entry( 'ip', $ip, 'Bulk-whitelisted from logs' );
                    }
                    $count++;
                }

                $msg = $action === 'block_ip'
                    ? sprintf( __( '%d IP addresses added to the blocklist.', 'mighty-shield' ), $count )
                    : sprintf( __( '%d IP addresses added to the whitelist.', 'mighty-shield' ), $count );
                set_transient( 'mshield_admin_notice', [ 'bulk_ip', $msg, 'success' ], 30 );

            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=logs' ) );
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
     * Validate, resolve, and add a typed whitelist entry.
     *
     * @since   1.4.0
     *
     * @param   string  $type   'ip', 'user', or 'email'.
     * @param   string  $value  IP/CIDR, username/email/ID, or email address.
     * @param   string  $label  Optional label.
     * @return  array   Admin-notice tuple [ id, message, type ].
     */
    private function whitelist_add( $type, $value, $label = '' ) {

        if( $type === 'ip' ) {

            if( empty( $value ) || ! $this->validate_ip_input( $value ) ) {
                return [ 'wl_invalid', __( 'Invalid IP address or CIDR format.', 'mighty-shield' ), 'error' ];
            }
            ip_whitelist::add_entry( 'ip', $value, $label );
            return [ 'wl_added', sprintf( __( 'IP %s added to whitelist.', 'mighty-shield' ), $value ), 'success' ];

        }

        if( $type === 'email' ) {

            if( ! is_email( $value ) ) {
                return [ 'wl_invalid', __( 'Invalid email address.', 'mighty-shield' ), 'error' ];
            }
            ip_whitelist::add_entry( 'email', $value, $label );
            return [ 'wl_added', sprintf( __( 'Email %s added to whitelist.', 'mighty-shield' ), $value ), 'success' ];

        }

        if( $type === 'user' ) {

            if( ctype_digit( (string) $value ) ) {
                $user = get_user_by( 'id', (int) $value );
            } elseif( is_email( $value ) ) {
                $user = get_user_by( 'email', $value );
            } else {
                $user = get_user_by( 'login', $value );
            }

            if( ! $user ) {
                return [ 'wl_invalid', __( 'No WordPress user found for that username/email/ID.', 'mighty-shield' ), 'error' ];
            }

            $display = $label !== '' ? $label : $user->user_login . ' (' . $user->user_email . ')';
            ip_whitelist::add_entry( 'user', $user->ID, $display );
            return [ 'wl_added', sprintf( __( 'User %s added to whitelist.', 'mighty-shield' ), $user->user_login ), 'success' ];

        }

        if( $type === 'role' ) {

            $roles = wp_roles()->roles;
            $slug  = sanitize_key( $value );

            // Accept a slug directly, or resolve a display name to its slug.
            if( ! isset( $roles[ $slug ] ) ) {
                $slug = '';
                foreach( $roles as $role_slug => $role ) {
                    if( strtolower( $role['name'] ) === strtolower( trim( $value ) ) ) {
                        $slug = $role_slug;
                        break;
                    }
                }
            }

            if( $slug === '' || ! isset( $roles[ $slug ] ) ) {
                return [ 'wl_invalid', __( 'Unknown user role.', 'mighty-shield' ), 'error' ];
            }

            $name    = translate_user_role( $roles[ $slug ]['name'] );
            $display = $label !== '' ? $label : $name;
            ip_whitelist::add_entry( 'role', $slug, $display );
            return [ 'wl_added', sprintf( __( 'Role %s added to whitelist.', 'mighty-shield' ), $name ), 'success' ];

        }

        return [ 'wl_invalid', __( 'Invalid whitelist entry type.', 'mighty-shield' ), 'error' ];

    }

    /**
     * Enqueue admin styles.
     *
     * @since   1.0.0
     */
    public function enqueue_styles( $hook ) {

        if( strpos( $hook, 'mighty-shield' ) === false ) return;

        // Design-system fonts (Public Sans + JetBrains Mono).
        wp_enqueue_style(
            'mshield-fonts',
            'https://fonts.googleapis.com/css2?family=Public+Sans:ital,wght@0,300..800;1,400&family=JetBrains+Mono:wght@400;500;600&display=swap',
            [],
            null
        );

        // Version assets by modification time so edits always bust the cache.
        $css_ver = @filemtime( MSHIELD_PATH . 'assets/css/mshield-admin.css' ) ?: MSHIELD_VERSION;
        $js_ver  = @filemtime( MSHIELD_PATH . 'assets/js/mshield-admin.js' ) ?: MSHIELD_VERSION;

        wp_enqueue_style( 'mshield-admin', MSHIELD_URI . 'assets/css/mshield-admin.css', [ 'mshield-fonts' ], $css_ver );

        wp_enqueue_script( 'mshield-admin', MSHIELD_URI . 'assets/js/mshield-admin.js', [], $js_ver, [ 'in_footer' => true ] );
        wp_localize_script( 'mshield-admin', 'mshieldAdmin', [
            'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
            'themeNonce' => wp_create_nonce( 'mshield_set_theme' ),
            'ipNonce'    => wp_create_nonce( 'mshield_get_ip' ),
            'chartNonce' => wp_create_nonce( 'mshield_chart' ),
            'i18n'       => [
                'selected'    => __( 'selected', 'mighty-shield' ),
                'eventDetail' => __( 'Event detail', 'mighty-shield' ),
                'ip'          => __( 'IP address', 'mighty-shield' ),
                'endpoint'    => __( 'Endpoint', 'mighty-shield' ),
                'reason'      => __( 'Reason', 'mighty-shield' ),
                'user'        => __( 'User', 'mighty-shield' ),
                'raw'         => __( 'Request data', 'mighty-shield' ),
                'whitelistIp' => __( 'Whitelist IP', 'mighty-shield' ),
                'blockPerm'   => __( 'Block permanently', 'mighty-shield' ),
                'ipIntel'     => __( 'IP location', 'mighty-shield' ),
                'getIp'       => __( 'Get IP', 'mighty-shield' ),
                'gettingIp'   => __( 'Looking up…', 'mighty-shield' ),
                'location'    => __( 'Location', 'mighty-shield' ),
                'org'         => __( 'Organization', 'mighty-shield' ),
                'country'     => __( 'Country', 'mighty-shield' ),
                'lookupFail'  => __( 'Lookup failed. Please try again.', 'mighty-shield' ),
            ],
        ] );

    }

    /**
     * Get the current user's saved admin theme.
     *
     * @since   1.5.0
     *
     * @return  string  'light' or 'dark'.
     */
    private function get_theme() {

        $theme = get_user_meta( get_current_user_id(), 'mshield_admin_theme', true );
        return $theme === 'dark' ? 'dark' : 'light';

    }

    /**
     * Add a body class on the plugin page so dark mode can repaint the WP chrome.
     *
     * @since   1.5.0
     *
     * @param   string  $classes    Space-separated body classes.
     * @return  string
     */
    public function admin_body_class( $classes ) {

        if( isset( $_GET['page'] ) && $_GET['page'] === 'mighty-shield' && $this->get_theme() === 'dark' ) {
            $classes .= ' mshield-theme-dark';
        }

        return $classes;

    }

    /**
     * Render a horizontal radio-bubble group (segmented choice control).
     *
     * @since   1.5.0
     *
     * @param   string  $name       Field name.
     * @param   array   $options    value => label map.
     * @param   string  $current    Currently selected value.
     */
    public static function radios( $name, $options, $current ) {

        echo '<div class="mshield-radios">';
        foreach( $options as $value => $label ) {
            $is = ( (string) $current === (string) $value ) ? ' is-checked' : '';
            echo '<label class="mshield-radio' . esc_attr( $is ) . '">';
            echo '<input type="radio" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '" ' . checked( $current, $value, false ) . ' />';
            echo '<span>' . esc_html( $label ) . '</span>';
            echo '</label>';
        }
        echo '</div>';

    }

    /**
     * AJAX: persist the admin theme choice for the current user.
     *
     * @since   1.5.0
     */
    public function ajax_set_theme() {

        if( ! current_user_can( 'manage_woocommerce' ) ) wp_send_json_error( '', 403 );
        if( ! check_ajax_referer( 'mshield_set_theme', 'nonce', false ) ) wp_send_json_error( '', 400 );

        $theme = isset( $_POST['theme'] ) && $_POST['theme'] === 'dark' ? 'dark' : 'light';
        update_user_meta( get_current_user_id(), 'mshield_admin_theme', $theme );

        wp_send_json_success( [ 'theme' => $theme ] );

    }

    /**
     * AJAX: fetch (and cache) geolocation data for a single IP on demand.
     *
     * @since   1.6.0
     */
    public function ajax_get_ip() {

        if( ! current_user_can( 'manage_woocommerce' ) ) wp_send_json_error( '', 403 );
        if( ! check_ajax_referer( 'mshield_get_ip', 'nonce', false ) ) wp_send_json_error( '', 400 );

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
        if( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) wp_send_json_error( [ 'message' => __( 'Invalid IP.', 'mighty-shield' ) ], 400 );

        $data = ip_data::get_or_fetch( $ip );
        if( $data === null ) {
            wp_send_json_error( [ 'message' => __( 'Lookup failed. Please try again.', 'mighty-shield' ) ] );
        }

        wp_send_json_success( [
            'status'  => $data['status'],
            'city'    => $data['city'],
            'region'  => $data['region'],
            'country' => $data['country'],
            'org'     => $data['org'],
        ] );

    }

    /**
     * AJAX: return event-trend series for a given range (24h / 7d / 30d).
     *
     * @since   1.6.0
     */
    public function ajax_chart() {

        if( ! current_user_can( 'manage_woocommerce' ) ) wp_send_json_error( '', 403 );
        if( ! check_ajax_referer( 'mshield_chart', 'nonce', false ) ) wp_send_json_error( '', 400 );

        $range = isset( $_GET['range'] ) ? sanitize_text_field( wp_unslash( $_GET['range'] ) ) : '30d';

        wp_send_json_success( self::chart_series( $range ) );

    }

    /**
     * Build a chart series payload for a range key.
     *
     * @since   1.6.0
     *
     * @param   string  $range  '24h', '7d', or '30d'.
     * @return  array   [ 'labels' => [], 'blocked' => [], 'rate_limited' => [], 'flagged' => [] ]
     */
    public static function chart_series( $range ) {

        if( $range === '24h' ) {
            $rows     = db::get_hourly_stats( 24 );
            $label_fn = function( $r ) { return $r['label']; };
        } else {
            $days     = $range === '7d' ? 7 : 30;
            $rows     = db::get_daily_stats( $days );
            $label_fn = function( $r ) { return date_i18n( 'M j', strtotime( $r['date'] ) ); };
        }

        $out = [ 'labels' => [], 'blocked' => [], 'rate_limited' => [], 'flagged' => [] ];
        foreach( $rows as $r ) {
            $out['labels'][]       = $label_fn( $r );
            $out['blocked'][]      = (int) $r['blocked'];
            $out['rate_limited'][] = (int) $r['rate_limited'];
            $out['flagged'][]      = (int) $r['flagged'];
        }

        return $out;

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

        $theme = $this->get_theme();

        // Documentation is reached from a header button, not the card nav.
        $tabs = [
            'dashboard' => __( 'Dashboard', 'mighty-shield' ),
            'firewall'  => __( 'Firewall', 'mighty-shield' ),
            'whitelist' => __( 'IP Whitelist', 'mighty-shield' ),
            'blocklist' => __( 'IP Blocklist', 'mighty-shield' ),
            'rates'     => __( 'Rate Limits', 'mighty-shield' ),
            'fraud'     => __( 'Fraud Checks', 'mighty-shield' ),
            'logs'      => __( 'Logs', 'mighty-shield' ),
        ];

        $icons  = self::nav_icons();
        $shield = '<svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 4.6-3.2 8.4-8 9.6C7.2 20.4 4 16.6 4 12V6z"></path><path d="M9 12l2 2 4-4"></path></svg>';
        $sun    = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path></svg>';
        $book   = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 3h9l3 3v15H6z"></path><path d="M9 8h6M9 12h6M9 16h4"></path></svg>';
        $doc_url = admin_url( 'admin.php?page=mighty-shield&tab=documentation' );

        echo '<div class="wrap mshield-app" data-theme="' . esc_attr( $theme ) . '">';

        // Header.
        echo '<div class="mshield-header">';
        echo '<div class="ms-brandmark">' . $shield . '</div>';
        echo '<div><div class="mshield-title-row"><h1>' . esc_html__( 'MightyShield', 'mighty-shield' ) . '</h1>';
        echo '<span class="mshield-version">' . esc_html( 'v' . MSHIELD_VERSION ) . '</span></div>';
        echo '<div class="mshield-tagline">' . esc_html__( 'Spam and fraud protection for WooCommerce', 'mighty-shield' ) . '</div></div>';
        echo '<span class="mshield-spacer"></span>';
        $doc_active = $tab === 'documentation' ? ' is-primary' : '';
        echo '<a class="mshield-btn' . esc_attr( $doc_active ) . '" href="' . esc_url( $doc_url ) . '">' . $book . esc_html__( 'Documentation', 'mighty-shield' ) . '</a>';
        echo '<button type="button" id="mshield-theme-toggle" class="mshield-btn">' . $sun . '<span class="ms-theme-label">' . ( $theme === 'dark' ? esc_html__( 'Dark', 'mighty-shield' ) : esc_html__( 'Light', 'mighty-shield' ) ) . '</span></button>';
        echo '</div>';

        // Display any transient notices from redirected actions.
        $notice = get_transient( 'mshield_admin_notice' );
        if( $notice && is_array( $notice ) && count( $notice ) === 3 ) {
            delete_transient( 'mshield_admin_notice' );
            add_settings_error( 'mshield', $notice[0], $notice[1], $notice[2] );
        }

        settings_errors( 'mshield' );

        // Card-grid navigation.
        echo '<div class="mshield-navcards">';
        foreach( $tabs as $key => $label ) {
            $url    = admin_url( 'admin.php?page=mighty-shield&tab=' . $key );
            $active = ( $tab === $key ) ? ' is-active' : '';
            $icon   = isset( $icons[ $key ] ) ? $icons[ $key ] : '';
            echo '<a class="mshield-navcard' . esc_attr( $active ) . '" href="' . esc_url( $url ) . '">' . $icon . '<span>' . esc_html( $label ) . '</span></a>';
        }
        echo '</div>';

        // Render active tab.
        include MSHIELD_PATH . 'admin/views/' . $tab . '.php';

        // Drawer mount (used by the Logs screen).
        echo '<div id="mshield-drawer-root"></div>';

        echo '</div>';

    }

    /**
     * SVG icons for the card-grid navigation, keyed by tab slug.
     *
     * @since   1.5.0
     *
     * @return  array
     */
    private static function nav_icons() {

        $o = '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9">';
        $c = '</svg>';

        return [
            'dashboard'     => $o . '<rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect><rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect>' . $c,
            'firewall'      => $o . '<path d="M3 5h18v14H3z"></path><path d="M3 10h18M9 5v5M15 10v9M6 14h12"></path>' . $c,
            'whitelist'     => $o . '<circle cx="12" cy="12" r="9"></circle><path d="M8 12l3 3 5-6"></path>' . $c,
            'blocklist'     => $o . '<circle cx="12" cy="12" r="9"></circle><path d="M6 6l12 12"></path>' . $c,
            'rates'         => $o . '<path d="M12 13V7"></path><circle cx="12" cy="13" r="8"></circle><path d="M9 2h6"></path>' . $c,
            'fraud'         => $o . '<path d="M10.3 3.6 2.5 17a2 2 0 0 0 1.7 3h15.6a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0z"></path><path d="M12 9v4M12 17h.01"></path>' . $c,
            'logs'          => $o . '<path d="M4 5h16M4 10h16M4 15h10M4 20h7"></path>' . $c,
            'documentation' => $o . '<path d="M6 3h9l3 3v15H6z"></path><path d="M9 8h6M9 12h6M9 16h4"></path>' . $c,
        ];

    }

}
