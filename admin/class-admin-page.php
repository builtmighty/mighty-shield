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
    private const ALLOWED_TABS = [ 'dashboard', 'scoring', 'ai', 'blocking', 'payment', 'access', 'logs', 'documentation' ];

    /**
     * Tabs that were merged into another one in 1.9.0.
     *
     * Old bookmarks and any link out in the wild should land somewhere sensible
     * rather than silently bouncing to the dashboard.
     *
     * @since   1.9.0
     */
    private const MERGED_TABS = [
        'firewall'  => 'access',
        'whitelist' => 'access',
        'blocklist' => 'access',
        'rates'     => 'scoring',
        'fraud'     => 'scoring',
        'checks'    => 'scoring',
    ];

    /**
     * Page slugs that are MightyShield's own screens.
     *
     * Three separate things key off this — the stylesheet, the dark-mode chrome
     * on the surrounding WP admin, and the foreign-notice suppression — and
     * every one of them used to test `mighty-shield` as its own inline string.
     * The Fraud Review queue is registered as `mshield-fraud-review`, which
     * matches none of them, so that screen loaded no CSS at all and rendered as
     * bare WordPress list-table markup. Stated once here instead.
     *
     * @since   1.9.6
     */
    const SCREENS = [ 'mighty-shield', 'mshield-fraud-review' ];

    /**
     * Whether a screen belongs to MightyShield.
     *
     * Accepts an admin hook suffix, a screen ID or a page slug — they all
     * contain the slug, and the three callers each have a different one of the
     * three to hand.
     *
     * @since   1.9.6
     *
     * @param   string  $needle     Hook suffix, screen ID, or page slug.
     * @return  bool
     */
    public static function is_plugin_screen( $needle = '' ) {

        $needle = (string) $needle;

        if( $needle === '' ) {
            $needle = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';
        }

        if( $needle === '' ) return false;

        foreach( self::SCREENS as $slug ) {
            // Anchored on the slug rather than a loose substring: 'mighty-shield'
            // would otherwise also match a third-party screen that happens to
            // mention it.
            if( $needle === $slug || substr( $needle, -strlen( $slug ) - 1 ) === '_' . $slug ) return true;
        }

        return false;

    }

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        add_action( 'admin_menu', [ $this, 'register_menu' ] );
        // Not on MightyShield's own screens — suppress_notices() clears
        // admin_notices there — which is right: this needs to be seen on the
        // dashboard, not only by someone already looking at the settings.
        add_action( 'admin_notices', [ __CLASS__, 'render_store_api_notice' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'admin_init', [ $this, 'handle_actions' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_styles' ] );
        add_action( 'wp_ajax_mshield_set_theme', [ $this, 'ajax_set_theme' ] );
        add_action( 'wp_ajax_mshield_get_ip', [ $this, 'ajax_get_ip' ] );
        add_action( 'wp_ajax_mshield_chart', [ $this, 'ajax_chart' ] );
        add_filter( 'admin_body_class', [ $this, 'admin_body_class' ] );
        // Late, so notices registered by other plugins are already in place.
        add_action( 'in_admin_header', [ $this, 'suppress_notices' ], 1000 );

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
     * Tell the merchant the block checkout is now being checked.
     *
     * Shown once. A default that changes on upgrade should announce itself,
     * particularly one that can start blocking orders.
     *
     * @since   1.9.0
     */
    public static function render_store_api_notice() {

        if( ! get_option( 'mshield_store_api_enabled_notice' ) ) return;
        if( ! current_user_can( 'manage_woocommerce' ) ) return;

        printf(
            '<div class="notice notice-info is-dismissible"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
            esc_html__( 'MightyShield:', 'mighty-shield' ),
            esc_html__( 'Fraud checks now run on the block-based checkout as well as the classic one. Previously they only ran on classic, so stores using the newer checkout were unprotected. Each check still does exactly what you have it set to do.', 'mighty-shield' ),
            esc_url( admin_url( 'admin.php?page=mighty-shield&tab=blocking' ) ),
            esc_html__( 'Review the setting', 'mighty-shield' )
        );

        delete_option( 'mshield_store_api_enabled_notice' );

    }

    /**
     * Register settings with sanitize callbacks.
     *
     * @since   1.0.0
     */
    public function register_settings() {

        // mshield_enabled is deliberately NOT registered to a settings group.
        // It is owned by the dashboard's protection control, which sets it
        // directly. Registering it here while no field submits it would make
        // options.php write null over it on every save of that group.
        //
        // The mshield_firewall group is gone. Its three access settings moved to
        // Blocking, where they belong -- they decide what gets blocked -- and
        // log retention moved to Logs. A group must be registered where its
        // FIELDS are, or options.php writes null over every option in it.

        // --- Logs tab ---
        register_setting( 'mshield_logs', 'mshield_log_retention_days', [
            'sanitize_callback' => function( $value ) { return max( 1, min( 365, absint( $value ) ) ); },
        ] );

        // --- Scoring tab: one weight, floor and toggle per signal ---
        foreach( \MightyShield\Includes\signals::CATALOG as $key => $signal ) {

            register_setting( 'mshield_scoring', 'mshield_sig_' . $key . '_enabled', [
                'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
            ] );

            register_setting( 'mshield_scoring', 'mshield_sig_' . $key . '_weight', [
                'sanitize_callback' => function( $value ) {
                    // Negative weights are legal: they earn trust back.
                    return max( -100.0, min( 100.0, (float) $value ) );
                },
            ] );

            register_setting( 'mshield_scoring', 'mshield_sig_' . $key . '_floor', [
                'sanitize_callback' => function( $value ) {
                    return ( $value === 'none' || \MightyShield\Includes\risk_levels::exists( $value ) ) ? $value : 'none';
                },
            ] );

        }

        // Per-signal configuration now lives on its signal's row, so it has to
        // be registered against the Scoring group or options.php will refuse to
        // save it. Sanitising is driven by the field type declared alongside it.
        foreach( \MightyShield\Includes\signals::all_fields() as $option => $field ) {

            $type = $field['type'];
            $min  = isset( $field['min'] ) ? $field['min'] : null;
            $max  = isset( $field['max'] ) ? $field['max'] : null;
            $choices = isset( $field['choices'] ) ? array_keys( $field['choices'] ) : [];

            register_setting( 'mshield_scoring', $option, [
                'sanitize_callback' => function( $value ) use ( $type, $min, $max, $choices, $option ) {

                    if( $type === 'check' )  return $value === 'yes' ? 'yes' : 'no';

                    if( $type === 'number' ) {
                        $n = absint( $value );
                        if( $min !== null ) $n = max( $min, $n );
                        if( $max !== null ) $n = min( $max, $n );
                        return $n;
                    }

                    if( $type === 'select' || $type === 'radios' ) {
                        return \in_array( $value, $choices, true ) ? $value : ( $choices[0] ?? '' );
                    }

                    if( $type === 'password' ) {
                        // A masked field submits empty when untouched. Keep the
                        // stored key rather than wiping it.
                        return empty( $value ) ? get_option( $option, '' ) : sanitize_text_field( $value );
                    }

                    if( $type === 'textarea' ) return sanitize_textarea_field( $value );

                    return sanitize_text_field( $value );

                },
            ] );

        }

        // --- Blocking tab settings ---
        // mshield_enforcement_mode is deliberately NOT registered to a settings
        // group. Like mshield_enabled, it is owned by the dashboard's
        // protection control. Registering it here with no field to submit it
        // would make options.php write null over it on every Blocking save,
        // and the sanitiser would read that null as 'observe'.

        foreach( array_keys( \MightyShield\Includes\risk_levels::DEFAULT_THRESHOLDS ) as $level ) {
            register_setting( 'mshield_blocking', 'mshield_level_' . $level . '_threshold', [
                'sanitize_callback' => function( $value ) { return max( 1, min( 100, absint( $value ) ) ); },
            ] );
        }

        // One action and one AI toggle per configurable level.
        foreach( \MightyShield\Includes\risk_levels::CONFIGURABLE as $level ) {

            register_setting( 'mshield_blocking', 'mshield_level_' . $level . '_action', [
                'sanitize_callback' => function( $value ) use ( $level ) {

                    $default = \MightyShield\Includes\risk_levels::LADDER[ $level ]['action'];

                    if( ! \MightyShield\Includes\actions::exists( $value ) ) return $default;

                    // The select renders unavailable options disabled, but a
                    // disabled option can still be posted by hand. Refuse to
                    // store an action no gateway can perform — it would read as
                    // configured protection that silently falls back forever.
                    if( ! \MightyShield\Includes\actions::is_available( $value ) ) return $default;

                    return $value;

                },
            ] );

            register_setting( 'mshield_blocking', 'mshield_level_' . $level . '_ai', [
                'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
            ] );

        }
        // Moved here from the retired mshield_firewall group in 1.9.3: these
        // decide which requests are blocked, which is what this page is about.
        register_setting( 'mshield_blocking', 'mshield_block_store_api', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_blocking', 'mshield_firewall_mode', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'whitelist', 'blocklist' ], true ) ? $value : 'whitelist';
            },
        ] );
        register_setting( 'mshield_blocking', 'mshield_store_api_checks', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        // --- Bot challenge ---
        // Moved out of the mshield_fraud group (whose tab was merged away, so
        // it was registered but never submitted) and out of the per-signal
        // Scoring loop. The fields live on Blocking now, because the challenge
        // guards login, registration, lost password and comments as well as
        // checkout -- it stopped being a scoring detail.
        register_setting( 'mshield_blocking', 'mshield_captcha_provider', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'off', 'turnstile', 'recaptcha_v3' ], true ) ? $value : 'off';
            },
        ] );
        register_setting( 'mshield_blocking', 'mshield_captcha_site_key', [
            'sanitize_callback' => 'sanitize_text_field',
        ] );
        register_setting( 'mshield_blocking', 'mshield_captcha_secret_key', [
            'sanitize_callback' => function( $value ) {
                // A masked field posts empty when untouched. Keep the stored
                // key rather than wiping it.
                return empty( $value ) ? get_option( 'mshield_captcha_secret_key', '' ) : sanitize_text_field( $value );
            },
        ] );
        // mshield_captcha_action is retired and deliberately NOT registered.
        // The captcha_failed signal on Scoring already floors a failed
        // challenge to Rejected, so this was a second control for one outcome.
        // Left registered with no field, options.php would null it on every
        // Blocking save.

        foreach( \MightyShield\Protection\challenge::SURFACES as $surface => $option ) {
            register_setting( 'mshield_blocking', $option, [
                'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
            ] );
        }

        register_setting( 'mshield_blocking', 'mshield_card_hold_on_mismatch', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_blocking', 'mshield_tarpit_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_blocking', 'mshield_tarpit_min_ms', [
            'sanitize_callback' => function( $value ) { return max( 0, min( 30000, absint( $value ) ) ); },
        ] );
        register_setting( 'mshield_blocking', 'mshield_tarpit_max_ms', [
            'sanitize_callback' => function( $value ) { return max( 0, min( 30000, absint( $value ) ) ); },
        ] );
        register_setting( 'mshield_blocking', 'mshield_refusal_note', [
            'sanitize_callback' => [ $this, 'sanitize_refusal_note' ],
        ] );

        register_setting( 'mshield_ai', 'mshield_ai_daily_cap', [
            'sanitize_callback' => function( $value ) { return max( 0, absint( $value ) ); },
        ] );
        register_setting( 'mshield_ai', 'mshield_ai_redact_pii', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        // Which levels get an AI review is now a per-level checkbox on the Blocking
        // tab, stored as mshield_level_<level>_ai.

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

        // Bot challenge (CAPTCHA).
        // The mshield_fraud group is gone. Its tab was merged into Scoring in
        // 1.9.0 and admin/views/fraud.php has been unreachable ever since, so
        // nothing submitted it -- but it re-registered twenty options that
        // already belong to Scoring, and a later registration wins the group in
        // WordPress's registry. mshield_address_sensitivity reported itself as
        // living on a tab that does not exist.
        //
        // Removing the registrations changes no behaviour: settings::get()
        // reads options directly and does not consult the registry. The
        // per-layer *_action options (honeypot, timing, zip/state, smarty,
        // fingerprint) went down with fraud.php and still have no UI -- they sit
        // at their defaults. Worth a screen of their own eventually.

        // --- AI Detection tab settings ---
        register_setting( 'mshield_ai', 'mshield_ai_enabled', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_ai', 'mshield_ai_provider', [
            'sanitize_callback' => function( $value ) {
                return \in_array( $value, [ 'anthropic', 'openai', 'gemini' ], true ) ? $value : 'anthropic';
            },
        ] );
        register_setting( 'mshield_ai', 'mshield_ai_anthropic_key', [
            'sanitize_callback' => function( $value ) {
                if( empty( $value ) ) {
                    return get_option( 'mshield_ai_anthropic_key', '' );
                }
                return sanitize_text_field( $value );
            },
        ] );
        register_setting( 'mshield_ai', 'mshield_ai_anthropic_model', [
            'sanitize_callback' => 'sanitize_text_field',
        ] );
        register_setting( 'mshield_ai', 'mshield_ai_openai_key', [
            'sanitize_callback' => function( $value ) {
                if( empty( $value ) ) {
                    return get_option( 'mshield_ai_openai_key', '' );
                }
                return sanitize_text_field( $value );
            },
        ] );
        register_setting( 'mshield_ai', 'mshield_ai_openai_org', [
            'sanitize_callback' => 'sanitize_text_field',
        ] );
        register_setting( 'mshield_ai', 'mshield_ai_openai_model', [
            'sanitize_callback' => 'sanitize_text_field',
        ] );
        register_setting( 'mshield_ai', 'mshield_ai_gemini_key', [
            'sanitize_callback' => function( $value ) {
                if( empty( $value ) ) {
                    return get_option( 'mshield_ai_gemini_key', '' );
                }
                return sanitize_text_field( $value );
            },
        ] );
        register_setting( 'mshield_ai', 'mshield_ai_gemini_model', [
            'sanitize_callback' => 'sanitize_text_field',
        ] );
        // The AI no longer decides the outcome -- it raises the level, and the
        // level's action decides. Registered-but-unsubmitted would null this on
        // every AI-tab save.
        // Retired in 1.9.2 and deliberately NOT registered: mshield_ai_method,
        // _timing, _sensitivity, the four _sig_* toggles, and
        // _rating_threshold. Which orders get reviewed is per risk level on
        // Blocking; reviews always run during checkout; the four signal
        // toggles are the Scoring tab's per-signal switches; and the rating
        // caps the trust score rather than crossing a threshold.
        //
        // mshield_ai_velocity_orders / _days / _high_value_amount are not
        // registered here either. They ARE still live, registered once against
        // the Scoring group where their fields are. Registering a second copy
        // to this group meant every AI-tab save wrote null over whatever was
        // set on Scoring.
        register_setting( 'mshield_ai', 'mshield_ai_direction', [
            'sanitize_callback' => function( $value ) {
                // Anything unrecognised falls to the conservative arm: an AI
                // verdict that can hand trust back is opt-in.
                return \in_array( $value, [ 'lower', 'both' ], true ) ? $value : 'lower';
            },
        ] );

        register_setting( 'mshield_ai', 'mshield_ai_notify_admin', [
            'sanitize_callback' => [ $this, 'sanitize_checkbox' ],
        ] );
        register_setting( 'mshield_ai', 'mshield_ai_notify_emails', [
            'sanitize_callback' => [ $this, 'sanitize_email_list' ],
        ] );

    }

    /**
     * Sanitize a comma-delimited list of email addresses.
     *
     * Invalid entries are dropped individually so one typo cannot discard the
     * whole list.
     *
     * @since   1.8.0
     *
     * @param   mixed   $value  Submitted value.
     * @return  string  Comma-delimited list of valid addresses.
     */
    public function sanitize_email_list( $value ) {

        if( ! is_string( $value ) ) return '';

        $valid = [];

        foreach( explode( ',', $value ) as $email ) {

            $email = sanitize_email( trim( $email ) );

            if( ! empty( $email ) && is_email( $email ) && ! \in_array( $email, $valid, true ) ) {
                $valid[] = $email;
            }

        }

        return implode( ', ', $valid );

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
     * Tags the refusal note may use.
     *
     * Not wp_kses_post, and the difference matters. This note is shown to the
     * customer by two different renderers: the classic checkout runs it through
     * wc_kses_notice(), which is wp_kses_post, while the block checkout runs it
     * through WooCommerce's own sanitizeHTML(), whose default allowlist is
     * exactly the list below. Allowing anything wider would mean a merchant
     * pasting a list, seeing it work on one checkout, and never learning it
     * silently vanished on the other.
     *
     * @since   2.0.0
     *
     * @return  array   wp_kses allowed-HTML array.
     */
    public static function refusal_note_tags() {

        $link = [ 'href' => true, 'title' => true, 'target' => true, 'rel' => true, 'name' => true, 'download' => true ];

        return [
            'a'      => $link,
            'b'      => [],
            'strong' => [],
            'i'      => [],
            'em'     => [],
            'p'      => [],
            'br'     => [],
            'abbr'   => [ 'title' => true ],
        ];

    }

    /**
     * Sanitize the merchant's refusal note.
     *
     * @since   2.0.0
     *
     * @param   string  $value
     * @return  string
     */
    public function sanitize_refusal_note( $value ) {

        // A group save posts every registered option, and an option with no
        // field on the page arrives as null. Coercing first keeps wp_kses from
        // being handed one.
        return trim( wp_kses( (string) $value, self::refusal_note_tags() ) );

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
                set_transient( 'mshield_admin_notice', [ 'ip_removed', __( 'Allowlist entry removed.', 'mighty-shield' ), 'success' ], 30 );
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

        // Protection state (dashboard hero control). Three states across two
        // options, set explicitly rather than cycled: the control shows which
        // one you are picking, so there is nothing to guess at.
        if( isset( $_GET['mshield_set_state'] ) && isset( $_GET['_wpnonce'] ) ) {

            $state = sanitize_key( wp_unslash( $_GET['mshield_set_state'] ) );

            if( wp_verify_nonce( $_GET['_wpnonce'], 'mshield_set_state_' . $state ) ) {

                // Anything unrecognised falls to the safest of the three rather
                // than to "enforce" — a bad nonce or a mangled URL must never
                // start refusing customers.
                $states = [
                    'disabled'  => [ 'no',  null,      __( 'Protection disabled. No orders are being checked.', 'mighty-shield' ) ],
                    'observing' => [ 'yes', 'observe', __( 'Now observing. Orders are rated and recorded, but the rating is not acted on.', 'mighty-shield' ) ],
                    'active'    => [ 'yes', 'enforce', __( 'Protection active. Orders are now blocked and held by their rating.', 'mighty-shield' ) ],
                ];

                if( isset( $states[ $state ] ) ) {

                    list( $enabled, $mode, $message ) = $states[ $state ];

                    update_option( 'mshield_enabled', $enabled );

                    // Disabling leaves the mode untouched, so turning protection
                    // back on returns it to whichever mode it was last in.
                    if( $mode !== null ) update_option( 'mshield_enforcement_mode', $mode );

                    set_transient( 'mshield_admin_notice', [ 'protection', $message, 'success' ], 30 );

                }

            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=dashboard' ) );
            exit;

        }

        // Apply a scoring profile. An action rather than a settings field: it
        // rewrites every trust cost at once, and it sits above the form on
        // Scoring rather than inside it, so it applies on click rather than
        // waiting for Save at the bottom of a long page.
        if( isset( $_GET['mshield_set_profile'] ) && isset( $_GET['_wpnonce'] ) ) {

            $profile = sanitize_key( wp_unslash( $_GET['mshield_set_profile'] ) );

            if( wp_verify_nonce( $_GET['_wpnonce'], 'mshield_set_profile_' . $profile )
                && \MightyShield\Includes\scoring_profiles::apply( $profile ) ) {

                set_transient( 'mshield_admin_notice', [
                    'profile',
                    sprintf(
                        /* translators: %s: profile name, e.g. Strict. */
                        __( 'Scoring set to %s. Every trust cost below now follows that profile, and you can still change any of them.', 'mighty-shield' ),
                        \MightyShield\Includes\scoring_profiles::label( $profile )
                    ),
                    'success',
                ], 30 );

            }

            // An unrecognised or unsigned profile changes nothing and lands
            // back on the tab, rather than falling through to the strictest.
            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=scoring' ) );
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
                    : sprintf( __( '%d IP addresses added to the allowlist.', 'mighty-shield' ), $count );
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
            return [ 'wl_added', sprintf( __( 'IP %s added to allowlist.', 'mighty-shield' ), $value ), 'success' ];

        }

        if( $type === 'email' ) {

            if( ! is_email( $value ) ) {
                return [ 'wl_invalid', __( 'Invalid email address.', 'mighty-shield' ), 'error' ];
            }
            ip_whitelist::add_entry( 'email', $value, $label );
            return [ 'wl_added', sprintf( __( 'Email %s added to allowlist.', 'mighty-shield' ), $value ), 'success' ];

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
            return [ 'wl_added', sprintf( __( 'User %s added to allowlist.', 'mighty-shield' ), $user->user_login ), 'success' ];

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
            return [ 'wl_added', sprintf( __( 'Role %s added to allowlist.', 'mighty-shield' ), $name ), 'success' ];

        }

        return [ 'wl_invalid', __( 'Invalid allowlist entry type.', 'mighty-shield' ), 'error' ];

    }

    /**
     * Enqueue admin styles.
     *
     * @since   1.0.0
     */
    public function enqueue_styles( $hook ) {

        if( ! self::is_plugin_screen( $hook ) ) return;

        self::enqueue_app_assets();

    }

    /**
     * The design system's CSS and JS.
     *
     * Split out of enqueue_styles() so the order-screen panel can load the same
     * assets. Its screen carries no `mighty-shield` page slug under either
     * storage, so it cannot pass the gate above, and duplicating the enqueue
     * would mean two lists of nonces drifting apart.
     *
     * wp_enqueue_* is idempotent, so a screen that somehow matched both gates
     * still registers each handle once.
     *
     * @since   1.9.5
     */
    public static function enqueue_app_assets() {

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
                'whitelistIp' => __( 'Allowlist IP', 'mighty-shield' ),
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
     * @return  string  'system' (default — follows the OS), 'light', or 'dark'.
     */
    private function get_theme() {

        $theme = get_user_meta( get_current_user_id(), 'mshield_admin_theme', true );
        return \in_array( $theme, [ 'light', 'dark' ], true ) ? $theme : 'system';

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

        if( self::is_plugin_screen() ) {
            $theme = $this->get_theme();
            // Explicit dark repaints the chrome outright; "system" defers to a
            // prefers-color-scheme media query in the CSS.
            if( $theme === 'dark' ) {
                $classes .= ' mshield-theme-dark';
            } elseif( $theme === 'system' ) {
                $classes .= ' mshield-theme-system';
            }
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
    /**
     * Strip foreign admin notices on the MightyShield screen.
     *
     * WordPress and other plugins inject notices into the top of any .wrap
     * element, which is this app's own wrapper — the result pushes the header
     * around and breaks the layout. MightyShield's own messages are re-rendered
     * inside the app instead (see render_page and render_degraded_banners), so
     * nothing of ours is lost. Scoped to this screen only.
     *
     * @since   1.8.0
     */
    public function suppress_notices() {

        $screen = get_current_screen();
        if( ! $screen || ! self::is_plugin_screen( $screen->id ) ) return;

        remove_all_actions( 'admin_notices' );
        remove_all_actions( 'all_admin_notices' );

    }

    /**
     * Render MightyShield's degraded warnings inside the app chrome.
     *
     * These normally ride admin_notices, which suppress_notices() clears on this
     * screen — and this is the page where they matter most.
     *
     * @since   1.8.0
     */
    private function render_degraded_banners() {

        $sources = [
            'mshield_ai_degraded'      => __( 'AI order review is unavailable and orders are NOT being reviewed. Last error: %s', 'mighty-shield' ),
            'mshield_smarty_degraded'  => __( 'Address verification (Smarty) is degraded and has fallen back to a basic ZIP/State check. Last error: %s', 'mighty-shield' ),
            'mshield_captcha_degraded' => __( 'The bot challenge is misconfigured and is failing open so it does not block checkout. Last error: %s', 'mighty-shield' ),
        ];

        foreach( $sources as $option => $template ) {

            $degraded = get_option( $option );
            if( empty( $degraded ) || empty( $degraded['time'] ) ) continue;
            if( ( time() - (int) $degraded['time'] ) > DAY_IN_SECONDS ) continue;

            printf(
                '<div class="mshield-banner" style="margin-bottom:18px;background:rgba(214,54,56,.08);border-color:rgba(214,54,56,.28);"><div><strong>%s</strong> %s</div></div>',
                esc_html__( 'MightyShield:', 'mighty-shield' ),
                esc_html( sprintf( $template, isset( $degraded['message'] ) ? $degraded['message'] : '' ) )
            );

        }

    }

    public static function radios( $name, $options, $current, $disabled = [] ) {

        echo '<div class="mshield-radios">';
        foreach( $options as $value => $label ) {
            $off = \in_array( (string) $value, array_map( 'strval', $disabled ), true );
            $is  = ( ! $off && (string) $current === (string) $value ) ? ' is-checked' : '';
            $is .= $off ? ' is-disabled' : '';
            echo '<label class="mshield-radio' . esc_attr( $is ) . '">';
            echo '<input type="radio" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '" ' . checked( $current, $value, false ) . disabled( $off, true, false ) . ' />';
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

        $requested = isset( $_POST['theme'] ) ? sanitize_text_field( wp_unslash( $_POST['theme'] ) ) : '';
        $theme     = \in_array( $requested, [ 'light', 'dark', 'system' ], true ) ? $requested : 'system';
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
        if( isset( self::MERGED_TABS[ $tab ] ) ) {
            $tab = self::MERGED_TABS[ $tab ];
        }

        if( ! \in_array( $tab, self::ALLOWED_TABS, true ) ) {
            $tab = 'dashboard';
        }

        self::shell_open( [ 'tab' => $tab ] );

        // Render active tab.
        include MSHIELD_PATH . 'admin/views/' . $tab . '.php';

        self::shell_close();

    }

    /**
     * Open a MightyShield page: wrapper, header, notices, navigation.
     *
     * Extracted so the Fraud Review queue wears the same chrome. It is
     * registered under WooCommerce with its own slug rather than as a tab, and
     * duplicating a dozen lines of header markup there is how two screens that
     * are meant to look identical stop looking identical.
     *
     * @since   1.9.6
     *
     * @param   array   $args {
     *     @type string  tab   Active tab slug, or '' on a screen that is not a
     *                         tab. Drives the nav cards and the Documentation
     *                         button's active state.
     *     @type bool    nav   Whether to render the tab cards. Default true when
     *                         a tab is given.
     *     @type array   back  Optional [ url, label ] shown in place of the nav.
     * }
     */
    public static function shell_open( $args = [] ) {

        $tab   = isset( $args['tab'] ) ? (string) $args['tab'] : '';
        $nav   = isset( $args['nav'] ) ? (bool) $args['nav'] : ( $tab !== '' );
        $back  = isset( $args['back'] ) ? $args['back'] : null;
        $theme = self::current_theme();

        $shield  = '<svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 4.6-3.2 8.4-8 9.6C7.2 20.4 4 16.6 4 12V6z"></path><path d="M9 12l2 2 4-4"></path></svg>';
        $sun     = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path></svg>';
        $moon    = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"></path></svg>';
        $monitor = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"></rect><path d="M8 20h8M12 16v4"></path></svg>';
        $book    = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 3h9l3 3v15H6z"></path><path d="M9 8h6M9 12h6M9 16h4"></path></svg>';

        $theme_icons  = [ 'system' => $monitor, 'light' => $sun, 'dark' => $moon ];
        $theme_labels = [ 'system' => esc_html__( 'System', 'mighty-shield' ), 'light' => esc_html__( 'Light', 'mighty-shield' ), 'dark' => esc_html__( 'Dark', 'mighty-shield' ) ];
        $doc_url      = admin_url( 'admin.php?page=mighty-shield&tab=documentation' );

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
        echo '<button type="button" id="mshield-theme-toggle" class="mshield-btn"><span class="ms-theme-icon">' . $theme_icons[ $theme ] . '</span><span class="ms-theme-label">' . $theme_labels[ $theme ] . '</span></button>';
        echo '</div>';

        self::render_notices();

        if( $nav ) {

            $tabs  = self::nav_tabs();
            $icons = self::nav_icons();

            echo '<div class="mshield-navcards">';
            foreach( $tabs as $key => $label ) {
                $url    = admin_url( 'admin.php?page=mighty-shield&tab=' . $key );
                $active = ( $tab === $key ) ? ' is-active' : '';
                $icon   = isset( $icons[ $key ] ) ? $icons[ $key ] : '';
                echo '<a class="mshield-navcard' . esc_attr( $active ) . '" href="' . esc_url( $url ) . '">' . $icon . '<span>' . esc_html( $label ) . '</span></a>';
            }
            echo '</div>';

        } elseif( is_array( $back ) && count( $back ) === 2 ) {

            printf(
                '<p class="mshield-back"><a href="%s">&larr; %s</a></p>',
                esc_url( $back[0] ),
                esc_html( $back[1] )
            );

        }

    }

    /**
     * Close a MightyShield page.
     *
     * @since   1.9.6
     */
    public static function shell_close() {

        // Drawer mount (used by the Logs screen).
        echo '<div id="mshield-drawer-root"></div>';

        echo '</div>';

    }

    /**
     * MightyShield's own messages, rendered inside the app chrome.
     *
     * Foreign notices are stripped by suppress_notices(), because WordPress
     * injects them into the top of any .wrap element — which is this app's own
     * wrapper — and they shove the header around. That suppression applies to
     * every plugin screen, so anything of ours that would have gone out as an
     * admin notice has to be re-rendered here or it is simply swallowed.
     *
     * @since   1.9.6
     */
    public static function render_notices() {

        // First, above everything: if the firewall is closing the checkout, that
        // is the only thing on this screen that matters.
        self::render_checkout_conflict();

        $notice = get_transient( 'mshield_admin_notice' );

        if( $notice && is_array( $notice ) && count( $notice ) === 3 ) {
            delete_transient( 'mshield_admin_notice' );
            printf(
                '<div class="mshield-banner" style="margin-bottom:18px;%s"><div>%s</div></div>',
                $notice[2] === 'error' ? 'background:rgba(214,54,56,.08);border-color:rgba(214,54,56,.28);' : '',
                esc_html( $notice[1] )
            );
        }

        if( isset( $_GET['settings-updated'] ) && $_GET['settings-updated'] ) {
            printf(
                '<div class="mshield-banner" style="margin-bottom:18px;"><div>%s</div></div>',
                esc_html__( 'Settings saved.', 'mighty-shield' )
            );
        }

        ( new self() )->render_degraded_banners();

    }

    /**
     * The three protection states, in severity order.
     *
     * Three, not two: being switched on and actually acting on the trust
     * rating are different things. In observe mode the rating is recorded and
     * nothing is enforced, so anything reporting only mshield_enabled claims
     * protection the plugin is deliberately not providing.
     *
     * Shared by the dashboard hero, its three-way control and the WordPress
     * dashboard widget — three places that describe the same state, which is
     * exactly the shape of thing that drifts when each keeps its own copy.
     *
     * @since   1.9.6
     *
     * @return  array   key => [ label, hint, icon ]
     */
    public static function protection_states() {

        return [
            'disabled'  => [
                'label' => __( 'Disabled', 'mighty-shield' ),
                'hint'  => __( 'Disabled. No orders are checked', 'mighty-shield' ),
                // Power symbol.
                'icon'  => '<path d="M12 4v8"></path><path d="M7.5 6.6a7 7 0 1 0 9 0"></path>',
            ],
            'observing' => [
                'label' => __( 'Observing', 'mighty-shield' ),
                'hint'  => __( 'Observing. Orders are rated and recorded, but not acted on', 'mighty-shield' ),
                // Binoculars.
                'icon'  => '<circle cx="6.5" cy="16" r="3.5"></circle><circle cx="17.5" cy="16" r="3.5"></circle>'
                         . '<path d="M10 16h4"></path>'
                         . '<path d="M4.6 13.2 5.6 5A1.5 1.5 0 0 1 7.1 3.6h1A1.5 1.5 0 0 1 9.6 5l.4 8.2"></path>'
                         . '<path d="M19.4 13.2 18.4 5A1.5 1.5 0 0 0 16.9 3.6h-1A1.5 1.5 0 0 0 14.4 5L14 13.2"></path>',
            ],
            'active'    => [
                'label' => __( 'Active', 'mighty-shield' ),
                'hint'  => __( 'Active. Orders are blocked and held by their rating', 'mighty-shield' ),
                // Shield, matching the hero icon.
                'icon'  => '<path d="M12 3l8 3v6c0 4.6-3.2 8.4-8 9.6C7.2 20.4 4 16.6 4 12V6z"></path><path d="M9 12l2 2 4-4"></path>',
            ],
        ];

    }

    /**
     * Which state protection is in right now, and how to draw it.
     *
     * @since   1.9.6
     *
     * @return  array   key, label, hint, icon, title, meta, pill, hero
     */
    public static function protection_state() {

        $enabled   = settings::get( 'mshield_enabled' ) === 'yes';
        $enforcing = $enabled && \MightyShield\Includes\response::is_enforcing();

        $key    = $enabled ? ( $enforcing ? 'active' : 'observing' ) : 'disabled';
        $states = self::protection_states();

        // Observe still says "Shields are up": the individual checks really do
        // block. What is not happening is the trust rating being acted on, and
        // that is the only thing the meta line claims.
        $meta = [
            'active'    => __( 'MightyShield is actively protecting your store.', 'mighty-shield' ),
            'observing' => __( 'Trust ratings are being recorded, not enforced.', 'mighty-shield' ),
            'disabled'  => __( 'MightyShield is not checking any orders.', 'mighty-shield' ),
        ];

        $pill = [ 'active' => 'is-ok', 'observing' => 'is-rate', 'disabled' => 'is-blocked' ];
        $hero = [ 'active' => '', 'observing' => 'is-observing', 'disabled' => 'is-off' ];

        return array_merge( $states[ $key ], [
            'key'       => $key,
            'enabled'   => $enabled,
            'enforcing' => $enforcing,
            'observing' => $enabled && ! $enforcing,
            'title'     => $enabled
                ? __( 'Shields are up', 'mighty-shield' )
                : __( 'Shields are down', 'mighty-shield' ),
            'meta'      => $meta[ $key ],
            'pill'      => $pill[ $key ],
            'hero'      => $hero[ $key ],
        ] );

    }

    /**
     * The tab cards, in the order things actually happen.
     *
     * Documentation is reached from a header button, not the card nav.
     *
     * @since   1.9.6
     *
     * @return  array   slug => label
     */
    private static function nav_tabs() {

        return [
            'dashboard' => __( 'Dashboard', 'mighty-shield' ),
            'scoring'   => __( 'Scoring', 'mighty-shield' ),
            // Between Scoring and Blocking: that is the order things actually
            // happen in. Scoring rates the order, AI review can revise the
            // rating, Blocking acts on whatever it ends up being.
            'ai'        => __( 'AI Review', 'mighty-shield' ),
            'blocking'  => __( 'Blocking', 'mighty-shield' ),
            'payment'   => __( 'Payment', 'mighty-shield' ),
            'access'    => __( 'Access', 'mighty-shield' ),
            'logs'      => __( 'Logs', 'mighty-shield' ),
        ];

    }

    /**
     * Whether the Store API firewall is currently closing the checkout.
     *
     * In whitelist mode the firewall denies /wc/store/v1/cart and
     * /wc/store/v1/checkout to everyone who is not explicitly allowlisted. On a
     * classic-checkout store that is exactly right and costs a shopper nothing.
     * On a block checkout those are the endpoints the checkout is BUILT from,
     * so the same setting quietly closes the shop: every real customer gets a
     * 403 and an empty cart, and nothing anywhere says why.
     *
     * The settings are doing what they were asked to do, so this is a warning
     * rather than a correction. What is not acceptable is that the plugin can
     * take a store offline without mentioning it.
     *
     * @since   1.9.7
     *
     * @return  bool
     */
    public static function checkout_conflict() {

        static $answer = null;

        if( $answer !== null ) return $answer;

        $answer = false;

        // Never on the front end: has_block() loads the checkout page's post
        // content, which is wasted work on every shopper request for a warning
        // only an administrator can see or act on.
        if( ! is_admin() ) return $answer;

        if( settings::get( 'mshield_block_store_api' ) !== 'yes' )    return $answer;
        if( settings::get( 'mshield_firewall_mode' ) !== 'whitelist' ) return $answer;

        if( ! function_exists( 'wc_get_page_id' ) || ! function_exists( 'has_block' ) ) return $answer;

        $page = (int) wc_get_page_id( 'checkout' );
        if( $page <= 0 ) return $answer;

        $answer = has_block( 'woocommerce/checkout', $page );

        return $answer;

    }

    /**
     * The warning itself, so both screens say it the same way.
     *
     * @since   1.9.7
     */
    public static function render_checkout_conflict() {

        if( ! self::checkout_conflict() ) return;

        printf(
            '<div class="mshield-banner is-danger" style="margin-bottom:18px"><div><strong>%s</strong> %s <a href="%s">%s</a></div></div>',
            esc_html__( 'Your checkout is closed to customers.', 'mighty-shield' ),
            esc_html__( 'This store uses the block checkout, which is built on the Store API, and the Store API Firewall is set to Allowlist. That combination refuses the cart and the checkout for everyone who is not on your allowlist, so no customer can buy. Set the firewall to Blocklist, or turn it off.', 'mighty-shield' ),
            esc_url( admin_url( 'admin.php?page=mighty-shield&tab=blocking' ) ),
            esc_html__( 'Change it on Blocking', 'mighty-shield' )
        );

    }

    /**
     * The current user's admin theme, callable without an instance.
     *
     * @since   1.9.6
     *
     * @return  string  'system', 'light' or 'dark'.
     */
    public static function current_theme() {

        $theme = get_user_meta( get_current_user_id(), 'mshield_admin_theme', true );

        return \in_array( $theme, [ 'light', 'dark', 'system' ], true ) ? $theme : 'system';

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
            // Sliders — the scoring tab is where weights get tuned.
            'scoring'       => $o . '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"></path><path d="M1 14h6M9 8h6M17 16h6"></path>' . $c,
            // A shield with a slash — the blocking tab is where refusals live.
            'blocking'      => $o . '<path d="M12 3l8 3v6c0 4.6-3.2 8.4-8 9.6C7.2 20.4 4 16.6 4 12V6z"></path><path d="M9 12h6"></path>' . $c,
            // Sliders for Checks (per-layer configuration).
            'checks'        => $o . '<path d="M20 6H9M14 12H4M18 18H7"></path><circle cx="6" cy="6" r="2"></circle><circle cx="17" cy="12" r="2"></circle><circle cx="4" cy="18" r="2"></circle>' . $c,
            // A card, for Payment.
            'payment'       => $o . '<rect x="2" y="5" width="20" height="14" rx="2"></rect><path d="M2 10h20"></path>' . $c,
            // A key, for Access.
            'access'        => $o . '<circle cx="7.5" cy="15.5" r="3.5"></circle><path d="M10 13L20 3M17 6l2 2M14 9l2 2"></path>' . $c,
            'firewall'      => $o . '<path d="M3 5h18v14H3z"></path><path d="M3 10h18M9 5v5M15 10v9M6 14h12"></path>' . $c,
            'whitelist'     => $o . '<circle cx="12" cy="12" r="9"></circle><path d="M8 12l3 3 5-6"></path>' . $c,
            'blocklist'     => $o . '<circle cx="12" cy="12" r="9"></circle><path d="M6 6l12 12"></path>' . $c,
            'rates'         => $o . '<path d="M12 13V7"></path><circle cx="12" cy="13" r="8"></circle><path d="M9 2h6"></path>' . $c,
            'fraud'         => $o . '<path d="M10.3 3.6 2.5 17a2 2 0 0 0 1.7 3h15.6a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0z"></path><path d="M12 9v4M12 17h.01"></path>' . $c,
            'ai'            => $o . '<path d="M11 3l1.7 4.3L17 9l-4.3 1.7L11 15l-1.7-4.3L5 9l4.3-1.7z"></path><path d="M17.5 14l.9 2.1 2.1.9-2.1.9-.9 2.1-.9-2.1-2.1-.9 2.1-.9z"></path>' . $c,
            'logs'          => $o . '<path d="M4 5h16M4 10h16M4 15h10M4 20h7"></path>' . $c,
            'documentation' => $o . '<path d="M6 3h9l3 3v15H6z"></path><path d="M9 8h6M9 12h6M9 16h4"></path>' . $c,
        ];

    }

}
