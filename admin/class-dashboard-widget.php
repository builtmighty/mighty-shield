<?php
/**
 * The MightyShield widget on the WordPress dashboard.
 *
 * Three things, in the order a shop owner needs them: is protection on, what
 * has it been doing, and is anything waiting for me. Nothing here is a control
 * except the button at the bottom — the widget reports, and hands off to the
 * screen that acts.
 *
 * Everything it draws is borrowed rather than reimplemented: the status stripe
 * from admin_page::protection_state(), the chart from the same JSON-seeded
 * markup and the same initChart() the dashboard uses, the pending count from
 * fraud_review. A widget that restated any of it would be a fourth place for
 * "what does Observing look like" to drift.
 *
 * @package MightyShield
 * @since   1.9.6
 */
namespace MightyShield\Admin;

class dashboard_widget {

    /**
     * Widget ID.
     *
     * @since   1.9.6
     */
    const ID = 'mshield_dashboard_widget';

    /**
     * Construct.
     *
     * @since   1.9.6
     */
    public function __construct() {

        add_action( 'wp_dashboard_setup', [ $this, 'register' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue' ] );

    }

    /**
     * Register the widget.
     *
     * @since   1.9.6
     */
    public function register() {

        if( ! current_user_can( 'manage_woocommerce' ) ) return;

        // wp_add_dashboard_widget() lives in wp-admin/includes/dashboard.php,
        // which WordPress only loads while it is actually building the
        // dashboard. wp_dashboard_setup normally fires from there, so this is
        // belt and braces — but anything that runs the hook out of context
        // (WP-CLI, a test, another plugin firing it early) would otherwise take
        // the whole request down with a fatal.
        if( ! function_exists( 'wp_add_dashboard_widget' ) ) return;

        wp_add_dashboard_widget(
            self::ID,
            __( 'MightyShield', 'mighty-shield' ),
            [ $this, 'render' ]
        );

    }

    /**
     * Load the design system on the WordPress dashboard.
     *
     * Its own gate, deliberately NOT an entry in admin_page::SCREENS. That list
     * also drives suppress_notices(), which calls remove_all_actions() on
     * admin_notices — appropriate on a screen the plugin owns, catastrophic on
     * the WordPress dashboard, where it would silently swallow every other
     * plugin's notices.
     *
     * @since   1.9.6
     *
     * @param   string  $hook
     */
    public function enqueue( $hook ) {

        if( $hook !== 'index.php' ) return;
        if( ! current_user_can( 'manage_woocommerce' ) ) return;

        admin_page::enqueue_app_assets();

    }

    /**
     * Render the widget.
     *
     * @since   1.9.6
     */
    public function render() {

        // .mshield-scope, not .mshield-app: the tokens without the page chrome.
        // .mshield-app paints a background and insets itself, which inside a
        // dashboard postbox reads as a panel floating in a panel.
        printf(
            '<div class="mshield-scope mshield-dashwidget" data-theme="%s">',
            esc_attr( admin_page::current_theme() )
        );

        // Above the status stripe: a store that cannot take orders is more
        // urgent than whether the ratings are being enforced.
        $this->render_conflict();

        $this->render_status();
        $this->render_chart();
        $this->render_queue();

        echo '</div>';

    }

    /**
     * The checkout-is-closed warning, if it applies.
     *
     * Shown here as well as on Blocking because this is the screen somebody
     * opens when the shop looks wrong, and the plugin should say so before they
     * go looking for the cause.
     *
     * @since   1.9.7
     */
    private function render_conflict() {

        if( ! admin_page::checkout_conflict() ) return;

        printf(
            '<div class="ms-conflict"><strong>%s</strong> %s <a href="%s">%s</a></div>',
            esc_html__( 'Your checkout is closed to customers.', 'mighty-shield' ),
            esc_html__( 'The Store API Firewall is set to Allowlist, and this store uses the block checkout, which needs those endpoints.', 'mighty-shield' ),
            esc_url( admin_url( 'admin.php?page=mighty-shield&tab=blocking' ) ),
            esc_html__( 'Fix it', 'mighty-shield' )
        );

    }

    /**
     * The status stripe — the left-hand side of the dashboard's own hero.
     *
     * No control: changing the state is a decision, and it belongs on the
     * screen that explains what the three states mean.
     *
     * @since   1.9.6
     */
    private function render_status() {

        $now = admin_page::protection_state();

        printf( '<div class="mshield-hero %s">', esc_attr( $now['hero'] ) );

        echo '<span class="ms-accent"></span>';

        printf(
            '<span class="ms-ico"><svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">%s</svg></span>',
            $now['icon'] // phpcs:ignore WordPress.Security.EscapeOutput -- static markup from protection_states().
        );

        echo '<div style="min-width:0">';
        echo '<div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap">';
        printf( '<span class="mshield-hero-title">%s</span>', esc_html( $now['title'] ) );
        printf(
            '<span class="mshield-pill %s"><span class="dot"></span>%s</span>',
            esc_attr( $now['pill'] ),
            esc_html( $now['label'] )
        );
        echo '</div>';
        printf( '<div class="mshield-hero-meta">%s</div>', esc_html( $now['meta'] ) );
        echo '</div>';

        echo '</div>';

    }

    /**
     * Seven days of events.
     *
     * The same element IDs the dashboard's chart uses, so initChart() picks it
     * up with no second implementation. The range buttons are left out — this
     * is a summary, and the full screen is one click away — and initChart()
     * treats those, the title and the subtitle as optional, so their absence
     * costs nothing.
     *
     * @since   1.9.6
     */
    private function render_chart() {

        $series = admin_page::chart_series( '7d' );

        echo '<div class="ms-chartwrap">';

        echo '<div class="ms-charthead">';
        printf( '<span class="mshield-eyebrow">%s</span>', esc_html__( 'Last 7 days', 'mighty-shield' ) );
        echo '<span class="mshield-spacer"></span>';
        echo '<span class="mshield-card-sub" id="mshield-chart-sub"></span>';
        echo '</div>';

        echo '<div class="mshield-legend">';
        foreach( [
            '#d63638' => __( 'Blocked', 'mighty-shield' ),
            '#dba617' => __( 'Rate-limited', 'mighty-shield' ),
            '#8c5ce6' => __( 'Flagged', 'mighty-shield' ),
        ] as $colour => $label ) {
            printf(
                '<span><i style="background:%s"></i>%s</span>',
                esc_attr( $colour ),
                esc_html( $label )
            );
        }
        echo '</div>';

        echo '<div id="mshield-chart" class="mshield-chartbox"></div>';

        printf(
            '<script type="application/json" id="mshield-chart-data">%s</script>',
            wp_json_encode( $series )
        );

        echo '</div>';

    }

    /**
     * What is waiting to be reviewed.
     *
     * @since   1.9.6
     */
    private function render_queue() {

        $count = fraud_review::pending_count();
        $url   = admin_url( 'admin.php?page=mshield-fraud-review' );

        printf( '<div class="ms-queue%s">', $count > 0 ? ' has-work' : '' );

        echo '<div style="min-width:0">';

        printf(
            '<div class="ms-queue-count">%s</div>',
            esc_html( $count > 0
                ? sprintf(
                    /* translators: %s: number of orders. */
                    _n( '%s order needs review', '%s orders need review', $count, 'mighty-shield' ),
                    number_format_i18n( $count )
                )
                : __( 'Nothing needs review', 'mighty-shield' ) )
        );

        printf(
            '<div class="mshield-hint">%s</div>',
            esc_html( $count > 0
                ? __( 'Held or flagged, and waiting on a decision.', 'mighty-shield' )
                : __( 'Every order MightyShield stopped has been dealt with.', 'mighty-shield' ) )
        );

        echo '</div>';

        echo '<span class="mshield-spacer"></span>';

        printf(
            '<a href="%s" class="mshield-btn is-small%s">%s</a>',
            esc_url( $url ),
            $count > 0 ? ' is-primary' : '',
            esc_html( $count > 0
                ? __( 'Review', 'mighty-shield' )
                : __( 'Open queue', 'mighty-shield' ) )
        );

        echo '</div>';

    }

}
