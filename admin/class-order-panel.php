<?php
/**
 * The MightyShield panel on the order screen.
 *
 * Everything the plugin decides about an order used to be invisible on the
 * order itself — written to the risk table and to order meta, and read back by
 * nothing. A merchant looking at a suspicious order could see WooCommerce's own
 * fields and no rating, no reasons and no controls.
 *
 * This is the one place all of it surfaces: the trust badge first, then why,
 * then whatever this particular order needs doing about it. It replaces the
 * old Fraud Review panel, which sat in the main column and rendered only for
 * orders carrying _mshield_ai_flagged — a meta key nothing had written for two
 * versions, so its AI branch was unreachable.
 *
 * Layout constraint worth knowing before editing: WooCommerce renders order
 * metaboxes inside its own <form id="order">, and browsers drop nested forms.
 * A <form> here would silently submit WooCommerce's order update instead of
 * this panel's action. Every control is therefore a link to admin-post.php.
 *
 * @package MightyShield
 * @since   1.9.5
 */
namespace MightyShield\Admin;

use MightyShield\Includes\ai_capture;
use MightyShield\Includes\ai_client;
use MightyShield\Includes\db;
use MightyShield\Includes\rescore;
use MightyShield\Includes\response;
use MightyShield\Includes\risk_levels;
use MightyShield\Includes\signals;
use MightyShield\Includes\trust_badge;
use MightyShield\Firewall\ip_blocklist;

class order_panel {

    /**
     * The confirmation Block asks for, on both screens.
     *
     * It cancels an order and adds an address to the blocklist, neither of
     * which is undone by a back button.
     *
     * @since   1.9.6
     */
    const BLOCK_CONFIRM = 'Block this order? This cancels it and blocks the customer IP.';

    /**
     * Construct.
     *
     * @since   1.9.5
     */
    public function __construct() {

        // Priority 1 so this registers before WooCommerce's own boxes and sits
        // at the top of the side column. Order within a context follows
        // registration order, so a later priority puts the panel under Order
        // Actions — below the fold on most screens, which defeats the point.
        add_action( 'add_meta_boxes', [ $this, 'register' ], 1, 2 );
        add_action( 'admin_post_mshield_order_action', [ $this, 'handle' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue' ] );

    }

    /**
     * Register the metabox on the order edit screen.
     *
     * Registered unconditionally: unlike the panel it replaces, this renders on
     * every order, because "this order has never been rated" is information a
     * merchant needs and an empty right column does not convey it.
     *
     * @since   1.9.5
     *
     * @param   string  $screen_id  Screen ID under HPOS, post type on legacy.
     * @param   mixed   $subject    WC_Order under HPOS, WP_Post on legacy.
     */
    public function register( $screen_id = '', $subject = null ) {

        if( ! self::resolve_order( $subject ) ) return;

        add_meta_box(
            'mshield-order-panel',
            __( 'MightyShield', 'mighty-shield' ),
            [ $this, 'render' ],
            self::screen(),
            'side',
            'high'
        );

    }

    /**
     * The order edit screen ID, correct under HPOS and legacy post storage.
     *
     * @since   1.9.5
     *
     * @return  string
     */
    public static function screen() {

        // get_order_admin_screen() throws outside admin, so guard rather than
        // rely on every caller being inside an admin hook.
        if( is_admin() && class_exists( '\Automattic\WooCommerce\Utilities\OrderUtil' ) ) {
            return \Automattic\WooCommerce\Utilities\OrderUtil::get_order_admin_screen();
        }

        return 'shop_order';

    }

    /**
     * Normalize the metabox subject into a WC_Order.
     *
     * WooCommerce passes a WC_Order under HPOS and a WP_Post on legacy storage
     * — it documents the divergence explicitly.
     *
     * @since   1.9.5
     *
     * @param   mixed   $subject
     * @return  \WC_Order|null
     */
    public static function resolve_order( $subject ) {

        if( $subject instanceof \WC_Order ) return $subject;

        if( $subject instanceof \WP_Post ) {
            $order = wc_get_order( $subject->ID );
            return $order ? $order : null;
        }

        return null;

    }

    /**
     * Load the plugin's stylesheet on the order screen.
     *
     * admin_page::enqueue_styles() gates on the page slug, which the order
     * screen does not carry under either storage. The panel wraps itself in
     * .mshield-app so the design tokens resolve; admin_body_class() does not run
     * here and does not need to, since dark mode keys off the data-theme
     * attribute on that same wrapper.
     *
     * @since   1.9.5
     *
     * @param   string  $hook
     */
    public function enqueue( $hook ) {

        if( ! self::is_order_screen( $hook ) ) return;

        admin_page::enqueue_app_assets();

    }

    /**
     * Whether an admin hook suffix is the single-order screen.
     *
     * HPOS serves it as woocommerce_page_wc-orders; legacy as post.php with a
     * shop_order post type. The list table shares the HPOS hook, so the
     * edit-action check is what separates them.
     *
     * @since   1.9.5
     *
     * @param   string  $hook
     * @return  bool
     */
    public static function is_order_screen( $hook ) {

        if( $hook === 'woocommerce_page_wc-orders' ) {
            return isset( $_GET['action'] ) && $_GET['action'] === 'edit';
        }

        if( $hook === 'post.php' || $hook === 'post-new.php' ) {
            $screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
            return $screen && $screen->post_type === 'shop_order';
        }

        return false;

    }

    /**
     * Render the panel.
     *
     * @since   1.9.5
     *
     * @param   mixed   $subject    WC_Order under HPOS, WP_Post on legacy.
     */
    public function render( $subject ) {

        $order = self::resolve_order( $subject );
        if( ! $order ) return;

        $theme = get_user_meta( get_current_user_id(), 'mshield_admin_theme', true );
        if( ! \in_array( $theme, [ 'light', 'dark', 'system' ], true ) ) $theme = 'system';

        printf(
            '<div class="mshield-app mshield-orderbox" data-theme="%s">',
            esc_attr( $theme )
        );

        $row = rescore::stored( $order );

        $this->render_badge( $order, $row );

        if( $row ) {
            $this->render_reasons( $row );
        } else {
            $this->render_rate( $order );
        }

        $this->render_verdict( $order );
        $this->render_actions( $order );

        echo '</div>';

    }

    /**
     * The trust badge, always first.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @param   array|null  $row
     */
    private function render_badge( $order, $row ) {

        $rated = $row !== null;
        $trust = $rated ? (float) $row['trust'] : null;
        $level = $rated ? (string) $row['risk_level'] : '';

        printf( '<div class="ms-badge %s">', esc_attr( trust_badge::level_class( $level ) ) );

        // Escaped inside trust_badge.
        echo trust_badge::value( $trust, $level ); // phpcs:ignore WordPress.Security.EscapeOutput

        printf(
            '<span class="ms-level">%s</span>',
            esc_html( $rated && risk_levels::exists( $level )
                ? risk_levels::label( $level )
                : __( 'Unrated', 'mighty-shield' ) )
        );

        if( $rated && ( $row['rated_by'] ?? '' ) === 'manual' ) {
            printf(
                '<span class="mshield-hint">%s %s</span>',
                esc_html__( 'Rated by hand, so this is a partial rating.', 'mighty-shield' ),
                esc_html( self::skipped_note() )
            );
        }

        echo '</div>';

    }

    /**
     * Which layers a rating done after the fact could not replay.
     *
     * Named on the unrated state, where it sets expectations before the click,
     * and again on a manually rated one, where it is the difference between a
     * number a merchant can trust and one they cannot. A partial rating that
     * stops admitting it the moment it has a number is the failure this guards
     * against.
     *
     * @since   1.9.5
     *
     * @return  string
     */
    private static function skipped_note() {

        return sprintf(
            /* translators: %s: comma-separated list of check names. */
            __( 'These checks cannot be replayed: %s.', 'mighty-shield' ),
            strtolower( implode( ', ', rescore::SKIPPED_GROUPS ) )
        );

    }

    /**
     * Why it scored what it scored.
     *
     * @since   1.9.5
     *
     * @param   array   $row
     */
    private function render_reasons( $row ) {

        $found = rescore::signals_of( $row );

        if( empty( $found ) ) {
            printf(
                '<p class="ms-quiet">%s</p>',
                esc_html__( 'Nothing tripped. This order looked ordinary on every check that ran.', 'mighty-shield' )
            );
            return;
        }

        echo '<ul class="ms-reasons">';

        // Whether to offer the tuning link at all. The panel is visible to
        // anyone who can see the order, and sending a shop manager to a screen
        // they cannot open is worse than showing them nothing.
        $can_tune = current_user_can( 'manage_woocommerce' );

        foreach( $found as $signal ) {

            $key    = (string) ( $signal['key'] ?? '' );
            $reason = (string) ( $signal['reason'] ?? '' );
            $cost   = round( (float) ( $signal['weight'] ?? 0 ) * (float) ( $signal['confidence'] ?? 1 ), 1 );

            printf(
                '<li><span class="ms-detail"><span class="ms-why">%s</span>%s</span><span class="ms-cost">%s</span></li>',
                esc_html( $reason !== '' ? $reason : signals::label( $key ) ),
                // Not escaped: self::tune_link() returns markup it built and
                // escaped itself, and returns '' when there is nothing to link to.
                $can_tune ? self::tune_link( $key ) : '',
                // A negative weight is the one signal that ADDS trust, so it
                // gets a plus and reads as credit rather than as a smaller cost.
                esc_html( $cost <= 0 ? '+' . abs( $cost ) : '−' . $cost )
            );

        }

        echo '</ul>';

    }

    /**
     * A link to the Scoring row that governs one signal.
     *
     * Every catalog signal has a row, because on/off, trust cost and force
     * level are registered and rendered for all of them — so this always lands
     * somewhere a merchant can actually change something. Signals that also
     * carry a detector setting, like the address velocity thresholds, render
     * that setting on the same row.
     *
     * Returns escaped markup, or '' when there is no row to point at: an order
     * scored before the risk table existed has reasons but no keys, and a key
     * that has since been retired from the catalog would link to an anchor that
     * is no longer rendered.
     *
     * @since   2.0.0
     *
     * @param   string  $key    Signal key.
     * @return  string  Markup, or '' if there is nothing to link to.
     */
    public static function tune_link( $key ) {

        if( $key === '' || ! isset( signals::CATALOG[ $key ] ) ) return '';

        $url = add_query_arg(
            [ 'page' => 'mighty-shield', 'tab' => 'scoring' ],
            admin_url( 'admin.php' )
        ) . '#mshield-sig-' . rawurlencode( $key );

        return sprintf(
            '<a class="ms-tune" href="%s">%s</a>',
            esc_url( $url ),
            esc_html__( 'Adjust setting', 'mighty-shield' )
        );

    }

    /**
     * The Rate Order control, for an order nobody has scored.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     */
    private function render_rate( $order ) {

        printf(
            '<p class="ms-quiet">%s</p>',
            esc_html__( 'This order was placed without being rated, either before MightyShield was installed or while it was switched off.', 'mighty-shield' )
        );

        printf(
            '<p class="ms-buttons"><a href="%s" class="button button-primary" data-mshield-rate>%s</a></p>',
            esc_url( self::action_url( $order, 'rate' ) ),
            esc_html__( 'Rate Order', 'mighty-shield' )
        );

        // Only offered when a provider is actually configured. An unusable
        // toggle is worse than an absent one.
        if( ai_client::is_ready() ) {
            printf(
                '<label class="ms-aitoggle"><input type="checkbox" id="mshield-use-ai" /> %s</label>',
                esc_html__( 'Use AI to Review', 'mighty-shield' )
            );
        }

        printf(
            '<span class="mshield-hint">%s %s</span>',
            esc_html__( 'Rating an order after the fact gives a partial rating.', 'mighty-shield' ),
            esc_html( self::skipped_note() )
        );

    }

    /**
     * The reviewer's Fraud / Clean verdict.
     *
     * Always shown, on every order, in both directions. A chargeback can land
     * months after an order was called clean, and a chargeback can turn out to
     * be a family member using the card — so this is never locked.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     */
    private function render_verdict( $order ) {

        $current = \MightyShield\Protection\outcomes::verdict( $order );

        echo '<div class="ms-verdict">';

        printf( '<span class="ms-eyebrow">%s</span>', esc_html__( 'Your verdict', 'mighty-shield' ) );

        echo '<div class="ms-verdict-pair">';

        foreach( [
            'clean' => __( 'Clean', 'mighty-shield' ),
            'fraud' => __( 'Fraud', 'mighty-shield' ),
        ] as $key => $label ) {

            printf(
                '<a href="%s" class="ms-choice is-%s%s"%s>%s</a>',
                esc_url( self::action_url( $order, 'verdict_' . $key ) ),
                esc_attr( $key ),
                $current === $key ? ' is-on' : '',
                $current === $key ? ' aria-current="true"' : '',
                esc_html( $label )
            );

        }

        echo '</div>';

        printf(
            '<span class="mshield-hint">%s</span>',
            esc_html( $current === ''
                ? __( 'Telling MightyShield how this order turned out is what teaches it. It weighs your answer against future orders from the same customer, device, address or network.', 'mighty-shield' )
                : __( 'Change this any time. Switching the verdict takes back whatever the previous one did to this customer\'s standing.', 'mighty-shield' ) )
        );

        echo '</div>';

    }

    /**
     * Block / Approve, for an order that is being held.
     *
     * Which pair appears is decided by the GATEWAY's captured state, never by
     * MightyShield's own _mshield_hold — that records what was asked for, not
     * what happened, and telling a merchant funds are merely reserved when they
     * were actually taken is the worst failure this screen can produce.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     */
    private function render_actions( $order ) {

        if( ! self::needs_decision( $order ) ) return;

        echo '<div class="ms-decide">';

        printf( '<span class="ms-eyebrow">%s</span>', esc_html__( 'This order is on hold', 'mighty-shield' ) );
        printf( '<p class="ms-money">%s</p>', esc_html( self::money_state( $order ) ) );

        echo '<p class="ms-buttons">';

        printf(
            '<a href="%s" class="button button-primary">%s</a>',
            esc_url( self::action_url( $order, 'approve' ) ),
            esc_html( self::approve_label( $order ) )
        );

        printf(
            '<a href="%s" class="button ms-block" onclick="return confirm(\'%s\');">%s</a>',
            esc_url( self::action_url( $order, 'block' ) ),
            esc_attr( self::BLOCK_CONFIRM ),
            esc_html__( 'Block', 'mighty-shield' )
        );

        echo '</p>';

        printf( '<span class="mshield-hint">%s</span>', esc_html( self::decision_hint( $order ) ) );

        echo '</div>';

    }

    /**
     * What happened to the customer's money, in plain words.
     *
     * Read from the GATEWAY's own captured state, never from MightyShield's
     * _mshield_hold — that records what was asked for, not what happened, and
     * telling a merchant funds are merely reserved when they were actually
     * taken is the worst failure either of these screens can produce.
     *
     * Shared with the Fraud Review queue so one held order cannot be described
     * two different ways depending on where you are looking at it.
     *
     * @since   1.9.6
     *
     * @param   \WC_Order   $order
     * @return  string
     */
    public static function money_state( $order ) {

        if( response::is_detained( $order ) ) {
            return __( 'Nothing was charged. The order never reached the payment processor.', 'mighty-shield' );
        }

        if( ai_capture::is_authorized( $order ) ) {
            return __( 'The funds are reserved on the card but not taken.', 'mighty-shield' );
        }

        return __( 'The payment has already been captured in full.', 'mighty-shield' );

    }

    /**
     * The same answer, short enough for a table column.
     *
     * @since   1.9.6
     *
     * @param   \WC_Order   $order
     * @return  string
     */
    public static function money_short( $order ) {

        if( response::is_detained( $order ) )        return __( 'Never charged', 'mighty-shield' );
        if( ai_capture::is_authorized( $order ) )    return __( 'Reserved, not taken', 'mighty-shield' );

        return __( 'Taken in full', 'mighty-shield' );

    }

    /**
     * Why MightyShield is holding this order.
     *
     * Most specific first. _mshield_flagged records whichever layer noticed
     * first and is never overwritten, so it is the fallback rather than the
     * lead: an order that was detained AND flagged should read as detained.
     *
     * @since   1.9.6
     *
     * @param   \WC_Order   $order
     * @return  string  '' when MightyShield is not holding it at all.
     */
    public static function hold_reason( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return '';

        if( response::is_detained( $order ) ) {
            return __( 'Stopped before payment', 'mighty-shield' );
        }

        switch( (string) $order->get_meta( '_mshield_hold' ) ) {
            case 'authorized':
                return __( 'Held on an authorization', 'mighty-shield' );
            case 'paid':
                return __( 'Held after payment', 'mighty-shield' );
            case 'unavailable':
                // hold_authorized() asked the gateway to authorize without
                // charging and it could not, so the order was held anyway.
                return __( 'Held after payment', 'mighty-shield' );
        }

        if( (string) $order->get_meta( '_mshield_card_flagged' ) === 'yes' ) {
            return __( 'Failed card checks', 'mighty-shield' );
        }

        $flagged = (string) $order->get_meta( '_mshield_flagged' );

        if( $flagged !== '' ) {
            return self::flag_label( $flagged );
        }

        return '';

    }

    /**
     * A layer slug turned into something a shop owner would say.
     *
     * Unknown slugs are humanised rather than dropped — the Store API path
     * writes `token_<layer>` with a dynamic layer name, so this list can never
     * be exhaustive and must degrade to something readable.
     *
     * @since   1.9.6
     *
     * @param   string  $slug
     * @return  string
     */
    public static function flag_label( $slug ) {

        $known = [
            'detained'              => __( 'Stopped before payment', 'mighty-shield' ),
            'risk_hold'             => __( 'Held by its rating', 'mighty-shield' ),
            'risk_engine'           => __( 'Flagged by its rating', 'mighty-shield' ),
            'card_signals'          => __( 'Failed card checks', 'mighty-shield' ),
            'honeypot'              => __( 'Filled a hidden trap field', 'mighty-shield' ),
            'smarty_address_invalid'=> __( 'Address could not be verified', 'mighty-shield' ),
            'zip_state_mismatch'    => __( 'Postcode does not match the state', 'mighty-shield' ),
            'checkout_timing'       => __( 'Checkout completed implausibly fast', 'mighty-shield' ),
            'device_fingerprint'    => __( 'Browser looked automated', 'mighty-shield' ),
            'suspicious_amount'     => __( 'Unusually small order', 'mighty-shield' ),
        ];

        if( isset( $known[ $slug ] ) ) return $known[ $slug ];

        if( strpos( $slug, 'token_' ) === 0 ) {
            return sprintf(
                /* translators: %s: name of the check that flagged the order. */
                __( 'Flagged at checkout by %s', 'mighty-shield' ),
                str_replace( '_', ' ', substr( $slug, 6 ) )
            );
        }

        return ucfirst( str_replace( '_', ' ', $slug ) );

    }

    /**
     * The Approve button's label, which follows the money.
     *
     * @since   1.9.6
     *
     * @param   \WC_Order   $order
     * @return  string
     */
    public static function approve_label( $order ) {

        return ! response::is_detained( $order ) && ai_capture::is_authorized( $order )
            ? __( 'Approve & Capture', 'mighty-shield' )
            : __( 'Approve', 'mighty-shield' );

    }

    /**
     * What the two buttons will actually do to this order.
     *
     * @since   1.9.6
     *
     * @param   \WC_Order   $order
     * @return  string
     */
    public static function decision_hint( $order ) {

        if( response::is_detained( $order ) ) {
            return __( 'Approve sends the customer back to pay. Block cancels the order and blocks the IP. There is nothing to refund.', 'mighty-shield' );
        }

        if( ai_capture::is_authorized( $order ) ) {
            return __( 'Approve takes the money and moves the order to Processing. Block releases the authorization, cancels the order and blocks the IP, leaving nothing to refund.', 'mighty-shield' );
        }

        return __( 'Approve moves the order to Processing. Block cancels the order and blocks the IP, then tells you how to refund. It will not refund automatically.', 'mighty-shield' );

    }

    /**
     * Whether this order is waiting on a hold decision.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @return  bool
     */
    public static function needs_decision( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return false;
        if( ! $order->has_status( 'on-hold' ) ) return false;

        // Any of the three routes that put an order on hold. A merchant's own
        // manual on-hold is not MightyShield's to act on.
        if( response::is_detained( $order ) ) return true;
        if( (string) $order->get_meta( '_mshield_hold' ) !== '' ) return true;

        return (string) $order->get_meta( '_mshield_flagged' ) !== '';

    }

    /**
     * Build a nonced URL for one panel action.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @param   string      $do
     * @return  string
     */
    public static function action_url( $order, $do, $return = '' ) {

        $args = [
            'action'   => 'mshield_order_action',
            'order_id' => $order->get_id(),
            'do'       => $do,
        ];

        // Where to land afterwards. Acting from the review queue and being
        // dropped on the single order screen loses the merchant's place and
        // their page — the opposite of what a queue is for.
        if( $return !== '' ) $args['ms_return'] = $return;

        return wp_nonce_url(
            add_query_arg( $args, admin_url( 'admin-post.php' ) ),
            'mshield_order_action_' . $order->get_id()
        );

    }

    /**
     * Handle a panel action.
     *
     * @since   1.9.5
     */
    public function handle() {

        if( ! current_user_can( 'manage_woocommerce' ) ) {
            wp_die( esc_html__( 'You do not have permission to review orders.', 'mighty-shield' ), '', [ 'response' => 403 ] );
        }

        // $_REQUEST so the handler works whether it arrives by link or form;
        // check_admin_referer() reads the nonce from either.
        $order_id = isset( $_REQUEST['order_id'] ) ? absint( $_REQUEST['order_id'] ) : 0;
        $do       = isset( $_REQUEST['do'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['do'] ) ) : '';
        $use_ai   = isset( $_REQUEST['use_ai'] ) && $_REQUEST['use_ai'] === '1';

        check_admin_referer( 'mshield_order_action_' . $order_id );

        $order = wc_get_order( $order_id );

        $allowed = [ 'rate', 'verdict_clean', 'verdict_fraud', 'approve', 'block' ];

        if( ! $order || ! \in_array( $do, $allowed, true ) ) {
            wp_die( esc_html__( 'Invalid MightyShield order request.', 'mighty-shield' ), '', [ 'response' => 400 ] );
        }

        switch( $do ) {

            case 'rate':
                $notice = $this->rate( $order, $use_ai );
                break;

            case 'verdict_clean':
            case 'verdict_fraud':
                $notice = $this->verdict( $order, substr( $do, 8 ) );
                break;

            case 'approve':
                $notice = $this->approve( $order );
                break;

            default:
                $notice = $this->block( $order );
                break;

        }

        fraud_review::flush_count();

        // Back to the queue, if that is where the click came from. The queue
        // renders inside the app chrome, where suppress_notices() has stripped
        // admin_notices — so the result goes in the transient the shell reads,
        // not the order-screen one that render_notice() drains.
        $return = isset( $_REQUEST['ms_return'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['ms_return'] ) ) : '';

        if( $return === 'queue' ) {

            set_transient( 'mshield_admin_notice', [ 'order_action', $notice[0], $notice[1] ], 60 );

            $url = admin_url( 'admin.php?page=mshield-fraud-review' );

            $paged = isset( $_REQUEST['paged'] ) ? absint( $_REQUEST['paged'] ) : 0;
            if( $paged > 1 ) $url = add_query_arg( 'paged', $paged, $url );

            wp_safe_redirect( $url );
            exit;

        }

        set_transient( 'mshield_order_notice_' . $order_id, $notice, 60 );

        wp_safe_redirect( $order->get_edit_order_url() );
        exit;

    }

    /**
     * Rate an order that was never scored.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @param   bool        $use_ai
     * @return  array   [ message, type ]
     */
    private function rate( $order, $use_ai ) {

        $verdict = rescore::run( $order, $use_ai );

        if( is_wp_error( $verdict ) ) {
            return [ $verdict->get_error_message(), 'error' ];
        }

        return [ sprintf(
            /* translators: 1: trust rating, 2: risk level name. */
            __( 'Rated %1$s/100: %2$s. Nothing was done to the order. This is a rating, not an action.', 'mighty-shield' ),
            $verdict['trust'],
            risk_levels::label( $verdict['risk_level'] )
        ), 'success' ];

    }

    /**
     * Record the reviewer's verdict.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @param   string      $verdict    'clean' or 'fraud'.
     * @return  array   [ message, type ]
     */
    private function verdict( $order, $verdict ) {

        $changed = \MightyShield\Protection\outcomes::set_manual( $order, $verdict );

        if( ! $changed ) {
            return [ __( 'That was already the recorded verdict.', 'mighty-shield' ), 'success' ];
        }

        return [ $verdict === 'fraud'
            ? __( 'Marked as fraud. MightyShield will weigh this against future orders from the same customer, device, address or network.', 'mighty-shield' )
            : __( 'Marked as clean. Any penalty this order placed on the customer has been taken back.', 'mighty-shield' ),
            'success' ];

    }

    /**
     * Approve a held order.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @return  array   [ message, type ]
     */
    private function approve( $order ) {

        // A detained order was stopped BEFORE payment: no charge was taken and
        // no authorization exists, so there is nothing to capture and nothing
        // that would justify Processing. Moving it there would mark an unpaid
        // order as paid and release it to fulfilment — the same free-order
        // failure the detain itself exists to prevent, just via the admin.
        //
        // Approving one means letting the customer pay, so it goes back to
        // Pending and the merchant sends them the payment link.
        if( response::is_detained( $order ) ) {

            $url = response::release( $order );

            \MightyShield\Protection\outcomes::set_manual( $order, 'clean' );

            db::log_event( $order->get_customer_ip_address(), 'risk_engine', 'flagged', 'Held order #' . $order->get_id() . ' released for payment' );

            return [ sprintf(
                /* translators: %s: checkout payment URL. */
                __( 'Order released. It was never charged, so send the customer this link to pay: %s', 'mighty-shield' ),
                esc_url_raw( $url )
            ), 'success' ];

        }

        // Capture first when funds are only reserved. An order must never move
        // to Processing on the strength of money that did not actually move.
        if( ai_capture::is_authorized( $order ) ) {

            $result = ai_capture::capture( $order );

            if( is_wp_error( $result ) ) {

                $order->add_order_note( 'MightyShield: ' . sprintf(
                    /* translators: %s: gateway error. */
                    __( 'Approve failed. The authorization could not be captured: %s. The order remains on hold.', 'mighty-shield' ),
                    $result->get_error_message()
                ) );
                $order->save();

                return [ sprintf(
                    /* translators: %s: gateway error. */
                    __( 'Capture failed: %s. The order is still on hold.', 'mighty-shield' ),
                    $result->get_error_message()
                ), 'error' ];

            }

            // Most gateway capture handlers call payment_complete() themselves.
            // Re-read the order and only transition if they did not.
            $order = wc_get_order( $order->get_id() );

        }

        if( ! $order->has_status( [ 'processing', 'completed' ] ) ) {
            $order->update_status( 'processing', __( 'MightyShield: approved in review.', 'mighty-shield' ) );
        } else {
            $order->add_order_note( 'MightyShield: ' . __( 'Approved in review.', 'mighty-shield' ) );
        }

        // The decision reaches identity reputation. The old panel wrote its own
        // meta key and stopped there, so denying a fraudulent order taught the
        // scoring engine precisely nothing.
        \MightyShield\Protection\outcomes::set_manual( $order, 'clean' );

        db::log_event( $order->get_customer_ip_address(), 'risk_engine', 'flagged', 'Order #' . $order->get_id() . ' approved in review' );

        return [ __( 'Order approved.', 'mighty-shield' ), 'success' ];

    }

    /**
     * Block a held order.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @return  array   [ message, type ]
     */
    private function block( $order ) {

        $blocked = $this->blocklist_ip( $order );

        // A detained order never reached the gateway, so there is no
        // authorization to void and nothing to refund. Without this branch it
        // would fall through to the captured-payment path and tell the merchant
        // their money was taken and needs refunding, which is simply untrue.
        if( response::is_detained( $order ) ) {

            $order->add_order_note( 'MightyShield: ' . __( 'Blocked in review. No payment was ever taken, so there is nothing to refund.', 'mighty-shield' ) );
            $order->save();

            if( ! $order->has_status( 'cancelled' ) ) {
                $order->update_status( 'cancelled', __( 'MightyShield: blocked in review.', 'mighty-shield' ) );
            }

            \MightyShield\Protection\outcomes::set_manual( $order, 'fraud' );

            db::log_event( $order->get_customer_ip_address(), 'risk_engine', 'blocked', 'Held order #' . $order->get_id() . ' blocked in review' );

            return [ $blocked
                ? __( 'Order blocked and cancelled, and the IP added to the blocklist. No payment was taken, so there is nothing to refund.', 'mighty-shield' )
                : __( 'Order blocked and cancelled. No payment was taken, so there is nothing to refund.', 'mighty-shield' ),
                'success' ];

        }

        if( ai_capture::is_authorized( $order ) ) {

            $result = ai_capture::void( $order );

            if( is_wp_error( $result ) ) {

                $order->add_order_note( 'MightyShield: ' . sprintf(
                    /* translators: %s: gateway error. */
                    __( 'Block failed. The authorization could not be released: %s. The order remains on hold.', 'mighty-shield' ),
                    $result->get_error_message()
                ) );
                $order->save();

                return [ sprintf(
                    /* translators: %s: gateway error. */
                    __( 'Could not release the authorization: %s. The order is still on hold.', 'mighty-shield' ),
                    $result->get_error_message()
                ), 'error' ];

            }

            // Some processors tell us the release landed and some return
            // nothing at all. Saying "nothing was taken, so there is nothing to
            // refund" is a claim about the customer's money, and it is only
            // made when the processor actually confirmed it.
            $confirmed = ( $result !== ai_capture::UNCONFIRMED );

            $order->add_order_note( 'MightyShield: ' . ( $confirmed
                ? __( 'Blocked in review. The authorization was released.', 'mighty-shield' )
                : __( 'Blocked in review. The release was sent to the payment processor, which did not report back whether it completed. Check the authorization in your processor dashboard.', 'mighty-shield' ) ) );
            $order->save();

            // Some gateways cancel the order themselves once the void lands.
            $order = wc_get_order( $order->get_id() );
            if( ! $order->has_status( 'cancelled' ) ) {
                $order->update_status( 'cancelled', __( 'MightyShield: blocked in review.', 'mighty-shield' ) );
            }

            \MightyShield\Protection\outcomes::set_manual( $order, 'fraud' );

            db::log_event(
                $order->get_customer_ip_address(),
                'risk_engine',
                'blocked',
                'Order #' . $order->get_id() . ' blocked in review'
                    . ( $confirmed ? ', authorization released' : ', authorization release UNCONFIRMED by the processor' )
            );

            if( ! $confirmed ) {
                return [ $blocked
                    ? __( 'Order blocked and cancelled, and the IP added to the blocklist. The release was sent to your payment processor, but it did not confirm the authorization was cancelled, so check it in your processor dashboard.', 'mighty-shield' )
                    : __( 'Order blocked and cancelled. The release was sent to your payment processor, but it did not confirm the authorization was cancelled, so check it in your processor dashboard.', 'mighty-shield' ),
                    'warning' ];
            }

            return [ $blocked
                ? __( 'Order blocked. The authorization was released, the order cancelled, and the IP added to the blocklist. Nothing was taken, so there is nothing to refund.', 'mighty-shield' )
                : __( 'Order blocked. The authorization was released and the order cancelled. Nothing was taken, so there is nothing to refund.', 'mighty-shield' ),
                'success' ];

        }

        // Captured. No automatic refund: a refund is a movement of real money
        // and belongs to a deliberate click in WooCommerce's own refund panel,
        // where the merchant can see the amount.
        $order->add_order_note( 'MightyShield: ' . __( 'Blocked in review. The payment was already captured, so refund it from the order items panel.', 'mighty-shield' ) );
        $order->save();

        if( ! $order->has_status( 'cancelled' ) ) {
            $order->update_status( 'cancelled', __( 'MightyShield: blocked in review.', 'mighty-shield' ) );
        }

        \MightyShield\Protection\outcomes::set_manual( $order, 'fraud' );

        db::log_event( $order->get_customer_ip_address(), 'risk_engine', 'blocked', 'Order #' . $order->get_id() . ' blocked in review' );

        return [ $blocked
            ? __( 'Order blocked, cancelled, and the IP added to the blocklist. The payment was already captured, so refund it from the order items panel below and the order is settled.', 'mighty-shield' )
            : __( 'Order blocked and cancelled. The payment was already captured, so refund it from the order items panel below and the order is settled.', 'mighty-shield' ),
            'success' ];

    }

    /**
     * Add the order's IP to the blocklist.
     *
     * A duplicate returns false from add_ip(), which means "already blocked" —
     * not a failure, so it is not surfaced as one.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @return  bool    Whether a new entry was written.
     */
    private function blocklist_ip( $order ) {

        $ip = $order->get_customer_ip_address();

        if( empty( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) return false;

        return (bool) ip_blocklist::add_ip(
            $ip,
            sprintf( 'Order #%d', $order->get_id() ),
            'Blocked in MightyShield order review'
        );

    }

    /**
     * Show the result of a panel action on the order screen.
     *
     * @since   1.9.5
     */
    public static function render_notice() {

        $screen = get_current_screen();
        if( ! $screen ) return;

        // HPOS serves the order at ?page=wc-orders&action=edit&id=N; legacy at
        // post.php?post=N&action=edit.
        $order_id = isset( $_GET['id'] ) ? absint( $_GET['id'] ) : ( isset( $_GET['post'] ) ? absint( $_GET['post'] ) : 0 );
        if( ! $order_id ) return;

        $notice = get_transient( 'mshield_order_notice_' . $order_id );
        if( ! $notice || ! is_array( $notice ) || count( $notice ) !== 2 ) return;

        delete_transient( 'mshield_order_notice_' . $order_id );

        // Three tones, not two. An action that half-worked -- a release the
        // processor never confirmed -- must not be painted the same green as
        // one that did, which is the whole reason the caller can return
        // 'warning'.
        $tone = \in_array( $notice[1], [ 'error', 'warning' ], true ) ? $notice[1] : 'success';

        printf(
            '<div class="notice notice-%s is-dismissible"><p><strong>%s</strong> %s</p></div>',
            esc_attr( $tone ),
            esc_html__( 'MightyShield:', 'mighty-shield' ),
            esc_html( $notice[0] )
        );

    }

}
