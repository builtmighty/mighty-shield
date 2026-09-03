<?php
/**
 * Fraud Review queue.
 *
 * Adds a "Fraud Review" screen under WooCommerce → Orders that lists every order
 * the AI fraud review is still waiting on, with a count bubble on the menu item
 * (mirroring the way WooCommerce badges Orders with the processing count). The
 * screen only appears when AI fraud detection is enabled, and only lists orders
 * that are on hold and not yet approved or denied — the same "waiting" set the
 * per-order Approve/Deny panel keys off. Each row links to the native order
 * screen, where that panel handles the decision.
 *
 * @package MightyShield
 * @since   1.8.1
 */
namespace MightyShield\Admin;

use MightyShield\Includes\settings;
use MightyShield\Includes\response;

class fraud_review {

    /**
     * Menu slug for the review screen.
     *
     * @since   1.8.1
     */
    private const SLUG = 'mshield-fraud-review';

    /**
     * Transient caching the pending-review count for the menu bubble.
     *
     * @since   1.8.1
     */
    private const COUNT_KEY = 'mshield_ai_pending_count';

    /**
     * Construct.
     *
     * @since   1.8.1
     */
    public function __construct() {

        // Priority 99 so WooCommerce has already registered its own submenu
        // (Orders included) before we add ours and splice it into place.
        add_action( 'admin_menu', [ $this, 'register_menu' ], 99 );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue' ] );

    }

    /**
     * Register the Fraud Review submenu under WooCommerce, positioned directly
     * beneath Orders, with a count bubble. Only when AI review is enabled.
     *
     * @since   1.8.1
     */
    public function register_menu() {

        // Gated on AI review when the queue only ever held AI-flagged orders.
        // It now lists everything the risk engine left waiting on a human, so
        // gating it on AI would hide held orders from every store that has not
        // configured a model — which is most of them.
        if( settings::get( 'mshield_enabled' ) !== 'yes' ) return;

        $count = self::pending_count();

        $title = esc_html__( 'Fraud Review', 'mighty-shield' );
        if( $count > 0 ) {
            $title .= ' <span class="awaiting-mod"><span class="pending-count">' . number_format_i18n( $count ) . '</span></span>';
        }

        add_submenu_page(
            'woocommerce',
            __( 'Fraud Review', 'mighty-shield' ),
            $title,
            'manage_woocommerce',
            self::SLUG,
            [ $this, 'render' ]
        );

        $this->reorder_submenu();

    }

    /**
     * Move our submenu row so it sits immediately after the Orders row.
     *
     * @since   1.8.1
     */
    private function reorder_submenu() {

        global $submenu;

        if( empty( $submenu['woocommerce'] ) || ! is_array( $submenu['woocommerce'] ) ) return;

        $items   = $submenu['woocommerce'];
        $our_idx = null;

        foreach( $items as $i => $it ) {
            if( isset( $it[2] ) && $it[2] === self::SLUG ) {
                $our_idx = $i;
                break;
            }
        }

        if( $our_idx === null ) return;

        $row = $items[ $our_idx ];
        unset( $items[ $our_idx ] );

        // Rebuild the menu, inserting our row right after whichever Orders slug
        // this store uses (HPOS = wc-orders, legacy = the shop_order list).
        $rebuilt  = [];
        $inserted = false;
        foreach( $items as $it ) {
            $rebuilt[] = $it;
            if( ! $inserted && isset( $it[2] ) && ( $it[2] === 'wc-orders' || $it[2] === 'edit.php?post_type=shop_order' ) ) {
                $rebuilt[] = $row;
                $inserted  = true;
            }
        }

        // If Orders was not found (unusual), leave our row where it was.
        if( ! $inserted ) $rebuilt[] = $row;

        $submenu['woocommerce'] = array_values( $rebuilt );

    }

    /**
     * Base wc_get_orders() args for the "waiting to be reviewed" set: flagged by
     * AI review, on hold, and not yet approved or denied. HPOS-safe.
     *
     * @since   1.8.1
     *
     * @param   array   $extra  Args to merge over the defaults.
     * @return  array
     */
    public static function pending_args( $extra = [] ) {

        $ids = self::pending_ids();

        return array_merge( [
            // Card-signal flags land on orders that already paid, so they can
            // be processing rather than on-hold. Restricting to on-hold would
            // hide exactly the orders that still need stopping before they ship.
            'status'   => [ 'on-hold', 'processing' ],
            'limit'    => -1,
            'return'   => 'ids',
            // Resolved to a plain ID list by pending_ids() rather than expressed
            // as a meta_query.
            //
            // post__in, not include: wc_get_orders() accepts `include` without
            // complaint and then ignores it, so the filter silently does
            // nothing and every order on the store comes back as "awaiting
            // review". post__in is honoured under both HPOS and legacy storage.
            //
            // [0] is the match-nothing sentinel — an empty array is treated as
            // no filter at all, which is the same failure by another route.
            'post__in' => $ids ? $ids : [ 0 ],
        ], $extra );

    }

    /**
     * Orders that are still waiting on a human decision.
     *
     * Deliberately several small queries rather than one meta_query, and this
     * is not a style preference.
     *
     * WooCommerce puts `meta_key` in the ON clause only when a meta clause
     * stands alone. Inside an OR group the key moves to the WHERE, leaving an
     * INNER JOIN on `order_id` with nothing else to constrain it — so N such
     * clauses produce an N-way cartesian product of every meta row on every
     * candidate order. At roughly a dozen meta rows per order, six clauses is
     * 12^6 ≈ 3 million intermediate rows per order. This screen timed out on a
     * store with 53 orders in it.
     *
     * One clause per query keeps every join to a single indexed lookup, and the
     * set arithmetic happens in PHP over what is, by its nature, a small list:
     * these are orders somebody has to look at by hand.
     *
     * @since   1.9.5
     *
     * @return  int[]   Order IDs, newest first.
     */
    public static function pending_ids() {

        if( ! function_exists( 'wc_get_orders' ) ) return [];

        // Every route that leaves an order waiting on a human: the risk engine
        // detained it before payment, an action held it with or without taking
        // the money, a layer flagged it, or the card checks came back bad after
        // payment.
        //
        // This used to lead with _mshield_ai_flagged = 'ai_review', which
        // nothing has written since AI review stopped being its own verdict —
        // so the queue only ever showed detained and card-flagged orders, and
        // looked empty on a store that had neither.
        $held = array_merge(
            self::by_meta( '_mshield_detained', 'yes' ),
            self::by_meta( '_mshield_hold' ),
            self::by_meta( '_mshield_flagged' ),
            self::by_meta( '_mshield_card_flagged', 'yes' )
        );

        if( empty( $held ) ) return [];

        // A verdict takes the order out of the queue. _mshield_review is what
        // the panel writes; _mshield_ai_decision is its predecessor, kept here
        // so orders decided under the old panel do not reappear after upgrading.
        $decided = array_merge(
            self::decided( '_mshield_review' ),
            self::decided( '_mshield_ai_decision' )
        );

        $ids = array_values( array_diff( array_unique( $held ), $decided ) );

        rsort( $ids, SORT_NUMERIC );

        return $ids;

    }

    /**
     * Order IDs carrying one meta key, optionally with a given value.
     *
     * @since   1.9.5
     *
     * @param   string      $key
     * @param   string|null $value  Null matches on the key's presence alone.
     * @return  int[]
     */
    private static function by_meta( $key, $value = null ) {

        $clause = $value === null
            ? [ 'key' => $key, 'compare' => 'EXISTS' ]
            : [ 'key' => $key, 'value' => $value ];

        return array_map( 'intval', (array) wc_get_orders( [
            'status'     => [ 'on-hold', 'processing' ],
            'limit'      => -1,
            'return'     => 'ids',
            'meta_query' => [ $clause ],
        ] ) );

    }

    /**
     * Order IDs whose decision meta holds an actual decision.
     *
     * A key present but empty is not a decision — the old panel cleared it back
     * to '' when a gateway void failed and it had to leave the order on hold.
     * Such an order must stay in the queue.
     *
     * @since   1.9.5
     *
     * @param   string  $key
     * @return  int[]
     */
    private static function decided( $key ) {

        return array_map( 'intval', (array) wc_get_orders( [
            'status'     => [ 'on-hold', 'processing' ],
            'limit'      => -1,
            'return'     => 'ids',
            'meta_query' => [ [ 'key' => $key, 'value' => '', 'compare' => '!=' ] ],
        ] ) );

    }

    /**
     * Count of orders waiting for review, cached briefly for the menu bubble.
     *
     * @since   1.8.1
     *
     * @return  int
     */
    public static function pending_count() {

        if( ! function_exists( 'wc_get_orders' ) ) return 0;

        $cached = get_transient( self::COUNT_KEY );
        if( $cached !== false ) return (int) $cached;

        // Counted from the resolved list rather than by asking the database to
        // count it again — this runs on every admin page load for the menu
        // bubble, so it is the hottest caller on the class.
        $count = count( self::pending_ids() );

        set_transient( self::COUNT_KEY, $count, 2 * MINUTE_IN_SECONDS );

        return $count;

    }

    /**
     * Drop the cached count so the bubble refreshes on the next admin load.
     *
     * @since   1.8.1
     */
    public static function flush_count() {

        delete_transient( self::COUNT_KEY );

    }

    /**
     * Render the review queue.
     *
     * @since   1.8.1
     */
    public function render() {

        if( ! current_user_can( 'manage_woocommerce' ) ) return;

        $per   = 20;
        $paged = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;

        $res = wc_get_orders( self::pending_args( [
            'limit'    => $per,
            'page'     => $paged,
            'paginate' => true,
            'return'   => 'objects',
            'orderby'  => 'date',
            'order'    => 'DESC',
        ] ) );

        $orders = $res->orders;
        $total  = (int) $res->total;
        $pages  = max( 1, (int) $res->max_num_pages );

        // The same chrome as every other MightyShield screen. No tab cards:
        // this is reached from WooCommerce -> Orders, not from the tab row, so
        // it offers a way back to the settings instead of pretending to be one
        // of them.
        admin_page::shell_open( [
            'nav'  => false,
            'back' => [ admin_url( 'admin.php?page=mighty-shield' ), __( 'MightyShield settings', 'mighty-shield' ) ],
        ] );

        echo '<div class="mshield-stack">';

        $this->render_intro( $total );

        if( empty( $orders ) ) {
            $this->render_empty();
        } else {
            $this->render_list( $orders, $total, $paged, $pages );
        }

        echo '</div>';

        admin_page::shell_close();

    }

    /**
     * What this screen is and what is on it.
     *
     * @since   1.9.6
     *
     * @param   int     $total
     */
    private function render_intro( $total ) {

        echo '<div class="mshield-section" style="margin-bottom:0">';

        printf( '<div class="mshield-eyebrow">%s</div>', esc_html__( 'Waiting on you', 'mighty-shield' ) );
        printf( '<h2>%s</h2>', esc_html__( 'Fraud Review', 'mighty-shield' ) );

        printf(
            '<p class="description">%s</p>',
            esc_html(
                $total > 0
                    ? sprintf(
                        /* translators: %s: number of orders. */
                        _n(
                            '%s order is held or flagged and has not been decided yet. Approve or block it here, or open it for the full picture.',
                            '%s orders are held or flagged and have not been decided yet. Approve or block them here, or open one for the full picture.',
                            $total,
                            'mighty-shield'
                        ),
                        number_format_i18n( $total )
                    )
                    : __( 'Orders MightyShield has stopped or flagged appear here until somebody decides what to do with them.', 'mighty-shield' )
            )
        );

        echo '</div>';

    }

    /**
     * An empty queue is the normal state, so it reads as reassurance rather
     * than as a broken page.
     *
     * @since   1.9.6
     */
    private function render_empty() {

        echo '<div class="mshield-card" style="text-align:center;padding:34px 20px">';

        echo '<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="var(--ink-ok)" stroke-width="1.7" style="margin-bottom:10px"><path d="M12 3l8 3v6c0 4.6-3.2 8.4-8 9.6C7.2 20.4 4 16.6 4 12V6z"></path><path d="M9 12l2 2 4-4"></path></svg>';

        printf(
            '<div style="font-size:15px;font-weight:650;margin-bottom:4px">%s</div>',
            esc_html__( 'Nothing is waiting for you', 'mighty-shield' )
        );

        printf(
            '<p style="margin:0;color:var(--fg-2);font-size:13px">%s</p>',
            esc_html__( 'Orders held before payment, held after it, or flagged by a check land here. An empty queue means every one of them has been dealt with.', 'mighty-shield' )
        );

        echo '</div>';

    }

    /**
     * The queue.
     *
     * A CSS grid rather than a <table>, following the Logs list: .mshield-table
     * restyles every checkbox inside it into a toggle switch, and a row of
     * action links reads better as a grid track than as a cell.
     *
     * @since   1.9.6
     *
     * @param   array   $orders
     * @param   int     $total
     * @param   int     $paged
     * @param   int     $pages
     */
    private function render_list( $orders, $total, $paged, $pages ) {

        echo '<div class="mshield-card is-flush mshield-loglist">';

        echo '<div class="mshield-queuerow is-head">';
        foreach( [
            __( 'Order', 'mighty-shield' ),
            __( 'Rating', 'mighty-shield' ),
            __( 'Why it is held', 'mighty-shield' ),
            __( 'The money', 'mighty-shield' ),
            __( 'Customer', 'mighty-shield' ),
            __( 'Total', 'mighty-shield' ),
            __( 'Waiting', 'mighty-shield' ),
            '',
        ] as $label ) {
            printf( '<span>%s</span>', esc_html( $label ) );
        }
        echo '</div>';

        foreach( $orders as $order ) {
            $this->render_row( $order, $paged );
        }

        $this->render_foot( count( $orders ), $total, $paged, $pages );

        echo '</div>';

    }

    /**
     * One order.
     *
     * @since   1.9.6
     *
     * @param   \WC_Order   $order
     * @param   int         $paged
     */
    private function render_row( $order, $paged ) {

        $edit = $order->get_edit_order_url();

        echo '<div class="mshield-queuerow">';

        // Order number.
        printf(
            '<span><a href="%s" class="ms-ordernum">#%s</a></span>',
            esc_url( $edit ),
            esc_html( $order->get_order_number() )
        );

        // Rating — the same badge as the orders list, straight from order meta
        // with no query of its own.
        printf( '<span>%s</span>', order_column::cell( $order ) ); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in cell().

        // Why it is here. This is the column the old screen never had, and the
        // reason clearing the queue meant opening every order.
        $reason = order_panel::hold_reason( $order );
        printf(
            '<span><span class="mshield-pill %s" style="justify-self:start">%s</span></span>',
            esc_attr( self::reason_tone( $order ) ),
            esc_html( $reason !== '' ? $reason : __( 'Flagged', 'mighty-shield' ) )
        );

        // What happened to the money, read from the gateway.
        printf(
            '<span class="ms-money" title="%s">%s</span>',
            esc_attr( order_panel::money_state( $order ) ),
            esc_html( order_panel::money_short( $order ) )
        );

        // Customer.
        $name  = trim( $order->get_formatted_billing_full_name() );
        $email = $order->get_billing_email();
        echo '<span>';
        if( $name !== '' ) printf( '<span class="ms-name">%s</span>', esc_html( $name ) );
        printf( '<span class="mshield-hint">%s</span>', esc_html( $email ) );
        echo '</span>';

        // Total.
        printf( '<span class="ms-total">%s</span>', wp_kses_post( $order->get_formatted_order_total() ) );

        // How long it has been sitting there.
        $created = $order->get_date_created();
        printf(
            '<span class="ms-age" title="%s">%s</span>',
            esc_attr( $created ? wc_format_datetime( $created, 'Y-m-d H:i' ) : '' ),
            esc_html( $created
                ? sprintf(
                    /* translators: %s: human time difference, e.g. "3 days". */
                    __( '%s ago', 'mighty-shield' ),
                    human_time_diff( $created->getTimestamp(), time() )
                )
                : '—' )
        );

        $this->render_row_actions( $order, $paged, $edit );

        echo '</div>';

    }

    /**
     * The action links on one row.
     *
     * Approve and Block go through the same admin-post handler, the same nonce
     * and the same code as the order panel's own buttons — there is one place
     * that captures, voids, cancels and blocklists, and this is not a second
     * one.
     *
     * @since   1.9.6
     *
     * @param   \WC_Order   $order
     * @param   int         $paged
     * @param   string      $edit
     */
    private function render_row_actions( $order, $paged, $edit ) {

        echo '<span class="ms-rowactions">';

        // needs_decision() is what the order panel gates its own buttons on. A
        // row offering Approve on an order the panel would not is a bug waiting
        // to happen, so the two ask the same question.
        if( order_panel::needs_decision( $order ) ) {

            $ret = $paged > 1 ? 'queue&paged=' . (int) $paged : 'queue';

            printf(
                '<a href="%s" class="mshield-btn is-small is-primary">%s</a>',
                esc_url( order_panel::action_url( $order, 'approve', $ret ) ),
                esc_html( order_panel::approve_label( $order ) )
            );

            printf(
                '<a href="%s" class="mshield-btn is-small ms-block" onclick="return confirm(\'%s\');">%s</a>',
                esc_url( order_panel::action_url( $order, 'block', $ret ) ),
                esc_attr( order_panel::BLOCK_CONFIRM ),
                esc_html__( 'Block', 'mighty-shield' )
            );

        }

        printf(
            '<a href="%s" class="mshield-btn is-small">%s</a>',
            esc_url( $edit ),
            esc_html__( 'Review', 'mighty-shield' )
        );

        echo '</span>';

    }

    /**
     * A pill tone for why the order is held.
     *
     * Coloured by how far the order got, not by how bad it is: red for one that
     * never reached the processor, amber for money already committed, neutral
     * for a flag that stopped nothing.
     *
     * @since   1.9.6
     *
     * @param   \WC_Order   $order
     * @return  string
     */
    private static function reason_tone( $order ) {

        if( response::is_detained( $order ) ) return 'is-danger';
        if( (string) $order->get_meta( '_mshield_hold' ) !== '' )    return 'is-warn';
        if( (string) $order->get_meta( '_mshield_card_flagged' ) === 'yes' ) return 'is-warn';

        return 'is-flag';

    }

    /**
     * Count and pagination.
     *
     * paginate_links() emits core's .tablenav markup, which has no styling in
     * this design system at all — hence the same Previous / n of m / Next bar
     * the Logs list uses.
     *
     * @since   1.9.6
     *
     * @param   int     $shown
     * @param   int     $total
     * @param   int     $paged
     * @param   int     $pages
     */
    private function render_foot( $shown, $total, $paged, $pages ) {

        $base = admin_url( 'admin.php?page=mshield-fraud-review' );

        echo '<div class="mshield-logfoot">';

        printf(
            '<span>%s</span>',
            esc_html( sprintf(
                /* translators: 1: orders on this page, 2: orders in total. */
                __( 'Showing %1$d of %2$s', 'mighty-shield' ),
                $shown,
                number_format_i18n( $total )
            ) )
        );

        echo '<span class="mshield-spacer"></span>';

        if( $paged > 1 ) {
            printf(
                '<a class="mshield-btn is-small" href="%s">%s</a>',
                esc_url( add_query_arg( 'paged', $paged - 1, $base ) ),
                esc_html__( 'Previous', 'mighty-shield' )
            );
        }

        printf(
            '<span class="mshield-mono">%s</span>',
            esc_html( sprintf( __( '%1$d / %2$d', 'mighty-shield' ), $paged, $pages ) )
        );

        if( $paged < $pages ) {
            printf(
                '<a class="mshield-btn is-small" href="%s">%s</a>',
                esc_url( add_query_arg( 'paged', $paged + 1, $base ) ),
                esc_html__( 'Next', 'mighty-shield' )
            );
        }

        echo '</div>';

    }

    /**
     * Load the design system on this screen.
     *
     * admin_page::enqueue_styles() covers it through is_plugin_screen() now,
     * but this screen is the reason that predicate exists and a second, local
     * guarantee costs nothing — wp_enqueue_* is idempotent.
     *
     * @since   1.9.6
     *
     * @param   string  $hook
     */
    public function enqueue( $hook ) {

        if( $hook !== 'woocommerce_page_' . self::SLUG ) return;

        admin_page::enqueue_app_assets();

    }

}
