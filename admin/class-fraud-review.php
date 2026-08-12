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

    }

    /**
     * Register the Fraud Review submenu under WooCommerce, positioned directly
     * beneath Orders, with a count bubble. Only when AI review is enabled.
     *
     * @since   1.8.1
     */
    public function register_menu() {

        if( settings::get( 'mshield_ai_enabled' ) !== 'yes' ) return;

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

        return array_merge( [
            'status'     => [ 'on-hold' ],
            'limit'      => -1,
            'return'     => 'ids',
            'meta_query' => [
                [ 'key' => '_mshield_ai_flagged', 'value' => 'ai_review' ],
                [
                    'relation' => 'OR',
                    [ 'key' => '_mshield_ai_decision', 'compare' => 'NOT EXISTS' ],
                    [ 'key' => '_mshield_ai_decision', 'value' => '', 'compare' => '=' ],
                ],
            ],
        ], $extra );

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

        $res   = wc_get_orders( self::pending_args( [ 'limit' => 1, 'paginate' => true ] ) );
        $count = (int) $res->total;

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
        $pages  = (int) $res->max_num_pages;

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__( 'Fraud Review', 'mighty-shield' ) . '</h1>';
        echo '<p>' . esc_html__( 'Orders flagged by AI fraud detection that are on hold and waiting for your decision. Open an order to approve or deny it.', 'mighty-shield' ) . '</p>';

        if( empty( $orders ) ) {
            echo '<p>' . esc_html__( 'No orders are waiting for review.', 'mighty-shield' ) . '</p>';
            echo '</div>';
            return;
        }

        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr>';
        echo '<th>' . esc_html__( 'Order', 'mighty-shield' ) . '</th>';
        echo '<th>' . esc_html__( 'Date', 'mighty-shield' ) . '</th>';
        echo '<th>' . esc_html__( 'Customer', 'mighty-shield' ) . '</th>';
        echo '<th>' . esc_html__( 'Total', 'mighty-shield' ) . '</th>';
        echo '<th>' . esc_html__( 'AI Rating', 'mighty-shield' ) . '</th>';
        echo '<th>' . esc_html__( 'Signals', 'mighty-shield' ) . '</th>';
        echo '<th></th>';
        echo '</tr></thead><tbody>';

        foreach( $orders as $order ) {

            $rating   = $order->get_meta( '_mshield_ai_rating' );
            $score    = $order->get_meta( '_mshield_ai_score' );
            $signals  = $order->get_meta( '_mshield_ai_signals' );
            $name     = trim( $order->get_formatted_billing_full_name() );
            $email    = $order->get_billing_email();
            $edit_url = $order->get_edit_order_url();

            echo '<tr>';

            echo '<td><a href="' . esc_url( $edit_url ) . '"><strong>#' . esc_html( $order->get_order_number() ) . '</strong></a></td>';

            echo '<td>' . esc_html( wc_format_datetime( $order->get_date_created() ) ) . '</td>';

            echo '<td>';
            if( $name !== '' ) echo esc_html( $name ) . '<br />';
            echo '<span class="description">' . esc_html( $email ) . '</span>';
            echo '</td>';

            echo '<td>' . wp_kses_post( $order->get_formatted_order_total() ) . '</td>';

            echo '<td>' . ( $rating !== '' ? esc_html( $rating . '/10' ) : '&mdash;' ) . '</td>';

            echo '<td>';
            if( is_array( $signals ) && ! empty( $signals ) ) {
                echo esc_html( implode( ', ', $signals ) );
            } elseif( $score !== '' ) {
                echo esc_html( sprintf( __( 'score %s', 'mighty-shield' ), $score ) );
            } else {
                echo '&mdash;';
            }
            echo '</td>';

            echo '<td><a class="button button-primary" href="' . esc_url( $edit_url ) . '">' . esc_html__( 'Review', 'mighty-shield' ) . '</a></td>';

            echo '</tr>';

        }

        echo '</tbody></table>';

        // Pagination.
        if( $pages > 1 ) {
            $base  = menu_page_url( self::SLUG, false );
            $links = paginate_links( [
                'base'      => $base . '%_%',
                'format'    => '&paged=%#%',
                'current'   => $paged,
                'total'     => $pages,
                'prev_text' => '&laquo;',
                'next_text' => '&raquo;',
            ] );
            if( $links ) {
                echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post( $links ) . '</div></div>';
            }
        }

        echo '</div>';

    }

}
