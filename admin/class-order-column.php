<?php
/**
 * The Rating column on the orders list.
 *
 * The panel answers "what did MightyShield think of THIS order". This answers
 * "which of these hundred orders should I be looking at", which is the question
 * a merchant actually arrives with.
 *
 * Reads the rating from order meta rather than from the risk table, and that is
 * the whole performance story: risk_recorder mirrors the trust rating and the
 * risk level onto the order precisely so the admin can show them without a
 * join, and WooCommerce has already loaded the order's meta by the time a
 * column renders. So this costs nothing per row — no query, no cache priming,
 * no N+1. db::get_risk() would have been one query per row for the same two
 * values.
 *
 * @package MightyShield
 * @since   1.9.5
 */
namespace MightyShield\Admin;

use MightyShield\Includes\risk_levels;
use MightyShield\Includes\trust_badge;
use MightyShield\Protection\outcomes;

class order_column {

    /**
     * Column ID.
     *
     * @since   1.9.5
     */
    const COLUMN = 'mshield_rating';

    /**
     * Construct.
     *
     * @since   1.9.5
     */
    public function __construct() {

        // HPOS.
        add_filter( 'woocommerce_shop_order_list_table_columns', [ $this, 'add_column' ] );
        add_action( 'woocommerce_shop_order_list_table_custom_column', [ $this, 'render_hpos' ], 10, 2 );

        // Legacy post storage. Both are registered unconditionally: a store can
        // switch storage at any time, and the inactive pair simply never fires.
        add_filter( 'manage_edit-shop_order_columns', [ $this, 'add_column' ] );
        add_action( 'manage_shop_order_posts_custom_column', [ $this, 'render_legacy' ], 10, 2 );

        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue' ] );

    }

    /**
     * Insert the column after the status.
     *
     * Placed by rebuilding the array rather than appending: appended, it lands
     * after the actions column at the far right, which on a wide order list is
     * off the edge of most screens.
     *
     * @since   1.9.5
     *
     * @param   array   $columns
     * @return  array
     */
    public function add_column( $columns ) {

        if( ! is_array( $columns ) || isset( $columns[ self::COLUMN ] ) ) return $columns;

        $out = [];

        foreach( $columns as $key => $label ) {

            $out[ $key ] = $label;

            if( $key === 'order_status' ) {
                $out[ self::COLUMN ] = __( 'Rating', 'mighty-shield' );
            }

        }

        // No status column on this store's list — fall back to appending rather
        // than silently dropping the column.
        if( ! isset( $out[ self::COLUMN ] ) ) $out[ self::COLUMN ] = __( 'Rating', 'mighty-shield' );

        return $out;

    }

    /**
     * Render the cell under HPOS, which hands over the order itself.
     *
     * @since   1.9.5
     *
     * @param   string      $column
     * @param   \WC_Order   $order
     */
    public function render_hpos( $column, $order ) {

        if( $column !== self::COLUMN ) return;

        echo self::cell( $order ); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in cell().

    }

    /**
     * Render the cell on legacy storage, which hands over a post ID.
     *
     * @since   1.9.5
     *
     * @param   string  $column
     * @param   int     $post_id
     */
    public function render_legacy( $column, $post_id ) {

        if( $column !== self::COLUMN ) return;

        echo self::cell( wc_get_order( $post_id ) ); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in cell().

    }

    /**
     * One cell's markup.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order|false $order
     * @return  string
     */
    public static function cell( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return '';

        // .mshield-scope, not .mshield-app: the tokens without the page chrome.
        // .mshield-app would paint a background and inset itself inside the cell.
        $open = sprintf(
            '<span class="mshield-scope mshield-rating %%s" data-theme="%s"%%s>',
            esc_attr( self::theme() )
        );

        $trust = $order->get_meta( '_mshield_risk_trust' );

        if( $trust === '' || $trust === null ) {

            return sprintf( $open, 's-none', '' )
                . '<span class="ms-none">' . esc_html__( 'Unrated', 'mighty-shield' ) . '</span></span>';

        }

        $level  = (string) $order->get_meta( '_mshield_risk_level' );
        $manual = (string) $order->get_meta( '_mshield_rated_by' ) === 'manual';

        $out = sprintf(
            $open,
            esc_attr( trust_badge::level_class( $level ) ),
            ' title="' . esc_attr( self::tooltip( $order, $trust, $level, $manual ) ) . '"'
        );

        $out .= '<strong class="ms-score">' . esc_html( (string) (int) round( (float) $trust ) ) . '</strong>';

        if( risk_levels::exists( $level ) ) {
            $out .= '<span class="ms-name">' . esc_html( risk_levels::label( $level ) ) . '</span>';
        }

        // A rating worked out after the fact could not replay the bot, timing or
        // device layers. Marked, because a partial 90 and a checkout 90 are not
        // the same statement and the column is where they sit side by side.
        if( $manual ) {
            $out .= '<span class="ms-partial" aria-hidden="true">*</span>';
        }

        return $out . '</span>';

    }

    /**
     * The hover text: the things that do not fit in a list column.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @param   mixed       $trust
     * @param   string      $level
     * @param   bool        $manual
     * @return  string
     */
    private static function tooltip( $order, $trust, $level, $manual ) {

        $parts = [ sprintf(
            /* translators: 1: trust rating, 2: risk level name. */
            __( 'Trust rating %1$d of 100: %2$s', 'mighty-shield' ),
            (int) round( (float) $trust ),
            risk_levels::exists( $level ) ? risk_levels::label( $level ) : __( 'unknown', 'mighty-shield' )
        ) ];

        if( $manual ) {
            $parts[] = __( 'Rated by hand, so this is a partial rating. The checkout-time bot, timing and device checks could not be replayed.', 'mighty-shield' );
        }

        $verdict = outcomes::verdict( $order );

        if( $verdict === 'fraud' ) {
            $parts[] = __( 'You marked this order as fraud.', 'mighty-shield' );
        } elseif( $verdict === 'clean' ) {
            $parts[] = __( 'You marked this order as clean.', 'mighty-shield' );
        }

        return implode( ' ', $parts );

    }

    /**
     * The current user's admin theme, for the token scope.
     *
     * @since   1.9.5
     *
     * @return  string
     */
    private static function theme() {

        $theme = get_user_meta( get_current_user_id(), 'mshield_admin_theme', true );

        return \in_array( $theme, [ 'light', 'dark', 'system' ], true ) ? $theme : 'system';

    }

    /**
     * Load the stylesheet on the orders list.
     *
     * @since   1.9.5
     *
     * @param   string  $hook
     */
    public function enqueue( $hook ) {

        if( ! self::is_list_screen( $hook ) ) return;

        admin_page::enqueue_app_assets();

    }

    /**
     * Whether an admin hook suffix is the orders LIST screen.
     *
     * HPOS serves the list and the single order off the same hook, separated by
     * the edit action — so this is the exact complement of
     * order_panel::is_order_screen().
     *
     * @since   1.9.5
     *
     * @param   string  $hook
     * @return  bool
     */
    public static function is_list_screen( $hook ) {

        if( $hook === 'woocommerce_page_wc-orders' ) {
            return ! isset( $_GET['action'] ) || $_GET['action'] !== 'edit';
        }

        if( $hook === 'edit.php' ) {
            $screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
            return $screen && $screen->post_type === 'shop_order';
        }

        return false;

    }

}
