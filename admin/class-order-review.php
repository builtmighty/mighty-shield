<?php
/**
 * Order Review.
 *
 * Approve/Deny panel on orders the AI review put on hold, so a merchant can
 * settle or release them without hunting through the gateway's own controls.
 *
 * Which panel renders is decided by the GATEWAY's captured-state, never by
 * MightyShield's own _mshield_ai_authorized_only — that records what we asked
 * for, not what happened, and telling a merchant funds are merely reserved when
 * they were actually taken is the worst failure this screen can produce.
 *
 * @package MightyShield
 * @since   1.8.0
 */
namespace MightyShield\Admin;

use MightyShield\Includes\settings;
use MightyShield\Includes\ai_capture;
use MightyShield\Includes\db;
use MightyShield\Firewall\ip_blocklist;

class order_review {

    /**
     * Construct.
     *
     * @since   1.8.0
     */
    public function __construct() {

        // Priority 1 so the panel registers before WooCommerce's own boxes and
        // renders at the top of the order screen.
        add_action( 'add_meta_boxes', [ $this, 'register' ], 1, 2 );
        add_action( 'admin_post_mshield_ai_decision', [ $this, 'handle_decision' ] );

    }

    /**
     * Register the metabox on the order edit screen.
     *
     * @since   1.8.0
     *
     * @param   string  $screen_id  Current screen ID.
     * @param   mixed   $subject    WC_Order under HPOS, WP_Post on legacy.
     */
    public function register( $screen_id = '', $subject = null ) {

        $order = $this->resolve_order( $subject );
        if( ! $order || ! $this->needs_review( $order ) ) return;

        add_meta_box(
            'mshield-order-review',
            __( 'MightyShield — Fraud Review', 'mighty-shield' ),
            [ $this, 'render' ],
            $this->screen(),
            'normal',
            'high'
        );

    }

    /**
     * The order edit screen ID, correct under HPOS and legacy post storage.
     *
     * @since   1.8.0
     *
     * @return  string
     */
    private function screen() {

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
     * @since   1.8.0
     *
     * @param   mixed   $subject
     * @return  \WC_Order|null
     */
    private function resolve_order( $subject ) {

        if( $subject instanceof \WC_Order ) return $subject;

        if( $subject instanceof \WP_Post ) {
            $order = wc_get_order( $subject->ID );
            return $order ? $order : null;
        }

        return null;

    }

    /**
     * Whether this order is awaiting a MightyShield decision.
     *
     * Keys off _mshield_ai_flagged, never the shared _mshield_flagged, which
     * eight other layers also write.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @return  bool
     */
    private function needs_review( $order ) {

        if( $order->get_meta( '_mshield_ai_flagged' ) !== 'ai_review' ) return false;

        // A recorded decision keeps the panel visible so the denial guidance
        // survives a page reload, but a released order drops out entirely.
        if( $order->get_meta( '_mshield_ai_decision' ) === 'approved' ) return false;

        return $order->has_status( 'on-hold' ) || $order->get_meta( '_mshield_ai_decision' ) === 'denied';

    }

    /**
     * Render the panel.
     *
     * @since   1.8.0
     *
     * @param   mixed   $subject    WC_Order under HPOS, WP_Post on legacy.
     */
    public function render( $subject ) {

        $order = $this->resolve_order( $subject );
        if( ! $order ) return;

        $rating     = $order->get_meta( '_mshield_ai_rating' );
        $score      = $order->get_meta( '_mshield_ai_score' );
        $signals    = $order->get_meta( '_mshield_ai_signals' );
        $decision   = $order->get_meta( '_mshield_ai_decision' );
        $authorized = ai_capture::is_authorized( $order );

        echo '<div class="mshield-review">';

        // Verdict summary.
        echo '<p style="margin-top:0;">';
        printf(
            /* translators: 1: AI rating, 2: suspicion score. */
            esc_html__( 'This order was held by AI fraud review with a rating of %1$s/10 (suspicion score %2$s).', 'mighty-shield' ),
            esc_html( $rating !== '' ? $rating : '?' ),
            esc_html( $score !== '' ? $score : '?' )
        );
        echo '</p>';

        if( is_array( $signals ) && ! empty( $signals ) ) {
            echo '<ul style="margin-left:18px;list-style:disc;">';
            foreach( $signals as $signal ) {
                echo '<li>' . esc_html( $signal ) . '</li>';
            }
            echo '</ul>';
        }

        // Denied on a captured order: instructions only, no automatic refund.
        if( $decision === 'denied' ) {
            $this->render_denied_notice( $order );
            echo '</div>';
            return;
        }

        // Funds state — the merchant's most important question.
        echo '<p><strong>';
        echo $authorized
            ? esc_html__( 'The charge is authorized but NOT captured. The funds are reserved, not taken.', 'mighty-shield' )
            : esc_html__( 'The payment has already been captured in full.', 'mighty-shield' );
        echo '</strong></p>';

        echo '<p>';
        echo $authorized
            ? esc_html__( 'Approve captures the authorization and moves the order to Processing. Deny releases the authorization, cancels the order, and blocks the IP.', 'mighty-shield' )
            : esc_html__( 'Approve moves the order to Processing. Deny blocks the IP and gives you refund instructions — it will not refund automatically.', 'mighty-shield' );
        echo '</p>';

        $this->render_buttons( $order );

        echo '</div>';

    }

    /**
     * Render the Approve / Deny controls.
     *
     * Links, not a form. WooCommerce renders order metaboxes inside its own
     * <form id="order">, and browsers drop nested forms — a form here would
     * silently submit WooCommerce's order update instead of our action.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     */
    private function render_buttons( $order ) {

        echo '<p style="display:flex;gap:10px;align-items:center;margin:14px 0 0;">';

        printf(
            '<a href="%s" class="button button-primary">%s</a>',
            esc_url( $this->decision_url( $order, 'approve' ) ),
            esc_html__( 'Approve order', 'mighty-shield' )
        );

        printf(
            '<a href="%s" class="button" onclick="return confirm(\'%s\');">%s</a>',
            esc_url( $this->decision_url( $order, 'deny' ) ),
            esc_attr__( 'Deny this order? This blocks the customer IP and cannot be undone from here.', 'mighty-shield' ),
            esc_html__( 'Deny order', 'mighty-shield' )
        );

        echo '</p>';

    }

    /**
     * Build a nonced URL for one decision.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @param   string      $decision   'approve' or 'deny'.
     * @return  string
     */
    private function decision_url( $order, $decision ) {

        return wp_nonce_url(
            add_query_arg( [
                'action'   => 'mshield_ai_decision',
                'order_id' => $order->get_id(),
                'decision' => $decision,
            ], admin_url( 'admin-post.php' ) ),
            'mshield_ai_decision_' . $order->get_id()
        );

    }

    /**
     * Guidance shown after denying an order whose funds were already captured.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     */
    private function render_denied_notice( $order ) {

        echo '<div class="notice notice-error inline" style="margin:12px 0;padding:10px 12px;">';
        echo '<p style="margin:0 0 6px;"><strong>' . esc_html__( 'This order was denied.', 'mighty-shield' ) . '</strong></p>';
        echo '<p style="margin:0 0 6px;">' . esc_html__( 'The payment was already captured, so MightyShield did not refund it automatically. To finish:', 'mighty-shield' ) . '</p>';
        echo '<ol style="margin:0 0 0 18px;list-style:decimal;">';
        echo '<li>' . esc_html__( 'Refund the order using the Refund button in the order items panel below.', 'mighty-shield' ) . '</li>';
        echo '<li>' . esc_html__( 'Set the order status to Cancelled and update the order.', 'mighty-shield' ) . '</li>';
        echo '</ol>';
        echo '<p style="margin:6px 0 0;">' . esc_html__( 'The customer IP has been added to the MightyShield blocklist.', 'mighty-shield' ) . '</p>';
        echo '</div>';

    }

    /**
     * Handle an Approve / Deny submission.
     *
     * @since   1.8.0
     */
    public function handle_decision() {

        if( ! current_user_can( 'manage_woocommerce' ) ) {
            wp_die( esc_html__( 'You do not have permission to review orders.', 'mighty-shield' ), '', [ 'response' => 403 ] );
        }

        // $_REQUEST so the handler works whether it arrives by link or form;
        // check_admin_referer() reads the nonce from either.
        $order_id = isset( $_REQUEST['order_id'] ) ? absint( $_REQUEST['order_id'] ) : 0;
        $decision = isset( $_REQUEST['decision'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['decision'] ) ) : '';

        check_admin_referer( 'mshield_ai_decision_' . $order_id );

        $order = wc_get_order( $order_id );

        if( ! $order || ! \in_array( $decision, [ 'approve', 'deny' ], true ) ) {
            wp_die( esc_html__( 'Invalid order review request.', 'mighty-shield' ), '', [ 'response' => 400 ] );
        }

        $notice = $decision === 'approve' ? $this->approve( $order ) : $this->deny( $order );

        set_transient( 'mshield_order_notice_' . $order_id, $notice, 60 );

        // A decision removes this order from the Fraud Review queue.
        delete_transient( 'mshield_ai_pending_count' );

        wp_safe_redirect( $order->get_edit_order_url() );
        exit;

    }

    /**
     * Approve an order.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @return  array   [ message, type ]
     */
    private function approve( $order ) {

        // Capture first when funds are only reserved. An order must never move
        // to Processing on the strength of money that did not actually move.
        if( ai_capture::is_authorized( $order ) ) {

            $result = ai_capture::capture( $order );

            if( is_wp_error( $result ) ) {

                $order->add_order_note( 'MightyShield: ' . sprintf(
                    /* translators: %s: gateway error. */
                    __( 'Approve failed — the authorization could not be captured: %s. The order remains on hold.', 'mighty-shield' ),
                    $result->get_error_message()
                ) );

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
            $order->update_status( 'processing', __( 'MightyShield: approved in fraud review.', 'mighty-shield' ) );
        } else {
            $order->add_order_note( 'MightyShield: ' . __( 'Approved in fraud review.', 'mighty-shield' ) );
        }

        $order->update_meta_data( '_mshield_ai_decision', 'approved' );
        $order->save();

        db::log_event( $order->get_customer_ip_address(), 'ai_review', 'flagged', 'Order #' . $order->get_id() . ' approved in fraud review' );

        return [ __( 'Order approved.', 'mighty-shield' ), 'success' ];

    }

    /**
     * Deny an order.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @return  array   [ message, type ]
     */
    private function deny( $order ) {

        $authorized = ai_capture::is_authorized( $order );
        $blocked    = $this->blocklist_ip( $order );

        $order->update_meta_data( '_mshield_ai_decision', 'denied' );

        if( $authorized ) {

            $result = ai_capture::void( $order );

            if( is_wp_error( $result ) ) {

                $order->update_meta_data( '_mshield_ai_decision', '' );
                $order->add_order_note( 'MightyShield: ' . sprintf(
                    /* translators: %s: gateway error. */
                    __( 'Deny failed — the authorization could not be released: %s. The order remains on hold.', 'mighty-shield' ),
                    $result->get_error_message()
                ) );
                $order->save();

                return [ sprintf(
                    /* translators: %s: gateway error. */
                    __( 'Could not release the authorization: %s. The order is still on hold.', 'mighty-shield' ),
                    $result->get_error_message()
                ), 'error' ];

            }

            $order->add_order_note( 'MightyShield: ' . __( 'Denied in fraud review — authorization released.', 'mighty-shield' ) );
            $order->save();

            // Some gateways cancel the order themselves once the void lands.
            $order = wc_get_order( $order->get_id() );
            if( ! $order->has_status( 'cancelled' ) ) {
                $order->update_status( 'cancelled', __( 'MightyShield: denied in fraud review.', 'mighty-shield' ) );
            }

            $message = $blocked
                ? __( 'Order denied. The authorization was released, the order cancelled, and the IP blocked.', 'mighty-shield' )
                : __( 'Order denied. The authorization was released and the order cancelled.', 'mighty-shield' );

        } else {

            $order->add_order_note( 'MightyShield: ' . __( 'Denied in fraud review. The payment was already captured — refund and cancel manually.', 'mighty-shield' ) );
            $order->save();

            $message = $blocked
                ? __( 'Order denied and the IP blocked. Refund and cancel the order manually — see the panel at the top of this order.', 'mighty-shield' )
                : __( 'Order denied. Refund and cancel the order manually — see the panel at the top of this order.', 'mighty-shield' );

        }

        db::log_event( $order->get_customer_ip_address(), 'ai_review', 'blocked', 'Order #' . $order->get_id() . ' denied in fraud review' );

        return [ $message, 'success' ];

    }

    /**
     * Add the order's IP to the blocklist.
     *
     * A duplicate returns false from add_ip(), which means "already blocked" —
     * not a failure, so it is not surfaced as one.
     *
     * @since   1.8.0
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
            'Denied in AI order review'
        );

    }

    /**
     * Show the result of a decision on the order screen.
     *
     * @since   1.8.0
     */
    public static function render_notice() {

        $screen = get_current_screen();
        if( ! $screen ) return;

        $order_id = isset( $_GET['id'] ) ? absint( $_GET['id'] ) : ( isset( $_GET['post'] ) ? absint( $_GET['post'] ) : 0 );
        if( ! $order_id ) return;

        $notice = get_transient( 'mshield_order_notice_' . $order_id );
        if( ! $notice || ! is_array( $notice ) || count( $notice ) !== 2 ) return;

        delete_transient( 'mshield_order_notice_' . $order_id );

        printf(
            '<div class="notice notice-%s is-dismissible"><p><strong>%s</strong> %s</p></div>',
            esc_attr( $notice[1] === 'error' ? 'error' : 'success' ),
            esc_html__( 'MightyShield:', 'mighty-shield' ),
            esc_html( $notice[0] )
        );

    }

}
