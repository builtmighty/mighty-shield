<?php
/**
 * Outcome learning.
 *
 * Closes the loop. Every verdict this plugin makes is eventually judged by
 * reality — the order ships fine, or it gets refunded, or the bank claws the
 * money back — and until now none of that came back to inform the next
 * decision. Approve/Deny in the review queue blocklisted an IP and nothing more.
 *
 * This records what actually happened against every identity on the order, so
 * Phase 1 scores the next order from the same buyer, device, address or card
 * with the benefit of hindsight.
 *
 * Two design rules:
 *
 * 1. Outcomes are recorded ONCE per order. A refund that fires several status
 *    transitions, or a webhook redelivered by the gateway, must not stack
 *    penalties onto an identity that only did one bad thing.
 * 2. Severity is ordered. A chargeback outranks a manual fraud report, which
 *    outranks a refund, which outranks a clean completion — so a later, worse
 *    outcome can overwrite an earlier, milder one, but never the reverse.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\db;
use MightyShield\Includes\entities;

class outcomes {

    /**
     * Outcome severity, low to high.
     *
     * An outcome may only be replaced by one further down this list.
     *
     * @since   1.9.0
     */
    const SEVERITY = [
        'approved'   => 0,
        'refunded'   => 1,
        'denied'     => 2,
        'chargeback' => 3,
    ];

    /**
     * Construct.
     *
     * @since   1.9.0
     */
    public function __construct() {

        // Gateway-agnostic, from WooCommerce core. These work on every store
        // regardless of processor.
        add_action( 'woocommerce_order_status_refunded',  [ $this, 'on_refunded' ], 10, 1 );
        add_action( 'woocommerce_order_status_completed', [ $this, 'on_completed' ], 10, 1 );

        // Stripe exposes no dispute-specific action, but its webhook handler
        // does pass the event type and the resolved order, which is enough.
        add_action( 'wc_stripe_webhook_received', [ $this, 'on_stripe_webhook' ], 10, 3 );

        // Merchant-driven, and the only source that works on every gateway:
        // someone looked at the order and called it fraud.
        add_filter( 'bulk_actions-woocommerce_page_wc-orders', [ $this, 'add_bulk_action' ] );
        add_filter( 'bulk_actions-edit-shop_order',            [ $this, 'add_bulk_action' ] );
        add_filter( 'handle_bulk_actions-woocommerce_page_wc-orders', [ $this, 'handle_bulk_action' ], 10, 3 );
        add_filter( 'handle_bulk_actions-edit-shop_order',            [ $this, 'handle_bulk_action' ], 10, 3 );
        add_action( 'admin_notices', [ $this, 'bulk_action_notice' ] );

    }

    /**
     * Record an outcome against every identity on an order.
     *
     * @since   1.9.0
     *
     * @param   int|\WC_Order   $order      Order or order ID.
     * @param   string          $outcome    approved | refunded | denied | chargeback.
     * @return  bool    True when the outcome was recorded.
     */
    public static function record( $order, $outcome ) {

        if( ! isset( self::SEVERITY[ $outcome ] ) ) return false;

        $order = is_object( $order ) ? $order : wc_get_order( $order );
        if( ! $order ) return false;

        // A person looked at this order and ruled on it. Nothing automatic
        // overrides that — not a later completion, not a redelivered dispute
        // webhook. The reviewer can still change their own mind through
        // set_manual(), which is the only way this is ever revised.
        if( (string) $order->get_meta( '_mshield_review' ) !== '' ) return false;

        $existing = (string) $order->get_meta( '_mshield_outcome' );

        // Already recorded something at least this bad — leave it alone. This
        // is what stops a redelivered webhook or a multi-step refund from
        // penalising an identity several times for one event.
        if( $existing !== '' && isset( self::SEVERITY[ $existing ] )
            && self::SEVERITY[ $existing ] >= self::SEVERITY[ $outcome ] ) {
            return false;
        }

        // An identity set is normally written at checkout by the risk recorder.
        // Orders that predate this version have none, so derive and link them
        // now — otherwise the whole back catalogue is unusable as training data.
        self::ensure_linked( $order );

        entities::record_outcome( $order->get_id(), $outcome );

        $order->update_meta_data( '_mshield_outcome', $outcome );
        $order->save();

        db::set_risk_outcome( $order->get_id(), $outcome );

        db::log_event(
            $order->get_customer_ip_address(),
            'outcome',
            'flagged',
            sprintf( 'Order #%d recorded as %s — identity reputation updated', $order->get_id(), $outcome ),
            '',
            (int) $order->get_id()
        );

        return true;

    }

    /**
     * A human verdict on one order, changeable in both directions.
     *
     * The automatic path is a ratchet — an outcome may only ever get worse —
     * because a redelivered webhook or a multi-step refund must not stack
     * penalties onto an identity that did one thing. A reviewer is the opposite
     * case: they are the authority, they are allowed to be wrong, and a
     * chargeback that turns out to be a family member using the card has to be
     * takeable back.
     *
     * So this reverses whatever was recorded before applying the new verdict.
     * Without that step "Fraud" then "Clean" would leave the identity carrying
     * both a -25 and a +1 — relabelled, but still condemned.
     *
     * @since   1.9.5
     *
     * @param   int|\WC_Order   $order
     * @param   string          $verdict    'fraud' or 'clean'.
     * @return  bool    True when the verdict was recorded or changed.
     */
    public static function set_manual( $order, $verdict ) {

        // Deliberately NOT 'chargeback' for fraud: a chargeback floors the
        // identity straight to banned, and a reviewer's judgement should not be
        // indistinguishable from the bank actually taking the money back.
        $map = [ 'fraud' => 'denied', 'clean' => 'approved' ];

        if( ! isset( $map[ $verdict ] ) ) return false;

        $order = is_object( $order ) ? $order : wc_get_order( $order );
        if( ! $order ) return false;

        $outcome  = $map[ $verdict ];
        $existing = (string) $order->get_meta( '_mshield_outcome' );

        // Same verdict twice is a no-op, not a second helping of reputation.
        if( (string) $order->get_meta( '_mshield_review' ) === $verdict && $existing === $outcome ) {
            return false;
        }

        // Identities first: an order placed before the identity graph existed
        // has nothing to reverse or credit until it is linked.
        self::ensure_linked( $order );

        if( $existing !== '' && isset( self::SEVERITY[ $existing ] ) ) {
            entities::reverse_outcome( $order->get_id(), $existing );
        }

        entities::record_outcome( $order->get_id(), $outcome );

        $order->update_meta_data( '_mshield_review', $verdict );
        $order->update_meta_data( '_mshield_outcome', $outcome );
        $order->add_order_note( 'MightyShield: ' . (
            $verdict === 'fraud'
                ? __( 'Marked as fraud by a reviewer. Future orders from this customer, device, address or network will be scored accordingly.', 'mighty-shield' )
                : __( 'Marked as clean by a reviewer. Any penalty this order placed on the customer has been taken back.', 'mighty-shield' )
        ) );
        $order->save();

        db::set_risk_outcome( $order->get_id(), $outcome );

        db::log_event(
            $order->get_customer_ip_address(),
            'outcome',
            $verdict === 'fraud' ? 'blocked' : 'flagged',
            sprintf( 'Order #%d marked %s by a reviewer — identity reputation updated', $order->get_id(), $verdict ),
            '',
            (int) $order->get_id()
        );

        return true;

    }

    /**
     * The reviewer's verdict on an order, if one has been given.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @return  string  'fraud', 'clean', or '' when nobody has ruled.
     */
    public static function verdict( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return '';

        $verdict = (string) $order->get_meta( '_mshield_review' );

        return \in_array( $verdict, [ 'fraud', 'clean' ], true ) ? $verdict : '';

    }

    /**
     * Make sure the order's identities exist and are linked to it.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     */
    private static function ensure_linked( $order ) {

        global $wpdb;

        $linked = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}mshield_entity_links WHERE order_id = %d",
            $order->get_id()
        ) );

        if( $linked > 0 ) return;

        $identities = entities::for_order( $order );
        if( empty( $identities ) ) return;

        entities::record( $identities, $order->get_id() );

    }

    /**
     * A refund is weak evidence — most refunds are ordinary retail returns.
     *
     * @since   1.9.0
     *
     * @param   int     $order_id
     */
    public function on_refunded( $order_id ) {

        self::record( $order_id, 'refunded' );

    }

    /**
     * A completed order is the only positive signal available, and it is what
     * lets a genuine repeat customer earn their way into the trusted risk level.
     *
     * Deliberately recorded even though a chargeback can still arrive months
     * later: the severity ordering means that later chargeback overwrites this,
     * and its far heavier penalty swamps the small credit given here.
     *
     * @since   1.9.0
     *
     * @param   int     $order_id
     */
    public function on_completed( $order_id ) {

        self::record( $order_id, 'approved' );

    }

    /**
     * Catch disputes from the Stripe webhook stream.
     *
     * @since   1.9.0
     *
     * @param   string          $type           Webhook event type.
     * @param   object          $notification   Raw event.
     * @param   \WC_Order|null  $order          Resolved order, if any.
     */
    public function on_stripe_webhook( $type, $notification, $order ) {

        if( $type !== 'charge.dispute.created' ) return;
        if( ! $order ) return;

        self::record( $order, 'chargeback' );

    }

    /**
     * Add the manual fraud report to the orders list.
     *
     * @since   1.9.0
     *
     * @param   array   $actions
     * @return  array
     */
    public function add_bulk_action( $actions ) {

        $actions['mshield_report_fraud'] = __( 'Report as fraud (MightyShield)', 'mighty-shield' );

        return $actions;

    }

    /**
     * Handle the manual fraud report.
     *
     * Recorded as "denied" rather than "chargeback": a chargeback floors the
     * identity straight to the banned risk level, and a misclick on a bulk action
     * should not permanently bar a real customer. Denied still weighs heavily
     * enough to detain the next order from that identity.
     *
     * @since   1.9.0
     *
     * @param   string  $redirect
     * @param   string  $action
     * @param   array   $ids
     * @return  string
     */
    public function handle_bulk_action( $redirect, $action, $ids ) {

        if( $action !== 'mshield_report_fraud' ) return $redirect;

        if( ! current_user_can( 'manage_woocommerce' ) ) return $redirect;

        $count = 0;

        foreach( (array) $ids as $id ) {
            if( self::record( (int) $id, 'denied' ) ) $count++;
        }

        return add_query_arg( 'mshield_reported', $count, $redirect );

    }

    /**
     * Confirm the manual report.
     *
     * @since   1.9.0
     */
    public function bulk_action_notice() {

        if( ! isset( $_GET['mshield_reported'] ) ) return;

        $count = (int) $_GET['mshield_reported'];

        printf(
            '<div class="notice notice-success is-dismissible"><p>%s</p></div>',
            esc_html( sprintf(
                /* translators: %d: number of orders. */
                _n(
                    '%d order reported as fraud. MightyShield will weigh this against future orders from the same customer, device, address or network.',
                    '%d orders reported as fraud. MightyShield will weigh these against future orders from the same customers, devices, addresses or networks.',
                    $count,
                    'mighty-shield'
                ),
                $count
            ) )
        );

    }

}
