<?php
/**
 * AI review, off the shopper's request.
 *
 * Inline review runs at checkout validation, which is the only moment an
 * authorize-only hold can be armed and the only moment a checkout can still
 * be refused. It is also ten seconds of a provider's latency added to the
 * request the customer is sitting in front of, and when that provider has a
 * bad afternoon the store's conversion rate has one too.
 *
 * Async trades the first for the second. The order is created and paid for
 * normally; the review happens moments later on a scheduled run, and anything
 * it finds arrives through the post-payment hold route -- the same one the
 * card checks use when a processor answers after the money has moved. What it
 * cannot do is stop the charge, because by then there is one. A merchant
 * choosing this mode is saying that a fast checkout matters more than holding
 * the card before it is charged, which for most stores it does.
 *
 * @package MightyShield
 * @since   3.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\actions;
use MightyShield\Includes\db;
use MightyShield\Includes\exempt;
use MightyShield\Includes\response;
use MightyShield\Includes\risk_context;
use MightyShield\Includes\risk_levels;
use MightyShield\Includes\settings;

defined( 'ABSPATH' ) || exit;

class ai_async {

    /**
     * The scheduled hook.
     *
     * @since   3.0.0
     */
    const HOOK = 'mshield_ai_review_order';

    /**
     * Seconds to wait before reviewing.
     *
     * Short enough that a held order is held before anybody picks it, long
     * enough that the checkout request -- and the gateway's own webhooks --
     * have finished writing to the order first.
     *
     * @since   3.0.0
     */
    const DELAY = 15;

    /**
     * How long a queued review may go unrun before the sweeper takes it.
     *
     * WP-Cron needs a visitor, Action Scheduler needs a working loopback, and
     * a store can be short of both at three in the morning. An order queued
     * for review and never reviewed is an order that quietly skipped the
     * feature the merchant is paying for, so something has to notice.
     *
     * @since   3.0.0
     */
    const STALE = 1800;

    /**
     * How many times one order's review may be attempted.
     *
     * The queue mark now survives a failed run so the sweeper can find the
     * order again. Without a ceiling, a review that reliably kills the process
     * would be retried forever. Three rides out a provider having a bad
     * minute; a genuinely poisoned order stops on its own and says so.
     *
     * @since   3.0.0
     */
    const MAX_ATTEMPTS = 3;

    /**
     * Construct.
     *
     * @since   3.0.0
     */
    public function __construct() {

        // The handler is registered whatever the mode. A merchant who switches
        // back to inline while reviews are queued should still get the ones
        // already promised, rather than a silent gap.
        add_action( self::HOOK, [ __CLASS__, 'run' ], 10, 1 );
        add_action( 'mshield_daily_cleanup', [ __CLASS__, 'sweep' ] );

        if( settings::get( 'mshield_ai_enabled' ) !== 'yes' ) return;
        if( settings::get( 'mshield_ai_mode' ) !== 'async' )   return;

        // After the order exists and the checkout has been answered. Both
        // checkouts fire one of these exactly once per placed order.
        add_action( 'woocommerce_checkout_order_processed', [ __CLASS__, 'queue' ], 30, 1 );
        add_action( 'woocommerce_store_api_checkout_order_processed', [ __CLASS__, 'queue' ], 30, 1 );

    }

    /**
     * Whether reviews are running off the checkout request.
     *
     * @since   3.0.0
     *
     * @return  bool
     */
    public static function enabled() {

        return settings::get( 'mshield_ai_enabled' ) === 'yes'
            && settings::get( 'mshield_ai_mode' ) === 'async';

    }

    /**
     * Put an order in the queue.
     *
     * @since   3.0.0
     *
     * @param   int|\WC_Order   $order
     */
    public static function queue( $order ) {

        $order = is_a( $order, 'WC_Order' ) ? $order : wc_get_order( $order );
        if( ! $order ) return;

        $id = $order->get_id();

        // The mark is what the sweeper looks for if the scheduled run never
        // happens. Nothing displays it: in async mode the order panel shows
        // the signal-only rating written at checkout, with nothing saying it
        // is about to change.
        $order->update_meta_data( '_mshield_ai_queued', time() );
        $order->save();

        self::schedule( $id );

    }

    /**
     * Schedule one review.
     *
     * @since   3.0.0
     *
     * @param   int     $order_id
     */
    private static function schedule( $order_id ) {

        // Action Scheduler when WooCommerce has it, which is always in
        // practice: it works its queue over the loopback rather than waiting
        // for the next visitor the way WP-Cron does, and this is a review a
        // merchant is waiting on.
        if( function_exists( 'as_schedule_single_action' ) && function_exists( 'as_next_scheduled_action' ) ) {

            if( ! as_next_scheduled_action( self::HOOK, [ $order_id ] ) ) {
                as_schedule_single_action( time() + self::DELAY, self::HOOK, [ $order_id ], 'mighty-shield' );
            }

            return;

        }

        if( ! wp_next_scheduled( self::HOOK, [ $order_id ] ) ) {
            wp_schedule_single_event( time() + self::DELAY, self::HOOK, [ $order_id ] );
        }

    }

    /**
     * Review one order, and act on what comes back.
     *
     * Modelled on the post-payment card pass, because it is the same problem:
     * a verdict arriving on a request the shopper is not making, that has to
     * be added to what the checkout already knew rather than replacing it.
     *
     * @since   3.0.0
     *
     * @param   int     $order_id
     */
    public static function run( $order_id ) {

        $order = wc_get_order( $order_id );
        if( ! $order ) return;

        // Nothing queued, or somebody got there first -- a reviewer clicking
        // Rate order, or the merchant switching back to inline mid-flight.
        if( (string) $order->get_meta( '_mshield_ai_queued' ) === '' ) return;

        if( (string) $order->get_meta( '_mshield_ai_rating' ) !== '' ) {
            self::dequeue( $order );
            return;
        }

        // The mark is cleared at the END of a successful run, not here.
        //
        // Clearing it first looked tidy and lost orders: the provider hangs,
        // the request outlives PHP's max_execution_time -- Action Scheduler
        // works a batch of up to 25 under a time limit, so this is ordinary
        // rather than exotic -- and the process is killed inside the HTTP
        // call. The mark was already deleted and committed, sweep() looks for
        // exactly that mark, and the order was never reviewed again with
        // nothing anywhere recording that a review was owed.
        //
        // What stops a poisoned order retrying forever is the attempt count,
        // not the mark.
        $attempts = (int) $order->get_meta( '_mshield_ai_attempts' );

        if( $attempts >= self::MAX_ATTEMPTS ) {
            self::dequeue( $order );
            db::log_event(
                \MightyShield\Includes\ip_utils::order_ip( $order ),
                'ai_review',
                'degraded',
                sprintf( 'Gave up reviewing order #%d after %d attempts', $order_id, $attempts ),
                '',
                $order_id
            );
            return;
        }

        $order->update_meta_data( '_mshield_ai_attempts', $attempts + 1 );
        $order->save();

        // Everything the checkout worked out, put back. Without this the model
        // would be shown an order with no signals on it and the ladder would
        // then rate it on the model's opinion alone -- which is the shape of
        // the 1.8.1 engine this one replaced.
        risk_context::reset();

        try {

            $stored = db::get_risk( $order_id );

            if( ! empty( $stored['signals'] ) ) {
                $signals = json_decode( (string) $stored['signals'], true );
                if( is_array( $signals ) ) risk_context::restore( $signals );
            }

            // The same gate as the inline path: only the levels the merchant
            // marked for review, and never an order already floored. A no is a
            // finished run, not a failed one, so the mark comes off.
            if( ! ai_reviewer::review_async( $order ) ) {
                self::dequeue( $order );
                return;
            }

            $verdict = risk_context::evaluate();

            $action = self::action_for( $order, risk_levels::action( $verdict['risk_level'] ) );

            $exempt = exempt::suppresses_action_for_order( $order );

            // The row keeps its place in the reporting windows: this is the
            // same order rated late, not a new one.
            db::save_risk( $order_id, [
                'trust'             => $verdict['trust'],
                'risk_level'        => $verdict['risk_level'],
                'risk_level_source' => $verdict['risk_level_source'],
                'action_taken'      => $exempt ? 'exempt' : ( response::is_enforcing() ? $action : 'observed' ),
                'signals'           => risk_context::to_array()['signals'],
                'rated_by'          => 'ai',
                'created_at'        => $stored['created_at'] ?? '',
                'outcome'           => $stored['outcome'] ?? '',
                'ai_rating'         => (int) $order->get_meta( '_mshield_ai_rating' ),
                'ai_verdict'        => (string) $order->get_meta( '_mshield_ai_verdict' ),
            ] );

            $order->update_meta_data( '_mshield_risk_trust', $verdict['trust'] );
            $order->update_meta_data( '_mshield_risk_level', $verdict['risk_level'] );
            $order->save();

            db::log_event(
                \MightyShield\Includes\ip_utils::order_ip( $order ),
                'ai_review',
                'flagged',
                sprintf( 'Reviewed after checkout: trust %s/100 → %s', $verdict['trust'], risk_levels::label( $verdict['risk_level'] ) ),
                '',
                $order_id,
                db::log_trust( $order )
            );

            if( ! $exempt && response::is_enforcing() && $action !== actions::NONE ) {

                response::dispatch( $order, $action, sprintf(
                    'Reviewed after checkout. Trust rating %s/100 → %s. Signals: %s.',
                    $verdict['trust'],
                    risk_levels::label( $verdict['risk_level'] ),
                    implode( '; ', risk_context::reasons() )
                ) );

            }

            self::dequeue( $order );

        } finally {

            risk_context::reset();

        }

    }

    /**
     * Take an order out of the queue.
     *
     * @since   3.0.0
     *
     * @param   \WC_Order   $order
     */
    private static function dequeue( $order ) {

        $order->delete_meta_data( '_mshield_ai_queued' );
        $order->delete_meta_data( '_mshield_ai_attempts' );
        $order->save();

    }

    /**
     * What this verdict can still do to the order, at this moment.
     *
     * resolve_post_payment() is the right answer for the card pass, which only
     * ever runs for a real card processor once money has moved. On its own it
     * is the wrong answer here: this review is scheduled from
     * woocommerce_checkout_order_processed, which runs BEFORE process_payment,
     * so on a bank transfer, cheque or cash-on-delivery order there may be no
     * money at all fifteen seconds later.
     *
     * Collapsing a refusal to hold_paid on one of those wrote the money has
     * been taken onto an order nobody had paid for -- and order_panel's
     * has_money() reads that same meta, so Approve then skipped its own guard
     * against moving an unpaid order to Processing and the merchant shipped
     * against a bank transfer that never arrived.
     *
     * @since   3.0.0
     *
     * @param   \WC_Order   $order
     * @param   string      $action
     * @return  string
     */
    private static function action_for( $order, $action ) {

        // Paid, or the funds are reserved: the card pass's assumption holds,
        // and refusing or authorizing really are off the table.
        if( $order->is_paid() || $order->get_date_paid() ) {
            return actions::resolve_post_payment( $action, $order );
        }

        // Otherwise the order is in exactly the position the inline path would
        // have found it in, so it gets the inline answer -- which knows about
        // offline gateways and routes them to an unpaid hold.
        return actions::resolve( $action, $order );

    }

    /**
     * Pick up reviews that were queued and never ran.
     *
     * @since   3.0.0
     */
    public static function sweep() {

        if( ! function_exists( 'wc_get_orders' ) ) return;

        $orders = wc_get_orders( [
            'limit'      => 50,
            'return'     => 'ids',
            'meta_query' => [ // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query -- a daily batch of 50, not a request
                [
                    'key'     => '_mshield_ai_queued',
                    'value'   => time() - self::STALE,
                    'compare' => '<',
                    'type'    => 'NUMERIC',
                ],
            ],
        ] );

        foreach( (array) $orders as $id ) {
            self::run( (int) $id );
        }

    }

}
