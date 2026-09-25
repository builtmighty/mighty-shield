<?php
/**
 * Rating the orders that came before MightyShield.
 *
 * A new install knows nothing. The identity graph is empty, so no returning
 * customer earns trust and no previous chargeback counts against anybody, and
 * it stays that way until enough orders have come through to build a history
 * — which on a quiet store is months. That is the worst possible time to be
 * making decisions, and it is exactly when the merchant is deciding whether
 * the plugin is any good.
 *
 * This walks the store's existing orders through rescore::run(), which fills
 * the identity graph and writes a risk row for each. Afterwards the first
 * real order is judged against the store's actual history instead of against
 * nothing.
 *
 * Three things worth knowing before changing anything here.
 *
 * It is batched because it has to be. rescore::run() is not cheap per order:
 * address_velocity alone does up to fifty order lookups, and the entity graph
 * costs a query on top. A store with 40,000 orders is not a request, it is an
 * afternoon, so this runs in batches on Action Scheduler and keeps its place.
 *
 * It pages by offset over a list frozen at the start. The candidate set is
 * every order placed before the moment the run began, sorted by id, so an
 * order arriving mid-run cannot shift it. What can is an order deleted or
 * moved out of the set while the run is in progress, which shifts the
 * offset by one and skips one order; that is rare enough to accept, and the
 * run's counts say how many it rated. (An earlier draft of this comment
 * promised an id cursor; the code never had one.) A cursor would not
 * be disturbed by anything arriving after it.
 *
 * It takes no action, ever. rescore::run() is read-only by design: it records
 * a rating and dispatches nothing. Rating a shipped order from last year must
 * never cancel it, email anybody, or put it on hold.
 *
 * @package MightyShield
 * @since   2.3.0
 */
namespace MightyShield\Includes;

defined( 'ABSPATH' ) || exit;

class backfill {

    /**
     * The Action Scheduler hook, and the WP-Cron one when Action Scheduler is
     * not available.
     *
     * @since   2.3.0
     */
    const HOOK = 'mshield_backfill_batch';

    /**
     * Where the run keeps its place.
     *
     * @since   2.3.0
     */
    const STATE = 'mshield_backfill';

    /**
     * Orders per batch.
     *
     * Small on purpose. The ceiling is not the database, it is
     * address_velocity's fifty lookups per order on a shared host with a
     * thirty-second limit.
     *
     * @since   2.3.0
     */
    const BATCH = 20;

    /**
     * How far back to go, in days. 0 means everything.
     *
     * @since   2.3.0
     */
    const DEFAULT_DAYS = 365;

    /**
     * Register the batch handler.
     *
     * @since   2.3.0
     */
    public static function register() {

        add_action( self::HOOK, [ __CLASS__, 'run_batch' ] );

        // Watchdog. The next batch is queued at the end of the current one,
        // so a batch killed mid-run -- a PHP timeout, a host restart -- left
        // the run saying "running" with nothing scheduled, for good. On admin
        // and cron requests only: the state option is not autoloaded, and a
        // shopper's request should not pay a query to check on it.
        if( is_admin() || wp_doing_cron() ) {
            add_action( 'init', [ __CLASS__, 'resume_if_stranded' ], 30 );
        }

    }

    /**
     * Re-queue a run that is marked running but has no batch scheduled.
     *
     * @since   2.3.0
     */
    public static function resume_if_stranded() {

        $state = self::state();
        if( $state['status'] !== 'running' ) return;

        $queued = ( function_exists( 'as_next_scheduled_action' ) && as_next_scheduled_action( self::HOOK ) )
               || wp_next_scheduled( self::HOOK );

        if( ! $queued ) self::schedule();

    }

    /**
     * Begin, or restart, a backfill.
     *
     * @since   2.3.0
     *
     * @param   int     $days   How far back to reach. 0 for everything.
     * @return  array|\WP_Error The starting state.
     */
    public static function start( $days = self::DEFAULT_DAYS ) {

        if( ! function_exists( 'wc_get_orders' ) ) {
            return new \WP_Error( 'mshield_no_wc', __( 'WooCommerce is not available.', 'mighty-shield' ) );
        }

        $days = max( 0, (int) $days );

        $ceiling = time();

        $state = [
            'status'  => 'running',
            'days'    => $days,
            // Frozen at the start. See query_args() -- this is what makes
            // paging by offset safe while the store keeps taking orders.
            'ceiling' => $ceiling,
            // How many rows the offset has already stepped past, including
            // ones that failed to load. Distinct from 'done', which counts
            // only orders actually rated.
            'seen'    => 0,
            'done'    => 0,
            'failed'  => 0,
            'total'   => self::count_candidates( $days, $ceiling ),
            'started' => $ceiling,
            'ended'   => 0,
        ];

        update_option( self::STATE, $state, false );

        if( $state['total'] === 0 ) {

            $state['status'] = 'complete';
            $state['ended']  = time();
            update_option( self::STATE, $state, false );

            return $state;

        }

        self::schedule();

        return $state;

    }

    /**
     * Stop a run in progress, keeping what it has already done.
     *
     * @since   2.3.0
     */
    public static function cancel() {

        $state = self::state();

        if( $state['status'] === 'running' ) {
            $state['status'] = 'cancelled';
            $state['ended']  = time();
            update_option( self::STATE, $state, false );
        }

        if( function_exists( 'as_unschedule_all_actions' ) ) {
            as_unschedule_all_actions( self::HOOK );
        }

        $next = wp_next_scheduled( self::HOOK );
        if( $next ) wp_unschedule_event( $next, self::HOOK );

    }

    /**
     * The current state, in a known shape.
     *
     * @since   2.3.0
     *
     * @return  array
     */
    public static function state() {

        $state = get_option( self::STATE, [] );

        if( ! is_array( $state ) ) $state = [];

        return array_merge( [
            'status'  => 'idle',
            'days'    => self::DEFAULT_DAYS,
            'ceiling' => 0,
            'seen'    => 0,
            'done'    => 0,
            'failed'  => 0,
            'total'   => 0,
            'started' => 0,
            'ended'   => 0,
        ], $state );

    }

    /**
     * Rate one batch, then queue the next.
     *
     * @since   2.3.0
     */
    public static function run_batch() {

        $state = self::state();

        if( $state['status'] !== 'running' ) return;

        $ids = self::next_ids( $state );

        if( empty( $ids ) ) {

            $state['status'] = 'complete';
            $state['ended']  = time();
            update_option( self::STATE, $state, false );

            return;

        }

        foreach( $ids as $id ) {

            // The offset moves whether or not the order rates, so one
            // unloadable order cannot wedge the run in a loop on itself.
            $state['seen']++;

            $order = wc_get_order( $id );

            if( ! $order ) {
                $state['failed']++;
                continue;
            }

            // Never over a rating the checkout produced. That row is what the
            // order actually scored with every signal live, and what forecast
            // and the tuning report are built on; a re-rate replays a fraction
            // of the signals and stamps itself 'manual', which drops the row
            // out of both. The back catalogue is the orders placed before
            // MightyShield was there to see them, and only those.
            $existing = db::get_risk( $order->get_id() );

            if( $existing && in_array( (string) ( $existing['rated_by'] ?? '' ), [ 'checkout', '', 'card' ], true ) ) {
                $state['skipped'] = ( $state['skipped'] ?? 0 ) + 1;
                continue;
            }

            // Never with AI. This is a bulk pass over a back catalogue and
            // the provider bills per call -- a merchant who clicks "rate my
            // past orders" has not agreed to buy an opinion on every one of
            // forty thousand of them. rescore offers AI for the single-order
            // button, where somebody chose it.
            $result = rescore::run( $order, false );

            if( is_wp_error( $result ) ) {
                $state['failed']++;
                continue;
            }

            // What the order became. rescore links the identities and counts
            // the order against them, but a count is not a verdict: without
            // this every pre-install customer had orders and no approvals, so
            // none of them could earn trust and none of the refunds counted.
            // Only outcomes the store reached on its own; a cancellation is
            // ambiguous and stays out.
            if( ! class_exists( '\MightyShield\Protection\outcomes' ) ) {
                require_once MSHIELD_PATH . 'protection/class-outcomes.php';
            }

            $status = $order->get_status();

            if( $status === 'completed' ) {
                \MightyShield\Protection\outcomes::record( $order, 'approved' );
            } elseif( $status === 'refunded' ) {
                \MightyShield\Protection\outcomes::record( $order, 'refunded' );
            }

            $state['done']++;

        }

        update_option( self::STATE, $state, false );

        self::schedule();

    }

    /**
     * Queue the next batch.
     *
     * @since   2.3.0
     */
    private static function schedule() {

        // Action Scheduler when WooCommerce has it, which is always in
        // practice, because it processes its queue over the loopback rather
        // than waiting for the next visitor the way WP-Cron does.
        if( function_exists( 'as_schedule_single_action' ) && function_exists( 'as_next_scheduled_action' ) ) {

            if( ! as_next_scheduled_action( self::HOOK ) ) {
                as_schedule_single_action( time() + 10, self::HOOK, [], 'mighty-shield' );
            }

            return;

        }

        if( ! wp_next_scheduled( self::HOOK ) ) {
            wp_schedule_single_event( time() + 60, self::HOOK );
        }

    }

    /**
     * How many orders are in scope.
     *
     * @since   2.3.0
     *
     * @param   int     $days
     * @return  int
     */
    private static function count_candidates( $days, $ceiling ) {

        $args = self::query_args( $days, $ceiling );

        $args['limit']    = -1;
        $args['return']   = 'ids';
        $args['paginate'] = true;

        $result = wc_get_orders( $args );

        return isset( $result->total ) ? (int) $result->total : 0;

    }

    /**
     * The next batch of order ids.
     *
     * @since   2.3.0
     *
     * @param   array   $state
     * @return  int[]
     */
    private static function next_ids( $state ) {

        $args = self::query_args( $state['days'], $state['ceiling'] );

        $args['limit']   = self::BATCH;
        $args['offset']  = (int) $state['seen'];
        $args['return']  = 'ids';
        $args['orderby'] = 'ID';
        $args['order']   = 'ASC';

        $ids = wc_get_orders( $args );

        return is_array( $ids ) ? array_map( 'intval', $ids ) : [];

    }

    /**
     * The shared query.
     *
     * Two things here are load-bearing.
     *
     * The status list holds only orders that reached a real conclusion. A
     * pending or failed order is mostly an abandoned checkout, and feeding
     * those to the identity graph would teach the store that its own
     * customers habitually fail -- the graph counts outcomes, and "never
     * paid" is not an outcome anybody chose.
     *
     * The ceiling is a timestamp taken when the run started, and it is what
     * makes paging by offset safe. Without it, an order placed during the run
     * would land inside the result set and push everything after it down one
     * place, so the next batch would skip an order -- silently, with nothing
     * to say which. Orders created after the run began are simply not its
     * job; they are being scored live as they arrive.
     *
     * Both bounds go in one key because wc_get_orders takes a range there;
     * assigning date_created twice would keep only the second.
     *
     * @since   2.3.0
     *
     * @param   int     $days
     * @param   int     $ceiling    Unix timestamp the run started at.
     * @return  array
     */
    private static function query_args( $days, $ceiling ) {

        $ceiling = $ceiling > 0 ? (int) $ceiling : time();
        $since   = $days > 0 ? $ceiling - ( $days * DAY_IN_SECONDS ) : 0;

        return [
            'type'         => 'shop_order',
            'status'       => [ 'wc-completed', 'wc-processing', 'wc-refunded', 'wc-cancelled' ],
            'date_created' => $since > 0 ? $since . '...' . $ceiling : '<=' . $ceiling,
        ];

    }

}
