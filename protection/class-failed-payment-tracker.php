<?php
/**
 * Failed Payment Tracker.
 *
 * Blocks IPs after repeated payment failures.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Protection;

defined( 'ABSPATH' ) || exit;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\risk_context;

class failed_payment_tracker {

    /**
     * The store-wide breaker: this many failed payments across ALL addresses
     * within ATTACK_WINDOW seconds arms store_under_attack for an hour.
     *
     * Twenty-five in ten minutes. A shop that sees that many genuine declines
     * in ten minutes is doing enough business to notice one signal's worth of
     * caution; a shop that does not has a script on it.
     *
     * @since   3.0.0
     */
    const ATTACK_THRESHOLD = 25;
    const ATTACK_WINDOW    = 600;

    /**
     * Declines in an hour that are worth a second look on the next order.
     *
     * Not a setting, and deliberately below the merchant's own threshold.
     * That one gates a temporary block as well as a signal, so it has to stay
     * high enough not to lock out a shopper fumbling a card number -- which
     * leaves the shape card testing actually has, two or three refusals and
     * then a charge that works, scoring nothing at all. Three is the smallest
     * count that is not simply a mistyped number twice.
     *
     * @since   3.0.0
     */
    const SCORE_THRESHOLD = 3;

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Track failed payment orders.
        add_action( 'woocommerce_order_status_failed', [ $this, 'track_failure' ], 10, 2 );

        // The classic checkout resumes a failed order for the next attempt
        // without touching its status, so the gateway's next "failed" is not
        // a transition and fires nothing: a card tester working one cart
        // through fifty cards counted once. Put the resumed order back to
        // Pending, as the Store API does before every attempt, so each
        // decline is a real transition.
        add_action( 'woocommerce_resume_order', [ $this, 'on_resume' ] );

        // And charge the NEXT checkout for them. track_failure() runs after the
        // order exists and after its verdict was written, so a signal emitted
        // there went into a context nothing evaluated again -- failed_payments
        // never reached a single recorded rating. The count is what carries
        // over; this reads it at validation, where it can still change the
        // outcome. Priority 12: after the cheap structural checks, before the
        // scorers that build on the whole picture.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess_checkout' ], 12 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'assess_checkout' ], 12 );

    }

    /**
     * Charge this checkout for the declines that came before it.
     *
     * @since   3.0.0
     */
    public function assess_checkout( $data = null ) {

        $threshold = (int) settings::get( 'mshield_failed_payment_threshold' );

        // The address, and the mailbox. A tester rotating residential proxies
        // never trips a per-address count; one rotating throwaway addresses
        // never trips a per-mailbox count; between them, most do.
        $email = '';
        if( is_a( $data, 'WC_Order' ) ) {
            $email = (string) $data->get_billing_email();
        } elseif( is_array( $data ) ) {
            $email = (string) ( $data['billing_email'] ?? '' );
        }

        $ip   = ip_utils::get_client_ip();
        $keys = [];

        if( $ip !== '' )    $keys['this address'] = md5( ip_utils::rate_key( $ip ) . '|declines' );
        if( $email !== '' ) $keys['this mailbox'] = md5( \MightyShield\Includes\entities::normalize( 'email_root', $email ) . '|declines' );

        // Both counters are read before either signal is raised.
        //
        // Raising the lighter signal inside the loop and breaking looked
        // equivalent and was not: the address is checked first, so a tester
        // rotating residential proxies -- three declines on this address,
        // fifteen on the mailbox -- tripped recent_declines at 25 on the
        // address and never reached the mailbox counter that would have
        // tripped failed_payments at 55. The new signal suppressed the
        // stronger one on exactly the case the mailbox counter exists for.
        $heaviest = null;

        foreach( $keys as $what => $key ) {

            $count = (int) db::check_rate_limit( $key, 'declines' );

            if( $threshold > 0 && $count >= $threshold ) {
                $heaviest = [ 'failed_payments', "Repeated payment failures from {$what}: {$count} in 1 hour" ];
                break;
            }

            // The shape the merchant's threshold cannot see. Two or three
            // cards refused and then one that works is what card testing
            // actually looks like, and against a ten-decline gate it scored
            // nothing. Held, not raised, in case a later counter is worse.
            if( $count >= self::SCORE_THRESHOLD && $heaviest === null ) {
                $heaviest = [ 'recent_declines', "Payments declined from {$what} shortly before this order: {$count} in 1 hour" ];
            }

        }

        // Never both: they are two readings of one counter, and charging the
        // same declines twice is the double-counting the catalogue warns about.
        if( $heaviest !== null ) {
            risk_context::add( $heaviest[0], $heaviest[1] );
        }

        // Store-wide. A distributed tester keeps every per-address and
        // per-mailbox count under its limit by construction; what it cannot
        // hide is the store's own decline rate. While that is running hot,
        // every unknown customer costs a little more.
        if( self::under_attack() ) {
            risk_context::add( 'store_under_attack', 'Payment failures across the whole store are running far above normal' );
        }

    }

    /**
     * Whether the store-wide breaker is armed.
     *
     * Kept in the rate-limit table like the counters, and for the same
     * reason: a transient can be evicted by an object cache mid-wave, which
     * disarmed the breaker and then re-armed it -- and re-sent the "once an
     * hour" email -- on the next decline.
     *
     * @since   3.0.0
     *
     * @return  bool
     */
    public static function under_attack() {

        return db::check_rate_limit( md5( 'store|attack' ), 'attack' ) > 0;

    }

    /**
     * A failed order is being paid for again on the classic checkout.
     *
     * @since   3.0.0
     *
     * @param   int     $order_id
     */
    public function on_resume( $order_id ) {

        $order = wc_get_order( $order_id );

        if( $order && $order->has_status( 'failed' ) ) {
            $order->update_status( 'pending', __( 'MightyShield: payment being retried.', 'mighty-shield' ) );
        }

    }

    /**
     * Track a failed payment.
     *
     * @since   1.0.0
     *
     * @param   int     $order_id   Order ID.
     * @param   object  $order      WC_Order object.
     */
    public function track_failure( $order_id, $order ) {

        // A gateway that reports each declined authorization itself is the
        // better source, and counting both would count one decline twice.
        // Which way round it is does not depend on delivery order: the
        // gateway's own hook is authoritative for the gateways that have one,
        // and this status transition is the fallback for the rest.
        if( self::counts_its_own_declines( $order ) ) return;

        // No reference. get_transaction_id() is whatever the gateway last left
        // on the order, not an id for THIS authorization, so feeding it to an
        // idempotency check made the second decline on an order look like a
        // repeat of the first and silently dropped it -- fifty cards through
        // one order counted once, which is the exact failure this was built to
        // fix. A status transition has no per-attempt id; it is simply counted.
        self::record_decline( $order, '' );

    }

    /**
     * Whether this order's gateway reports its own declines.
     *
     * @since   3.0.0
     *
     * @param   \WC_Order   $order
     * @return  bool
     */
    private static function counts_its_own_declines( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return false;

        return \MightyShield\Includes\gateways::supports( 'declines', (string) $order->get_payment_method() );

    }

    /**
     * One declined authorization, counted.
     *
     * The shape a decline actually has, rather than the shape WooCommerce's
     * status machine gives it. A gateway that tells MightyShield about each
     * declined charge calls this with that charge's own id; the status hook
     * calls it with whatever reference the gateway left on the order, which is
     * often nothing at all.
     *
     * $reference is what makes a redelivered webhook free. Without one the
     * call is counted as it always was -- best effort, and better than the
     * alternative of not counting a real decline in case it was a repeat.
     *
     * @since   3.0.0
     *
     * @param   \WC_Order   $order
     * @param   string      $reference  The gateway's id for this authorization.
     * @return  int         The address's decline count in the last hour, or 0.
     */
    public static function record_decline( $order, $reference = '' ) {

        if( ! is_a( $order, 'WC_Order' ) ) return 0;

        $order_id = $order->get_id();

        // The address MightyShield resolved for this order, never the one
        // WooCommerce copied from a request header: a card tester who set
        // X-Real-IP to a fresh value per attempt was spreading their declines
        // across addresses nobody had, and the threshold was never reached.
        $ip = (string) $order->get_meta( '_mshield_ip' );

        // Only a shopper's own attempt. An order the checkout never stamped
        // -- a subscription renewal charged off-session, an order failed by
        // hand, a cron job's retry -- is not a decline at the checkout, and
        // counting it charged the store's own loopback address, fed the
        // mailbox counter, and on a renewal night armed the store-wide
        // breaker and emailed the merchant about an attack that was not one.
        if( $ip === '' ) return 0;

        // A charge id already counted. Stripe redelivers a webhook until it is
        // acknowledged, and a retried delivery is not a second decline.
        // is_array, not a cast: an absent meta comes back as '' and (array) ''
        // is [ '' ], which put an empty string in the list on the first
        // decline and kept it there.
        $seen = $order->get_meta( '_mshield_decline_refs' );
        if( ! is_array( $seen ) ) $seen = [];

        if( $reference !== '' ) {

            if( \in_array( $reference, $seen, true ) ) return 0;

            $seen[] = $reference;

            // Capped: a card tester working one order through a long list of
            // cards should not grow the order's meta without limit.
            if( count( $seen ) > 50 ) $seen = array_slice( $seen, -50 );

            $order->update_meta_data( '_mshield_decline_refs', $seen );
            $order->save();

        }

        // Counted in the rate-limit table, not a transient: an object cache
        // can evict a transient at any moment, which would silently disable
        // exactly the counting this relies on. Three counters -- the address,
        // the mailbox, and the store as a whole.
        $count = (int) db::increment_rate_limit( md5( ip_utils::rate_key( $ip ) . '|declines' ), 'declines', HOUR_IN_SECONDS );

        $email = (string) $order->get_billing_email();
        if( $email !== '' ) {
            db::increment_rate_limit( md5( \MightyShield\Includes\entities::normalize( 'email_root', $email ) . '|declines' ), 'declines', HOUR_IN_SECONDS );
        }

        $store = (int) db::increment_rate_limit( md5( 'store|declines' ), 'declines', self::ATTACK_WINDOW );

        // Log the failure.
        db::log_event( $ip, 'payment_failed', 'flagged', "Failed payment #{$order_id} (count: {$count})", '', $order_id, db::log_trust( $order ) );

        // Check threshold. The signal itself is emitted at validation on the
        // NEXT attempt, by assess_checkout(); here the verdict is already
        // written, so only the temporary block is worth doing.
        // $threshold > 0, as assess_checkout() has always had it. Zero means
        // the merchant switched the threshold off, and without the guard it
        // read as "block on the first decline" -- which now lands from a
        // webhook, out of band, with no checkout request to tie it to.
        $threshold = (int) settings::get( 'mshield_failed_payment_threshold' );
        if( $threshold > 0 && $count >= $threshold ) {
            rate_limiter::temp_block_ip( $ip, "Failed payment threshold exceeded: {$count}/{$threshold} in 1 hour" );
        }

        // The store-wide breaker. Twenty-five declines in ten minutes is not a
        // customer mistyping a card number; it is a script, and one that has
        // spread itself thin enough that nothing above noticed. Arm the
        // store_under_attack signal for an hour and tell the merchant once.
        if( $store >= self::ATTACK_THRESHOLD && ! self::under_attack() ) {

            // Armed for an hour, in the rate-limit table. See under_attack().
            db::increment_rate_limit( md5( 'store|attack' ), 'attack', HOUR_IN_SECONDS );

            db::log_event( $ip, 'system', 'blocked', sprintf( 'Store-wide decline rate: %d failed payments in %d minutes', $store, (int) ( self::ATTACK_WINDOW / 60 ) ) );

            if( ! settings::alerts_enabled() ) return $count;

            // Guarded for the same reason ai_client::degrade() is: this runs
            // on the shopper's own request, and a broken mail transport
            // throwing from phpmailer_init would end the checkout it is
            // reporting on. An alert is a side effect.
            try {

                wp_mail(
                    settings::notification_recipients(),
                    __( 'MightyShield: your store may be under a card-testing attack', 'mighty-shield' ),
                    sprintf(
                        /* translators: 1: number of declines, 2: minutes. */
                        __( '%1$d payments failed in the last %2$d minutes, far above normal. For the next hour every unknown customer is scored as riskier. Nothing is refused on that alone; watch the review queue, and consider switching on the bot challenge for checkout if it is not on.', 'mighty-shield' ),
                        $store,
                        (int) ( self::ATTACK_WINDOW / 60 )
                    )
                );

            } catch( \Throwable $e ) {

                db::log_event( $ip, 'system', 'flagged', 'The card-testing alert could not be sent: ' . $e->getMessage() );

            }

        }

        return $count;

    }

}
