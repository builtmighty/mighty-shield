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
     * @since   2.3.0
     */
    const ATTACK_THRESHOLD = 25;
    const ATTACK_WINDOW    = 600;

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Track failed payment orders.
        add_action( 'woocommerce_order_status_failed', [ $this, 'track_failure' ], 10, 2 );

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
     * @since   2.3.0
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

        if( $ip !== '' )    $keys['this address'] = md5( $ip . '|declines' );
        if( $email !== '' ) $keys['this mailbox'] = md5( \MightyShield\Includes\entities::normalize( 'email_root', $email ) . '|declines' );

        foreach( $keys as $what => $key ) {

            $count = (int) db::check_rate_limit( $key, 'declines' );

            if( $threshold > 0 && $count >= $threshold ) {
                risk_context::add( 'failed_payments', "Repeated payment failures from {$what}: {$count} in 1 hour" );
                break;
            }

        }

        // Store-wide. A distributed tester keeps every per-address and
        // per-mailbox count under its limit by construction; what it cannot
        // hide is the store's own decline rate. While that is running hot,
        // every unknown customer costs a little more.
        if( get_transient( 'mshield_store_under_attack' ) ) {
            risk_context::add( 'store_under_attack', 'Payment failures across the whole store are running far above normal' );
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

        // The address MightyShield resolved for this order, never the one
        // WooCommerce copied from a request header: a card tester who set
        // X-Real-IP to a fresh value per attempt was spreading their declines
        // across addresses nobody had, and the threshold was never reached.
        $ip = is_object( $order ) && method_exists( $order, 'get_meta' ) ? (string) $order->get_meta( '_mshield_ip' ) : '';
        if( $ip === '' ) $ip = ip_utils::get_client_ip();

        // Counted in the rate-limit table, not a transient: an object cache
        // can evict a transient at any moment, which would silently disable
        // exactly the counting this relies on. Three counters -- the address,
        // the mailbox, and the store as a whole.
        $count = (int) db::increment_rate_limit( md5( $ip . '|declines' ), 'declines', HOUR_IN_SECONDS );

        $email = is_object( $order ) && method_exists( $order, 'get_billing_email' ) ? (string) $order->get_billing_email() : '';
        if( $email !== '' ) {
            db::increment_rate_limit( md5( \MightyShield\Includes\entities::normalize( 'email_root', $email ) . '|declines' ), 'declines', HOUR_IN_SECONDS );
        }

        $store = (int) db::increment_rate_limit( md5( 'store|declines' ), 'declines', self::ATTACK_WINDOW );

        // Log the failure.
        db::log_event( $ip, 'payment_failed', 'flagged', "Failed payment #{$order_id} (count: {$count})" );

        // Check threshold. The signal itself is emitted at validation on the
        // NEXT attempt, by assess_checkout(); here the verdict is already
        // written, so only the temporary block is worth doing.
        $threshold = (int) settings::get( 'mshield_failed_payment_threshold' );
        if( $count >= $threshold ) {
            rate_limiter::temp_block_ip( $ip, "Failed payment threshold exceeded: {$count}/{$threshold} in 1 hour" );
        }

        // The store-wide breaker. Twenty-five declines in ten minutes is not a
        // customer mistyping a card number; it is a script, and one that has
        // spread itself thin enough that nothing above noticed. Arm the
        // store_under_attack signal for an hour and tell the merchant once.
        if( $store >= self::ATTACK_THRESHOLD && ! get_transient( 'mshield_store_under_attack' ) ) {

            set_transient( 'mshield_store_under_attack', time(), HOUR_IN_SECONDS );

            db::log_event( $ip, 'system', 'blocked', sprintf( 'Store-wide decline rate: %d failed payments in %d minutes', $store, (int) ( self::ATTACK_WINDOW / 60 ) ) );

            $to = array_filter( array_map( 'sanitize_email', array_map( 'trim', explode( ',', (string) settings::get( 'mshield_ai_notify_emails' ) ) ) ) );
            if( empty( $to ) ) $to = [ get_option( 'admin_email' ) ];

            wp_mail(
                $to,
                __( 'MightyShield: your store may be under a card-testing attack', 'mighty-shield' ),
                sprintf(
                    /* translators: 1: number of declines, 2: minutes. */
                    __( '%1$d payments failed in the last %2$d minutes, far above normal. For the next hour every unknown customer is scored as riskier. Nothing is refused on that alone; watch the review queue, and consider switching on the bot challenge for checkout if it is not on.', 'mighty-shield' ),
                    $store,
                    (int) ( self::ATTACK_WINDOW / 60 )
                )
            );

        }

    }

}
