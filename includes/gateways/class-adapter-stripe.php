<?php
/**
 * Stripe adapter — official Stripe, Payment Plugins Stripe, and WooPayments.
 *
 * Grouped because they share what matters here: an intent-request filter that
 * can be told to require 3-D Secure for a single order.
 *
 * Card details arrive separately, on the webhook stream, because no hook in the
 * plugin hands back the intent or charge response. That means these signals
 * depend on Stripe webhooks being configured; without them they are simply
 * absent, which degrades to the old behaviour rather than breaking anything.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes\Gateways;

use MightyShield\Protection\card_signals;

class adapter_stripe implements gateway_adapter {

    /**
     * Order currently being forced to 3-D Secure.
     *
     * @since   1.9.0
     */
    private static $order_id = 0;

    /**
     * Registered filters, for teardown.
     *
     * @since   1.9.0
     */
    private static $teardown = [];

    /**
     * @since 1.9.0
     */
    public static function handles() {

        return [ 'stripe', 'stripe_cc', 'woocommerce_payments' ];

    }

    /**
     * @since 1.9.0
     */
    public static function supports( $capability, $gateway ) {

        if( ! \in_array( $gateway, self::handles(), true ) ) return false;

        if( $capability === '3ds' ) return true;

        // Card signals come from the Stripe webhook stream, which WooPayments
        // does not share — it has its own. Claiming support there would mean
        // promising a signal that never arrives.
        if( $capability === 'card_signals' ) {
            return \in_array( $gateway, [ 'stripe', 'stripe_cc' ], true );
        }

        return false;

    }

    /**
     * @since 1.9.0
     */
    public static function listen() {

        add_action( 'wc_stripe_webhook_received', [ __CLASS__, 'on_webhook' ], 10, 3 );

    }

    /**
     * Read card details off a succeeded charge.
     *
     * @since   1.9.0
     *
     * @param   string          $type
     * @param   object          $notification
     * @param   \WC_Order|null  $order
     */
    public static function on_webhook( $type, $notification, $order ) {

        if( $type !== 'charge.succeeded' ) return;
        if( ! $order instanceof \WC_Order ) return;
        if( empty( $notification->data->object ) ) return;

        $charge = $notification->data->object;
        $card   = $charge->payment_method_details->card ?? null;

        if( ! $card ) return;

        $checks = $card->checks ?? null;

        card_signals::ingest_normalised( $order, [
            'fingerprint' => $card->fingerprint ?? '',
            'brand'       => $card->brand ?? '',
            'last4'       => $card->last4 ?? '',
            'country'     => strtoupper( (string) ( $card->country ?? '' ) ),
            'funding'     => $card->funding ?? '',
            'avs_street'  => $checks->address_line1_check ?? '',
            'avs_zip'     => $checks->address_postal_code_check ?? '',
            'cvc'         => $checks->cvc_check ?? '',
            'three_d'     => $card->three_d_secure->result ?? '',
            'risk_level'  => $charge->outcome->risk_level ?? '',
            'risk_score'  => $charge->outcome->risk_score ?? '',
        ] );

    }

    /**
     * @since 1.9.0
     */
    public static function request_3ds( $order ) {

        $gateway  = $order->get_payment_method();
        $order_id = (int) $order->get_id();

        // Without an ID nothing can match the target, so every filter would
        // fall through silently. Report failure rather than claiming a
        // challenge that was never arranged.
        if( $order_id <= 0 || ! self::supports( '3ds', $gateway ) ) return false;

        self::$order_id = $order_id;

        add_action( 'woocommerce_payment_complete', [ __CLASS__, 'teardown' ], 999 );
        add_action( 'shutdown', [ __CLASS__, 'teardown' ], 1 );

        if( $gateway === 'woocommerce_payments' ) {

            return self::hook( 'wcpay_create_and_confirm_intent_request', function( $request, $payment_information = null ) {

                if( ! is_object( $request ) ) return $request;

                $target = ( is_object( $payment_information ) && method_exists( $payment_information, 'get_order' ) )
                    ? $payment_information->get_order() : null;

                if( ! self::is_target( $target ) ) return $request;

                if( method_exists( $request, 'set_payment_method_options' ) ) {
                    $request->set_payment_method_options( [ 'card' => [ 'request_three_d_secure' => 'any' ] ] );
                }

                return $request;

            }, 10, 2 );

        }

        return self::hook( 'wc_stripe_generate_create_intent_request', function( $request, $intent_order = null ) {

            if( ! self::is_target( $intent_order ) || ! is_array( $request ) ) return $request;

            // Stripe nests this under the payment method type. Seed the card
            // entry when the gateway did not send one, or the option has
            // nowhere to attach.
            if( ! isset( $request['payment_method_options'] ) || ! is_array( $request['payment_method_options'] ) ) {
                $request['payment_method_options'] = [];
            }

            if( ! isset( $request['payment_method_options']['card'] ) || ! is_array( $request['payment_method_options']['card'] ) ) {
                $request['payment_method_options']['card'] = [];
            }

            $request['payment_method_options']['card']['request_three_d_secure'] = 'any';

            return $request;

        }, 10, 2 );

    }

    /**
     * Register a scoped filter and record its teardown.
     *
     * @since   1.9.0
     *
     * @param   string      $hook
     * @param   callable    $callback
     * @param   int         $priority
     * @param   int         $args
     * @return  bool
     */
    private static function hook( $hook, $callback, $priority, $args ) {

        add_filter( $hook, $callback, $priority, $args );
        self::$teardown[] = [ $hook, $callback, $priority ];

        return true;

    }

    /**
     * Whether a gateway callback is acting on the order we targeted.
     *
     * Several of these filters also fire with a null order from reporting
     * paths; returning false there lets the callback fall through to the
     * gateway's own value.
     *
     * @since   1.9.0
     *
     * @param   mixed   $order
     * @return  bool
     */
    private static function is_target( $order ) {

        if( ! is_object( $order ) || ! method_exists( $order, 'get_id' ) ) return false;

        return (int) $order->get_id() === (int) self::$order_id && self::$order_id > 0;

    }

    /**
     * Remove every filter this adapter registered.
     *
     * @since   1.9.0
     */
    public static function teardown() {

        foreach( self::$teardown as $entry ) {
            remove_filter( $entry[0], $entry[1], $entry[2] );
        }

        self::$teardown = [];
        self::$order_id = 0;

    }

}
