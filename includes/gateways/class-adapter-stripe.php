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

defined( 'ABSPATH' ) || exit;

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

        // 3-D Secure is requested through the gateway's own intent filter, and
        // only two of the three have one this adapter can reach. WooPayments'
        // Create_And_Confirm_Intention exposes no payment_method_options
        // setter (only its Update_Intention does), so there is nothing to ask
        // for the challenge through -- and claiming otherwise wrote "3-D Secure
        // was required" onto orders where it never was. resolve() falls back
        // to the next honest action instead.
        if( $capability === '3ds' ) {
            return \in_array( $gateway, [ 'stripe', 'stripe_cc' ], true );
        }

        // Card signals arrive synchronously from the official gateway's
        // process_response hook, with its webhook as the fallback. Payment
        // Plugins' gateway (stripe_cc) shares neither hook, and WooPayments has
        // its own stream this adapter does not read. Claiming support for
        // either would promise a signal that never arrives.
        if( $capability === 'card_signals' ) return $gateway === 'stripe';

        return false;

    }

    /**
     * @since 1.9.0
     */
    public static function listen() {

        // The synchronous path first. The gateway fires this in the checkout
        // request itself, with the charge or intent it just processed and the
        // order, so card details arrive whether or not webhooks were ever
        // configured -- which on a great many stores they were not.
        add_action( 'wc_gateway_stripe_process_response', [ __CLASS__, 'on_response' ], 10, 2 );

        add_action( 'wc_stripe_webhook_received', [ __CLASS__, 'on_webhook' ], 10, 3 );

    }

    /**
     * Read card details off the response the gateway just processed.
     *
     * @since   2.3.0
     *
     * @param   object      $response   A Charge, or a PaymentIntent whose
     *                                  latest charge carries the details.
     * @param   \WC_Order   $order
     */
    public static function on_response( $response, $order ) {

        if( ! $order instanceof \WC_Order || ! is_object( $response ) ) return;

        $charge = self::charge_from( $response );
        if( $charge ) self::ingest( $order, $charge );

    }

    /**
     * Read card details off a succeeded charge.
     *
     * The official gateway returns from its charge.succeeded handler for card
     * payments BEFORE it records which order the event was for, so this action
     * fires with a null order on exactly the payment type that carries card
     * details. The order is therefore looked up here from the charge rather
     * than trusted from the argument.
     *
     * @since   1.9.0
     *
     * @param   string          $type
     * @param   object          $notification
     * @param   \WC_Order|null  $order
     */
    public static function on_webhook( $type, $notification, $order ) {

        if( empty( $notification->data->object ) ) return;

        $charge = $notification->data->object;

        // A declined card is the one thing a card tester leaves behind. The
        // card's own identity takes the refusal, so the next order that pays
        // with it -- from a fresh email, a fresh address, a fresh IP -- meets
        // the history the earlier attempts wrote.
        if( $type === 'charge.failed' ) {

            $fp = (string) ( $charge->payment_method_details->card->fingerprint ?? '' );

            if( $fp !== '' && class_exists( '\MightyShield\Includes\entities' ) ) {
                \MightyShield\Includes\entities::record_refusal( [
                    'card_fp' => \MightyShield\Includes\entities::normalize( 'card_fp', $fp ),
                ] );
            }

            return;

        }

        if( $type !== 'charge.succeeded' ) return;

        if( ! $order instanceof \WC_Order ) $order = self::order_for( $charge );
        if( ! $order instanceof \WC_Order ) return;

        self::ingest( $order, $charge );

    }

    /**
     * The charge object inside whatever Stripe answered with.
     *
     * @since   2.3.0
     *
     * @param   object  $response
     * @return  object|null
     */
    private static function charge_from( $response ) {

        if( ( $response->object ?? '' ) === 'charge' ) return $response;

        // A PaymentIntent: the charge is the latest one on it, expanded, or the
        // first entry of the charges list depending on API version.
        if( is_object( $response->latest_charge ?? null ) ) return $response->latest_charge;

        $list = $response->charges->data ?? null;
        if( is_array( $list ) && isset( $list[0] ) && is_object( $list[0] ) ) return $list[0];

        return null;

    }

    /**
     * Resolve the order a charge paid for.
     *
     * @since   2.3.0
     *
     * @param   object  $charge
     * @return  \WC_Order|null
     */
    private static function order_for( $charge ) {

        if( ! class_exists( '\WC_Stripe_Helper' ) ) return null;

        $order = null;

        if( ! empty( $charge->id ) && method_exists( '\WC_Stripe_Helper', 'get_order_by_charge_id' ) ) {
            $order = \WC_Stripe_Helper::get_order_by_charge_id( (string) $charge->id );
        }

        if( ! $order && ! empty( $charge->payment_intent ) && method_exists( '\WC_Stripe_Helper', 'get_order_by_intent_id' ) ) {
            $intent = is_object( $charge->payment_intent ) ? ( $charge->payment_intent->id ?? '' ) : $charge->payment_intent;
            if( $intent ) $order = \WC_Stripe_Helper::get_order_by_intent_id( (string) $intent );
        }

        return $order instanceof \WC_Order ? $order : null;

    }

    /**
     * Hand a charge's card details to card_signals, once per charge.
     *
     * @since   2.3.0
     *
     * @param   \WC_Order   $order
     * @param   object      $charge
     */
    private static function ingest( $order, $charge ) {

        $card = $charge->payment_method_details->card ?? null;

        if( ! $card ) return;

        // The synchronous hook and the webhook both deliver the same charge,
        // and re-rating twice would note the order twice.
        $charge_id = (string) ( $charge->id ?? '' );

        if( $charge_id !== '' ) {
            if( (string) $order->get_meta( '_mshield_card_charge' ) === $charge_id ) return;
            $order->update_meta_data( '_mshield_card_charge', $charge_id );
            $order->save();
        }

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

        // Payment Plugins' gateway builds its intent through a different
        // filter from the official one, with the arguments already shaped the
        // way Stripe wants them. ai_capture uses the same hook for
        // authorize-only, so the two stay in step.
        if( $gateway === 'stripe_cc' ) {

            return self::hook( 'wc_stripe_payment_intent_args', function( $args, $intent_order = null ) {

                if( ! self::is_target( $intent_order ) || ! is_array( $args ) ) return $args;

                if( ! isset( $args['payment_method_options'] ) || ! is_array( $args['payment_method_options'] ) ) {
                    $args['payment_method_options'] = [];
                }

                if( ! isset( $args['payment_method_options']['card'] ) || ! is_array( $args['payment_method_options']['card'] ) ) {
                    $args['payment_method_options']['card'] = [];
                }

                $args['payment_method_options']['card']['request_three_d_secure'] = 'any';

                return $args;

            }, 10, 2 );

        }

        // No WooPayments branch: supports() answers false for it, so this is
        // never reached for that gateway. The branch that used to be here
        // guarded on a setter WooPayments' create-and-confirm request does not
        // have, passed the request through untouched, and reported success.

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
