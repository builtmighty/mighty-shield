<?php
/**
 * AI Capture control.
 *
 * Everything gateway-specific about holding a suspected-fraud order lives here:
 * forcing a single order to authorize without capturing, capturing that
 * authorization later, and voiding it.
 *
 * Every filter is scoped to one order ID and torn down after payment, so
 * nothing leaks into another order in the same request.
 *
 * IMPORTANT: force_auth_only() only reports that the filters were registered.
 * It cannot know the gateway honored them, which is why is_authorized() reads
 * the gateway's OWN captured-state meta rather than trusting our own.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes;

class ai_capture {

    /**
     * Order ID currently being forced to authorize-only.
     *
     * @since   1.9.0
     */
    private static $order_id = 0;

    /**
     * Registered teardown callbacks.
     *
     * @since   1.9.0
     */
    private static $teardown = [];

    /**
     * Gateways running the SkyVerge Payment Gateway Framework.
     *
     * Square, Authorize.Net, and Braintree ship the same framework, so one code
     * path covers all three for authorize, capture, void, and state detection.
     * Square is a renamespaced fork, which matters only if you reach for the
     * framework's classes directly — the public gateway API is identical.
     *
     * @since   1.9.0
     */
    const SKYVERGE = [
        'square_credit_card',
        'authorize_net_cim_credit_card',
        'braintree_credit_card',
        'braintree_paypal',
    ];

    /**
     * Gateways with their own per-order authorize-only filter.
     *
     * @since   1.9.0
     */
    const NATIVE = [
        'stripe_cc',
        'stripe',
        'woocommerce_payments',
    ];

    /**
     * Whether a gateway can be forced to authorize a single order.
     *
     * ppcp-gateway is deliberately absent: WooCommerce PayPal Payments fixes
     * the intent when the PayPal order is created, in the separate
     * ppc-create-order request fired by its JS button — before the WooCommerce
     * order exists and long before our hook runs. Its orders can still be
     * captured and voided (see capture()/void()) when the merchant has set
     * PayPal's global intent to Authorize.
     *
     * @since   1.9.0
     *
     * @param   string  $gateway    Gateway ID.
     * @return  bool
     */
    public static function supports_auth_only( $gateway ) {

        return \in_array( $gateway, self::NATIVE, true ) || \in_array( $gateway, self::SKYVERGE, true );

    }

    /**
     * Whether any gateway available at checkout can authorize-only.
     *
     * Drives both the settings UI and its sanitize callback, so the store can
     * never be left on a verdict action it cannot honor.
     *
     * @since   1.9.0
     *
     * @return  bool
     */
    public static function any_gateway_supports_auth_only() {

        if( ! function_exists( 'WC' ) || ! WC()->payment_gateways() ) return false;

        foreach( WC()->payment_gateways()->get_available_payment_gateways() as $id => $gateway ) {
            if( self::supports_auth_only( $id ) ) return true;
        }

        return false;

    }

    /**
     * Gateway IDs available at checkout that can authorize-only.
     *
     * @since   1.9.0
     *
     * @return  array
     */
    public static function supporting_gateways() {

        $supported = [];

        if( ! function_exists( 'WC' ) || ! WC()->payment_gateways() ) return $supported;

        foreach( WC()->payment_gateways()->get_available_payment_gateways() as $id => $gateway ) {
            if( self::supports_auth_only( $id ) ) $supported[ $id ] = $gateway->get_title();
        }

        return $supported;

    }

    /**
     * Force an order to authorize without capturing.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  bool    True only when authorize-only was actually arranged.
     */
    public static function force_auth_only( $order ) {

        $gateway  = $order->get_payment_method();
        $order_id = (int) $order->get_id();

        // Without an ID there is nothing for is_target() to match, so every
        // filter would silently fall through — report failure rather than
        // claiming an authorization hold that was never actually arranged.
        if( empty( $gateway ) || $order_id <= 0 ) return false;

        self::$order_id = $order_id;

        // Tear down once payment has been taken, so a later order in the same
        // request is unaffected.
        add_action( 'woocommerce_checkout_order_processed', [ __CLASS__, 'teardown' ], 999 );
        add_action( 'woocommerce_payment_complete', [ __CLASS__, 'teardown' ], 999 );
        add_action( 'shutdown', [ __CLASS__, 'teardown' ], 1 );

        // Site-specific integrations win, so an unsupported gateway can be
        // handled without changing plugin code.
        if( apply_filters( 'mshield_ai_authorize_only', false, $order, $gateway ) === true ) return true;

        if( \in_array( $gateway, self::SKYVERGE, true ) ) return self::hook_skyverge( $gateway );

        switch( $gateway ) {

            case 'stripe_cc':
                return self::hook( 'wc_stripe_payment_intent_args', function( $args, $intent_order = null ) {
                    if( self::is_target( $intent_order ) ) $args['capture_method'] = 'manual';
                    return $args;
                }, 10, 2 );

            case 'stripe':
                return self::hook( 'wc_stripe_generate_create_intent_request', function( $request, $intent_order = null ) {
                    if( ! self::is_target( $intent_order ) || ! is_array( $request ) ) return $request;
                    // Two shapes: normally top-level, but the confirmation-token
                    // flow (and Amazon Pay) nests it under payment_method_options.
                    if( isset( $request['capture_method'] ) ) {
                        $request['capture_method'] = 'manual';
                    } elseif( isset( $request['payment_method_options'] ) && is_array( $request['payment_method_options'] ) ) {
                        foreach( $request['payment_method_options'] as $type => $options ) {
                            $request['payment_method_options'][ $type ]['capture_method'] = 'manual';
                        }
                    } else {
                        $request['capture_method'] = 'manual';
                    }
                    return $request;
                }, 10, 2 );

            case 'woocommerce_payments':
                return self::hook( 'wcpay_create_and_confirm_intent_request', function( $request, $payment_information = null ) {
                    if( ! is_object( $request ) || ! method_exists( $request, 'set_capture_method' ) ) return $request;
                    $target = null;
                    if( is_object( $payment_information ) && method_exists( $payment_information, 'get_order' ) ) {
                        $target = $payment_information->get_order();
                    }
                    if( self::is_target( $target ) ) $request->set_capture_method( true );
                    return $request;
                }, 10, 2 );

        }

        // Nothing here can authorize-only on this gateway. Say so honestly —
        // the caller falls back to flagging the order after payment.
        self::teardown();
        return false;

    }

    /**
     * Register the SkyVerge authorize-only filter pair.
     *
     * Both are required: the API call branches on the CHARGE filter, while the
     * AUTHORIZATION filter is what makes the framework record the charge as
     * uncaptured. Filtering only one produces a captured order that claims to
     * be authorized, or vice versa.
     *
     * @since   1.9.0
     *
     * @param   string  $gateway    Gateway ID.
     * @return  bool
     */
    private static function hook_skyverge( $gateway ) {

        self::hook( 'wc_' . $gateway . '_perform_credit_card_charge', function( $perform, $order = null ) {
            return self::is_target( $order ) ? false : $perform;
        }, 10, 2 );

        self::hook( 'wc_' . $gateway . '_perform_credit_card_authorization', function( $perform, $order = null ) {
            return self::is_target( $order ) ? true : $perform;
        }, 10, 2 );

        return true;

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
     * Several of these filters are also fired with a null order from reporting
     * paths. Returning false there makes the callback fall through to the
     * gateway's own value, which is what we want.
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
     * Remove every filter this class registered.
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

    /**
     * Resolve the gateway object handling an order.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  \WC_Payment_Gateway|null
     */
    private static function gateway_for( $order ) {

        if( ! function_exists( 'WC' ) || ! WC()->payment_gateways() ) return null;

        $gateways = WC()->payment_gateways()->payment_gateways();
        $id       = $order->get_payment_method();

        return isset( $gateways[ $id ] ) ? $gateways[ $id ] : null;

    }

    /**
     * Whether the order currently holds an authorization that has not been
     * captured.
     *
     * Reads the GATEWAY's own state, never MightyShield's — force_auth_only()
     * records intent, not outcome, and telling a merchant funds are merely
     * reserved when they were actually taken is the worst failure here.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  bool
     */
    public static function is_authorized( $order ) {

        $id = $order->get_payment_method();

        if( \in_array( $id, self::SKYVERGE, true ) ) {
            return $order->get_meta( '_wc_' . $id . '_charge_captured' ) === 'no';
        }

        switch( $id ) {

            case 'stripe':
                return $order->get_meta( '_stripe_charge_captured' ) === 'no';

            case 'woocommerce_payments':
                return $order->get_meta( '_intention_status' ) === 'requires_capture';

            case 'stripe_cc':
                // Payment Plugins stores the intent id; the authoritative status
                // lives on the intent, but an uncaptured order reliably still
                // has one alongside an on-hold status.
                return ! empty( $order->get_meta( '_payment_intent_id' ) ) && $order->has_status( 'on-hold' );

            case 'ppcp-gateway':
                return strtoupper( (string) $order->get_meta( '_ppcp_paypal_intent' ) ) === 'AUTHORIZE'
                    && ! wc_string_to_bool( $order->get_meta( '_ppcp_paypal_captured' ) );

        }

        return false;

    }

    /**
     * Capture a previously authorized order.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  true|\WP_Error
     */
    public static function capture( $order ) {

        $gateway = self::gateway_for( $order );
        $id      = $order->get_payment_method();

        if( ! $gateway ) return new \WP_Error( 'mshield_no_gateway', __( 'The payment gateway for this order is not available.', 'mighty-shield' ) );

        if( \in_array( $id, self::SKYVERGE, true ) ) {

            if( ! method_exists( $gateway, 'get_capture_handler' ) ) {
                return new \WP_Error( 'mshield_no_capture', __( 'This gateway does not support capturing.', 'mighty-shield' ) );
            }

            $result = $gateway->get_capture_handler()->perform_capture( $order );

            if( empty( $result['success'] ) ) {
                return new \WP_Error( 'mshield_capture_failed', ! empty( $result['message'] ) ? $result['message'] : __( 'Capture failed.', 'mighty-shield' ) );
            }

            return true;

        }

        switch( $id ) {

            case 'stripe_cc':
                $result = $gateway->capture_charge( $order->get_total(), $order );
                return is_wp_error( $result ) ? $result : true;

            case 'stripe':
                if( ! class_exists( '\WC_Stripe_Order_Handler' ) ) {
                    return new \WP_Error( 'mshield_no_capture', __( 'Stripe order handler unavailable.', 'mighty-shield' ) );
                }
                \WC_Stripe_Order_Handler::get_instance()->capture_payment( $order->get_id() );
                // The handler reports through order notes rather than a return
                // value, so re-read the gateway's own state as the verdict.
                return self::is_authorized( $order )
                    ? new \WP_Error( 'mshield_capture_failed', __( 'Stripe did not capture the authorization. Check the order notes.', 'mighty-shield' ) )
                    : true;

            case 'woocommerce_payments':
                $result = $gateway->capture_charge( $order );
                if( is_array( $result ) && isset( $result['status'] ) && $result['status'] === 'succeeded' ) return true;
                return new \WP_Error( 'mshield_capture_failed', ! empty( $result['message'] ) ? $result['message'] : __( 'Capture failed.', 'mighty-shield' ) );

            case 'ppcp-gateway':
                do_action( 'woocommerce_order_action_ppcp_authorize_order', $order );
                $fresh = wc_get_order( $order->get_id() );
                return ( $fresh && ! self::is_authorized( $fresh ) )
                    ? true
                    : new \WP_Error( 'mshield_capture_failed', __( 'PayPal did not capture the authorization. Check the order notes.', 'mighty-shield' ) );

        }

        return new \WP_Error( 'mshield_no_capture', __( 'Capturing is not supported for this gateway.', 'mighty-shield' ) );

    }

    /**
     * Void / release an authorization without capturing it.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  true|\WP_Error
     */
    public static function void( $order ) {

        $gateway = self::gateway_for( $order );
        $id      = $order->get_payment_method();

        if( ! $gateway ) return new \WP_Error( 'mshield_no_gateway', __( 'The payment gateway for this order is not available.', 'mighty-shield' ) );

        if( \in_array( $id, self::SKYVERGE, true ) ) {
            // The framework routes an uncaptured full-amount refund to a void.
            // Partial amounts are rejected, so always pass the full total.
            $result = $gateway->process_refund( $order->get_id(), $order->get_total() );
            return is_wp_error( $result ) ? $result : true;
        }

        switch( $id ) {

            case 'stripe_cc':
                $result = $gateway->void_charge( $order );
                return is_wp_error( $result ) ? $result : true;

            case 'stripe':
                if( ! class_exists( '\WC_Stripe_Order_Handler' ) ) {
                    return new \WP_Error( 'mshield_no_void', __( 'Stripe order handler unavailable.', 'mighty-shield' ) );
                }
                \WC_Stripe_Order_Handler::get_instance()->cancel_payment( $order->get_id() );
                return true;

            case 'woocommerce_payments':
                $gateway->cancel_authorization( $order );
                return true;

            case 'ppcp-gateway':
                // Refunding an authorize-intent order voids it.
                $result = $gateway->process_refund( $order->get_id(), $order->get_total() );
                return is_wp_error( $result ) ? $result : true;

        }

        return new \WP_Error( 'mshield_no_void', __( 'Voiding is not supported for this gateway.', 'mighty-shield' ) );

    }

}
