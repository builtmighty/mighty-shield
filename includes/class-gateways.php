<?php
/**
 * Gateway capability layer.
 *
 * Phases 1-3 are deliberately processor-agnostic — they run entirely on data
 * available before payment, so they behave identically on every store. This is
 * the one place that knows about specific gateways, and everything it offers is
 * additive: a store on an unsupported processor still gets the full scoring
 * pipeline and the full response ladder, just without the step-up challenge or
 * card signals.
 *
 * That is why the unsupported case is not an afterthought. Across a fleet of
 * stores running different processors, "this gateway cannot do 3-D Secure" has
 * to degrade to "no challenge" and never to "checkout broken".
 *
 * Resolution is by adapter, not by a flat list, so adding a processor means
 * adding one class rather than editing several arrays that can fall out of step
 * with each other.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes;

use MightyShield\Includes\Gateways\adapter_null;

class gateways {

    /**
     * Registered adapters, most specific first.
     *
     * @since   1.9.0
     */
    const ADAPTERS = [
        '\MightyShield\Includes\Gateways\adapter_stripe',
        '\MightyShield\Includes\Gateways\adapter_skyverge',
    ];

    /**
     * Processors MightyShield has specifically been built for.
     *
     * Grouped by brand rather than by gateway ID, because several IDs are the
     * same processor: `stripe` and `stripe_cc` are the official and Payment
     * Plugins builds of Stripe with identical capability, and Braintree ships
     * a card gateway and a PayPal gateway off one framework.
     *
     * Only the NAMES live here. What each one can do is read back from
     * supports(), so this list cannot promise a capability the adapters do not
     * actually implement.
     *
     * It is a floor, not a ceiling: a gateway MightyShield has never heard of
     * can be taught through the mshield_gateway_supports / mshield_request_3ds
     * / mshield_ai_authorize_only filters.
     *
     * @since   1.9.3
     */
    const SUPPORTED = [

        'stripe' => [
            'label' => 'Stripe',
            'ids'   => [ 'stripe', 'stripe_cc' ],
            'note'  => '',
        ],

        'woopayments' => [
            'label' => 'WooPayments',
            'ids'   => [ 'woocommerce_payments' ],
            'note'  => '',
        ],

        'square' => [
            'label' => 'Square',
            'ids'   => [ 'square_credit_card' ],
            'note'  => '',
        ],

        'authorize_net' => [
            'label' => 'Authorize.Net',
            'ids'   => [ 'authorize_net_cim_credit_card' ],
            'note'  => '',
        ],

        // Braintree is PayPal's enterprise product and is branded as such. The
        // KEY stays 'braintree': it is what the gateway IDs and the stored
        // capability report are keyed on, and renaming it would orphan both.
        'braintree' => [
            'label' => 'PayPal Enterprise',
            'ids'   => [ 'braintree_credit_card', 'braintree_paypal' ],
            'note'  => '',
        ],

        // Partial on purpose. PayPal fixes the capture decision when it creates
        // its own order, in a request fired by its JS button before the
        // WooCommerce order exists — so there is no moment at which MightyShield
        // could ask it to authorize instead. Approving and denying still work on
        // its orders when the merchant has set PayPal's own intent to Authorize.
        'paypal' => [
            'label' => 'PayPal',
            'ids'   => [ 'ppcp-gateway' ],
            'note'  => 'Held orders can be captured or voided, but only if PayPal\'s own intent is set to Authorize. MightyShield cannot switch it per order.',
        ],
    ];

    /**
     * The supported list, with what each brand can do and whether you have it.
     *
     * @since   1.9.3
     *
     * @return  array   brand => [ label, 3ds, auth_only, card_signals, active, note ]
     */
    public static function supported_report() {

        $active = self::capability_report();
        $out    = [];

        foreach( self::SUPPORTED as $brand => $meta ) {

            $row = [
                'label'        => $meta['label'],
                'note'         => $meta['note'],
                '3ds'          => false,
                'auth_only'    => false,
                'card_signals' => false,
                'active'       => false,
            ];

            foreach( $meta['ids'] as $id ) {

                // Derived, never restated. If an adapter drops a capability
                // this row stops claiming it on the next page load.
                foreach( [ '3ds', 'auth_only', 'card_signals' ] as $cap ) {
                    if( self::supports( $cap, $id ) ) $row[ $cap ] = true;
                }

                // capability_report() lists only gateways available at
                // checkout, which is the honest test for "you have this" —
                // enabled but unavailable (wrong currency, wrong country)
                // would otherwise read as working.
                if( isset( $active[ $id ] ) ) $row['active'] = true;

            }

            $out[ $brand ] = $row;

        }

        return $out;

    }

    /**
     * Start every adapter listening.
     *
     * @since   1.9.0
     */
    public static function listen() {

        foreach( self::ADAPTERS as $adapter ) {
            if( class_exists( $adapter ) ) $adapter::listen();
        }

    }

    /**
     * The adapter responsible for a gateway.
     *
     * Always returns something. Falling back to the null adapter rather than
     * null means callers never have to guard, and an unknown processor takes
     * the same code path as a known one.
     *
     * @since   1.9.0
     *
     * @param   string  $gateway    Gateway ID.
     * @return  string  Adapter class name.
     */
    public static function adapter_for( $gateway ) {

        foreach( self::ADAPTERS as $adapter ) {

            if( ! class_exists( $adapter ) ) continue;

            if( \in_array( $gateway, $adapter::handles(), true ) ) return $adapter;

        }

        return adapter_null::class;

    }

    /**
     * Whether a gateway can do something.
     *
     * @since   1.9.0
     *
     * @param   string  $capability     3ds | card_signals | auth_only.
     * @param   string  $gateway        Gateway ID.
     * @return  bool
     */
    public static function supports( $capability, $gateway ) {

        // auth_only is answered by ai_capture rather than by an adapter. That
        // class shipped a version earlier with its own gateway lists and its
        // own hook/teardown machinery; routing the question here means callers
        // have one capability API even though there are two implementations
        // behind it. Folding ai_capture into a real adapter is a follow-up.
        if( $capability === 'auth_only' ) {

            return (bool) apply_filters(
                'mshield_gateway_supports',
                ai_capture::supports_auth_only( $gateway ),
                $capability,
                $gateway
            );

        }

        $adapter = self::adapter_for( $gateway );

        /**
         * Add support for a gateway MightyShield does not know.
         *
         * Pair a 3ds claim with the mshield_request_3ds action to do the work.
         *
         * @since 1.9.0
         *
         * @param bool   $supported
         * @param string $capability
         * @param string $gateway
         */
        return (bool) apply_filters(
            'mshield_gateway_supports',
            $adapter::supports( $capability, $gateway ),
            $capability,
            $gateway
        );

    }

    /**
     * Whether a gateway can be asked for 3-D Secure.
     *
     * @since   1.9.0
     *
     * @param   string  $gateway
     * @return  bool
     */
    public static function supports_3ds( $gateway ) {

        return self::supports( '3ds', $gateway );

    }

    /**
     * Whether any gateway available at checkout can do 3-D Secure.
     *
     * Drives the settings UI, so a merchant is never offered a challenge their
     * store cannot deliver.
     *
     * @since   1.9.0
     *
     * @return  bool
     */
    public static function any_supports_3ds() {

        return self::any_supports( '3ds' );

    }

    /**
     * Whether any active gateway can do something.
     *
     * Everything asks capability through here, so the filter that lets a store
     * teach MightyShield about an unknown gateway reaches every consumer. The
     * action layer used to ask ai_capture directly for auth_only, which meant
     * the Payment tab and the Blocking tab could give different answers about
     * the same processor.
     *
     * @since   1.9.4
     *
     * @param   string  $capability     3ds | card_signals | auth_only.
     * @return  bool
     */
    public static function any_supports( $capability ) {

        foreach( self::available() as $id => $title ) {
            if( self::supports( $capability, $id ) ) return true;
        }

        return false;

    }

    /**
     * What each available gateway can do, for the admin.
     *
     * @since   1.9.0
     *
     * @return  array   id => [ title, 3ds, card_signals, auth_only, adapter ]
     */
    public static function capability_report() {

        $out = [];

        foreach( self::available() as $id => $title ) {

            $adapter = self::adapter_for( $id );

            $out[ $id ] = [
                'title'        => $title,
                '3ds'          => self::supports( '3ds', $id ),
                'card_signals' => self::supports( 'card_signals', $id ),
                'auth_only'    => self::supports( 'auth_only', $id ),
                'adapter'      => substr( strrchr( $adapter, '\\' ), 1 ),
            ];

        }

        return $out;

    }

    /**
     * Gateways currently available at checkout.
     *
     * @since   1.9.0
     *
     * @return  array   id => title
     */
    private static function available() {

        if( ! function_exists( 'WC' ) || ! WC()->payment_gateways() ) return [];

        $out = [];

        foreach( WC()->payment_gateways()->get_available_payment_gateways() as $id => $gateway ) {
            $out[ $id ] = $gateway->get_title();
        }

        return $out;

    }

    /**
     * Ask the gateway to require 3-D Secure for one order.
     *
     * This is what gives the "challenged" risk level teeth. A real cardholder taps
     * through their bank's prompt and the sale completes; someone using a
     * stolen card cannot. It turns a false-positive-prone block into a
     * near-zero-cost test, and shifts chargeback liability to the issuer.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  bool    True only when a request was actually arranged.
     */
    public static function request_3ds( $order ) {

        $gateway = $order->get_payment_method();
        if( empty( $gateway ) ) return false;

        /**
         * Arrange 3-D Secure for a gateway MightyShield does not know natively.
         *
         * @since 1.9.0
         *
         * @param bool      $handled
         * @param \WC_Order $order
         * @param string    $gateway
         */
        if( apply_filters( 'mshield_request_3ds', false, $order, $gateway ) === true ) return true;

        $adapter = self::adapter_for( $gateway );

        return (bool) $adapter::request_3ds( $order );

    }

    /**
     * Tear down every adapter's per-order filters.
     *
     * @since   1.9.0
     */
    public static function teardown() {

        foreach( self::ADAPTERS as $adapter ) {
            if( class_exists( $adapter ) && method_exists( $adapter, 'teardown' ) ) $adapter::teardown();
        }

    }

}
