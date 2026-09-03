<?php
/**
 * Gateway adapter contract.
 *
 * Everything processor-specific lives behind this. Phases 1-3 run entirely on
 * data available before payment and behave identically everywhere; only the
 * payment-instrument work varies, and this is where that variation is confined.
 *
 * Two rules for anything implementing this:
 *
 * 1. **Capability, then action.** Never attempt something the gateway cannot do
 *    and report success. A merchant told an order was verified when it was not
 *    is worse off than one told nothing.
 * 2. **Degrade, never break.** An unsupported gateway must return false or an
 *    empty array. Across a fleet of stores on different processors, "this one
 *    cannot do 3-D Secure" has to mean "no challenge", never "broken checkout".
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes\Gateways;

interface gateway_adapter {

    /**
     * Gateway IDs this adapter handles.
     *
     * @since   1.9.0
     *
     * @return  string[]
     */
    public static function handles();

    /**
     * Whether this adapter can do something for a gateway.
     *
     * @since   1.9.0
     *
     * @param   string  $capability     3ds | card_signals.
     * @param   string  $gateway        Gateway ID.
     * @return  bool
     */
    public static function supports( $capability, $gateway );

    /**
     * Ask the gateway to require 3-D Secure for one order.
     *
     * Must be scoped to that order and torn down afterwards — nothing may leak
     * into another order in the same request.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  bool    True only when a request was actually arranged.
     */
    public static function request_3ds( $order );

    /**
     * Start listening for card details.
     *
     * Called once at load. Implementations hook whatever their gateway offers
     * and hand what they find to card_signals::ingest_normalised().
     *
     * @since   1.9.0
     */
    public static function listen();

}
