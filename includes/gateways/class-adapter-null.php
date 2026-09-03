<?php
/**
 * Fallback adapter for gateways MightyShield knows nothing about.
 *
 * Not an afterthought. Across a fleet of stores on different processors this is
 * the common case, not the edge case, so it is written to be the thing that
 * never breaks a checkout: every capability is unsupported, every action is a
 * no-op, and nothing is listened for.
 *
 * A store on an unknown gateway still gets the whole scoring pipeline, the full
 * response ladder and the outcome loop. It simply gets no card signals and no
 * step-up challenge, which is a smaller feature set — not a broken one.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes\Gateways;

class adapter_null implements gateway_adapter {

    /**
     * @since 1.9.0
     */
    public static function handles() {

        return [];

    }

    /**
     * @since 1.9.0
     */
    public static function supports( $capability, $gateway ) {

        return false;

    }

    /**
     * @since 1.9.0
     */
    public static function request_3ds( $order ) {

        return false;

    }

    /**
     * @since 1.9.0
     */
    public static function listen() {}

}
