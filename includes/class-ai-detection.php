<?php
/**
 * Address helpers.
 *
 * What is left of the old AI-detection scorer. Its four checks moved to
 * protection/class-order-signals.php in 1.9.2, where they run on every checkout
 * instead of only when AI review was switched on, and its own 0-10 suspicion
 * score was retired: the plugin now has one scale, the 1-100 trust rating.
 *
 * These two helpers stay because they are used independently of any of that —
 * by class-entities.php to derive identities, and by the AI prompt builder to
 * format an address.
 *
 * @package MightyShield
 * @since   1.8.0
 */
namespace MightyShield\Includes;

class ai_detection {

    /**
     * Read a shipping field, falling back to billing.
     *
     * Virtual and downloadable orders leave shipping blank rather than
     * mirroring billing, so every shipping read goes through here — otherwise
     * three of the four signals silently never trip on those orders.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @param   string      $field  Field suffix, e.g. 'city'.
     * @return  string
     */
    public static function shipping_or_billing( $order, $field ) {

        $ship = 'get_shipping_' . $field;
        $bill = 'get_billing_' . $field;

        $value = method_exists( $order, $ship ) ? trim( (string) $order->$ship() ) : '';
        if( $value !== '' ) return $value;

        return method_exists( $order, $bill ) ? trim( (string) $order->$bill() ) : '';

    }

    /**
     * Normalize a street address for comparison.
     *
     * "123 Main St." and "123  main st" must compare equal — WooCommerce order
     * queries match addresses exactly, so the real comparison happens here.
     *
     * @since   1.8.0
     *
     * @param   string  $address
     * @return  string
     */
    public static function normalize_address( $address ) {

        $address = strtolower( trim( $address ) );
        $address = preg_replace( '/[^a-z0-9 ]/', '', $address );
        return preg_replace( '/\s+/', ' ', $address );

    }

}
