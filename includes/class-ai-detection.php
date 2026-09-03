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

    /**
     * Address velocity — one shipping address receiving orders from many buyers.
     *
     * The signature of a drop address. Queried through wc_get_orders() so it
     * works under both HPOS and legacy post storage.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @return  string|null Reason when tripped, null otherwise.
     */
    private static function signal_address_velocity( $order ) {

        $street = self::shipping_or_billing( $order, 'address_1' );
        if( $street === '' ) return null;

        $limit = (int) settings::get( 'mshield_ai_velocity_orders' );
        $days  = (int) settings::get( 'mshield_ai_velocity_days' );

        // Query on the coarse, reliably-formatted fields only. Street matching
        // is exact in WC order queries, so it is done in PHP below instead.
        // Statuses are left at the WooCommerce default, which includes failed
        // and cancelled orders — a drop address that generates failures is
        // still a drop address.
        $ids = wc_get_orders( [
            'limit'             => 50,
            'return'            => 'ids',
            'shipping_postcode' => self::shipping_or_billing( $order, 'postcode' ),
            'shipping_country'  => self::shipping_or_billing( $order, 'country' ),
            'date_created'      => '>' . ( time() - ( $days * DAY_IN_SECONDS ) ),
            'exclude'           => [ $order->get_id() ],
        ] );

        if( empty( $ids ) || ! is_array( $ids ) ) return null;

        $target = self::normalize_address( $street );
        $count  = 0;

        foreach( $ids as $id ) {

            $past = wc_get_order( $id );
            if( ! $past ) continue;

            if( self::normalize_address( self::shipping_or_billing( $past, 'address_1' ) ) === $target ) {
                $count++;
            }

        }

        if( $count < $limit ) return null;

        return sprintf( 'Shipping address used by %d other orders in the last %d days', $count, $days );

    }

    /**
     * Email/name mismatch — no overlap between the shipping name and the email.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @return  string|null
     */
    private static function signal_email_mismatch( $order ) {

        $email = strtolower( trim( (string) $order->get_billing_email() ) );
        $name  = self::shipping_or_billing( $order, 'first_name' ) . ' ' . self::shipping_or_billing( $order, 'last_name' );
        $name  = strtolower( trim( $name ) );

        // Nothing to compare is not evidence of anything.
        if( $email === '' || $name === '' || strpos( $email, '@' ) === false ) return null;

        $local  = preg_replace( '/[^a-z0-9]/', '', substr( $email, 0, strpos( $email, '@' ) ) );
        if( $local === '' ) return null;

        $tokens = preg_split( '/\s+/', $name );

        foreach( $tokens as $token ) {

            $token = preg_replace( '/[^a-z0-9]/', '', $token );

            // Short tokens (initials, "de", "jr") match too easily to be useful.
            if( strlen( $token ) < 3 ) continue;

            if( strpos( $local, $token ) !== false ) return null;

        }

        return 'Shipping name does not appear in the email address';

    }

    /**
     * High value order.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @return  string|null
     */
    private static function signal_high_value( $order ) {

        $threshold = (float) settings::get( 'mshield_ai_high_value_amount' );
        if( $threshold <= 0 ) return null;

        $total = (float) $order->get_total();
        if( $total < $threshold ) return null;

        return sprintf( 'Order total %s is at or above the high-value threshold %s', number_format( $total, 2 ), number_format( $threshold, 2 ) );

    }

    /**
     * IP location vs shipping address mismatch.
     *
     * Reads the IP cache only. ip_data::get_or_fetch() is a blocking call with
     * no backoff, and this runs on the checkout request — an uncached IP skips
     * the signal rather than costing the shopper five seconds.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @return  string|null
     */
    private static function signal_ip_mismatch( $order ) {

        $ip = $order->get_customer_ip_address();
        if( empty( $ip ) ) return null;

        $geo = db::get_ip_data( $ip );
        if( empty( $geo ) || empty( $geo['country'] ) ) return null;

        $ship_country = strtoupper( self::shipping_or_billing( $order, 'country' ) );
        if( $ship_country === '' ) return null;

        if( strtoupper( $geo['country'] ) !== $ship_country ) {
            return sprintf( 'IP resolves to %s but the order ships to %s', strtoupper( $geo['country'] ), $ship_country );
        }

        // Same country — compare region. ip-api returns a short region code and
        // WooCommerce stores US states the same way, so these line up.
        $ship_state = strtoupper( self::shipping_or_billing( $order, 'state' ) );
        if( $ship_state === '' || empty( $geo['region'] ) ) return null;

        if( strtoupper( $geo['region'] ) !== $ship_state ) {
            return sprintf( 'IP resolves to %s but the order ships to %s', strtoupper( $geo['region'] ), $ship_state );
        }

        return null;

    }

}
