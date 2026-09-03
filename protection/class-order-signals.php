<?php
/**
 * Whole-order signals.
 *
 * Four whole-order checks: a shipping address collecting orders from unrelated
 * buyers, a name that appears nowhere in the email, an unusually large total,
 * and an IP that resolves nowhere near where the goods are going. Individually
 * each is weak — plenty of real people buy expensive things while travelling —
 * which is exactly why they belong in the scoring bus, where they compound with
 * everything else, rather than deciding anything on their own.
 *
 * They used to run only on order-processed, on the reasoning that they needed a
 * finished order. They do not: every one of them reads address, name, email,
 * total and IP, all of which are on the request at validation. The cost of the
 * old reasoning was that all four arrived AFTER the refusal decision at
 * validation priority 99, so they could hold an order but never turn one away.
 * A previously-denied customer ordering again from a drop address scored 1/100
 * and was still let as far as an order, because 40 of those points did not
 * exist yet when the refusal was decided.
 *
 * They now run at validation on both checkouts and again after the order
 * exists, whichever comes first winning. Note the ceiling that makes that safe:
 * the four together are worth 70 and a refusal needs 75, so they can never
 * turn anyone away on their own — only tip an order that already has other
 * evidence against it.
 *
 * These lived in ai_detection until 1.9.2, where they were unreachable: their
 * only caller was ai_reviewer::review(), and ai_reviewer does not even register
 * its hooks unless AI review is switched on. So on a default install the four
 * signals appeared on the Scoring tab, with weights and their own settings, and
 * could never trip. With AI on they still only ran for orders already selected
 * for review — which is decided by the level these signals were supposed to
 * help set.
 *
 * They now run on every checkout, gated only by their own per-signal toggle,
 * which risk_context::add() already enforces.
 *
 * @package MightyShield
 * @since   1.9.2
 */
namespace MightyShield\Protection;

use MightyShield\Includes\db;
use MightyShield\Includes\ip_utils;
use MightyShield\Includes\settings;
use MightyShield\Includes\exempt;
use MightyShield\Includes\risk_context;
use MightyShield\Includes\ai_detection;

class order_signals {

    /**
     * Catalog key => the method that evaluates it.
     *
     * @since   1.9.2
     */
    const CHECKS = [
        'address_velocity'    => 'signal_address_velocity',
        'email_name_mismatch' => 'signal_email_mismatch',
        'high_value'          => 'signal_high_value',
        'ip_geo_mismatch'     => 'signal_ip_mismatch',
    ];

    /**
     * Construct.
     *
     * @since   1.9.2
     */
    public function __construct() {

        // At validation, priority 35: after account_guard at 30 and well before
        // risk_recorder::refuse_* at 99, so these four can actually influence a
        // refusal instead of arriving after it.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess_validation' ], 35, 2 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'assess_draft' ], 35, 2 );

        // And again once the order exists, for anything validation could not
        // see. Whichever runs first wins: risk_context::add() is
        // first-write-wins, and assess() skips a check already in the context
        // so the address-velocity query is not paid for twice.
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'assess_classic' ], 10, 3 );
        add_action( 'woocommerce_store_api_checkout_order_processed', [ $this, 'assess' ], 10, 1 );

    }

    /**
     * Classic checkout entry point.
     *
     * @since   1.9.2
     *
     * @param   int         $order_id
     * @param   array       $posted
     * @param   \WC_Order   $order
     */
    public function assess_classic( $order_id, $posted, $order ) {

        $this->assess( $order );

    }

    /**
     * Classic checkout, at validation — before any order exists.
     *
     * @since   2.0.0
     *
     * @param   array       $data   Checkout posted data.
     * @param   \WP_Error   $errors
     */
    public function assess_validation( $data, $errors ) {

        if( exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        self::emit( self::from_checkout( $data ) );

    }

    /**
     * Block checkout, at validation.
     *
     * The Store API populates the draft order from the request before this
     * hook, so the order is complete here and needs no separate mapping.
     *
     * @since   2.0.0
     *
     * @param   \WC_Order          $order
     * @param   \WP_REST_Request   $request
     */
    public function assess_draft( $order, $request ) {

        $this->assess( $order );

    }

    /**
     * Read a checkout's posted data into the shape the checks expect.
     *
     * Shipping wins over billing, matching shipping_or_billing() on the order
     * side: the goods are what matters to every one of these checks.
     *
     * @since   2.0.0
     *
     * @param   array   $data   Checkout posted data.
     * @return  array
     */
    public static function from_checkout( $data ) {

        $pick = function( $field ) use ( $data ) {
            $ship = trim( (string) ( $data[ 'shipping_' . $field ] ?? '' ) );
            if( $ship !== '' ) return $ship;
            return trim( (string) ( $data[ 'billing_' . $field ] ?? '' ) );
        };

        // No order exists yet, so the cart is the only total there is.
        $total = ( function_exists( 'WC' ) && WC()->cart ) ? (float) WC()->cart->get_total( 'edit' ) : 0.0;

        return [
            'email'            => (string) ( $data['billing_email'] ?? '' ),
            'first_name'       => $pick( 'first_name' ),
            'last_name'        => $pick( 'last_name' ),
            'address_1'        => $pick( 'address_1' ),
            'postcode'         => $pick( 'postcode' ),
            'country'          => $pick( 'country' ),
            'state'            => $pick( 'state' ),
            'total'            => $total,
            'ip'               => ip_utils::get_client_ip(),
            'exclude_order_id' => 0,
        ];

    }

    /**
     * Read a finished order into the same shape.
     *
     * @since   2.0.0
     *
     * @param   \WC_Order   $order
     * @return  array
     */
    public static function from_order( $order ) {

        return [
            'email'            => (string) $order->get_billing_email(),
            'first_name'       => ai_detection::shipping_or_billing( $order, 'first_name' ),
            'last_name'        => ai_detection::shipping_or_billing( $order, 'last_name' ),
            'address_1'        => ai_detection::shipping_or_billing( $order, 'address_1' ),
            'postcode'         => ai_detection::shipping_or_billing( $order, 'postcode' ),
            'country'          => ai_detection::shipping_or_billing( $order, 'country' ),
            'state'            => ai_detection::shipping_or_billing( $order, 'state' ),
            'total'            => (float) $order->get_total(),
            'ip'               => (string) $order->get_customer_ip_address(),
            'exclude_order_id' => (int) $order->get_id(),
        ];

    }

    /**
     * Run every check that has not already answered.
     *
     * The skip is not just an optimisation. address_velocity does up to fifty
     * order lookups, and this runs twice per checkout by design — once at
     * validation and once after the order exists. Without the guard the second
     * pass pays for that query again and then throws the answer away, because
     * risk_context::add() is first-write-wins.
     *
     * @since   2.0.0
     *
     * @param   array   $fields Normalised order fields.
     */
    public static function emit( $fields ) {

        foreach( self::CHECKS as $key => $method ) {

            // Already answered, at validation or by an earlier pass.
            if( risk_context::has( $key ) ) continue;

            $reason = self::$method( $fields );
            if( $reason === null ) continue;

            // add() checks the per-signal toggle itself, so there is no second
            // on/off switch here. The old code had two, and only one of them
            // was reachable.
            risk_context::add( $key, $reason );

        }

    }

    /**
     * Evaluate every check against one order.
     *
     * A check that cannot be evaluated — no address, an uncached IP — is
     * skipped rather than tripped. Absent data is not evidence of fraud.
     *
     * @since   1.9.2
     *
     * @param   \WC_Order   $order
     * @param   bool        $stored     True when the order is being assessed
     *                                  after the fact rather than during its own
     *                                  checkout. Switches the exemption test to
     *                                  the order's identity instead of the
     *                                  request's — see exempt::is_exempt_order().
     */
    public function assess( $order, $stored = false ) {

        if( ! is_a( $order, 'WC_Order' ) ) return;

        $skip = $stored
            ? exempt::is_exempt_order( $order )
            : exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() );

        if( $skip ) return;

        self::emit( self::from_order( $order ) );

    }

    /**
     * Address velocity — one shipping address receiving orders from many buyers.
     *
     * The signature of a drop address. Queried through wc_get_orders() so it
     * works under both HPOS and legacy post storage.
     *
     * @since   1.9.2
     *
     * @param   array   $f      Normalised order fields.
     * @return  string|null Reason when tripped, null otherwise.
     */
    private static function signal_address_velocity( $f ) {

        $street = (string) $f['address_1'];
        if( $street === '' ) return null;

        $limit = (int) settings::get( 'mshield_ai_velocity_orders' );
        $days  = (int) settings::get( 'mshield_ai_velocity_days' );

        if( $limit <= 0 || $days <= 0 ) return null;

        // Query on the coarse, reliably-formatted fields only. Street matching
        // is exact in WC order queries, so it is done in PHP below instead.
        // Statuses are left at the WooCommerce default, which includes failed
        // and cancelled orders — a drop address that generates failures is
        // still a drop address.
        $ids = wc_get_orders( [
            'limit'             => 50,
            'return'            => 'ids',
            'shipping_postcode' => (string) $f['postcode'],
            'shipping_country'  => (string) $f['country'],
            'date_created'      => '>' . ( time() - ( $days * DAY_IN_SECONDS ) ),
            // Zero at validation, where this order does not exist yet. An
            // empty exclude list is what wc_get_orders() expects for "nothing".
            'exclude'           => $f['exclude_order_id'] ? [ (int) $f['exclude_order_id'] ] : [],
        ] );

        if( empty( $ids ) || ! is_array( $ids ) ) return null;

        $target = ai_detection::normalize_address( $street );
        $count  = 0;

        foreach( $ids as $id ) {

            $past = wc_get_order( $id );
            if( ! $past ) continue;

            if( ai_detection::normalize_address( ai_detection::shipping_or_billing( $past, 'address_1' ) ) === $target ) {
                $count++;
            }

        }

        if( $count < $limit ) return null;

        return sprintf( 'Shipping address used by %d other orders in the last %d days', $count, $days );

    }

    /**
     * Email/name mismatch — no overlap between the shipping name and the email.
     *
     * @since   1.9.2
     *
     * @param   array   $f      Normalised order fields.
     * @return  string|null
     */
    private static function signal_email_mismatch( $f ) {

        $email = strtolower( trim( (string) $f['email'] ) );
        $name  = strtolower( trim( $f['first_name'] . ' ' . $f['last_name'] ) );

        // Nothing to compare is not evidence of anything.
        if( $email === '' || $name === '' || strpos( $email, '@' ) === false ) return null;

        $local = preg_replace( '/[^a-z0-9]/', '', substr( $email, 0, strpos( $email, '@' ) ) );
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
     * @since   1.9.2
     *
     * @param   array   $f      Normalised order fields.
     * @return  string|null
     */
    private static function signal_high_value( $f ) {

        $threshold = (float) settings::get( 'mshield_ai_high_value_amount' );
        if( $threshold <= 0 ) return null;

        $total = (float) $f['total'];
        if( $total < $threshold ) return null;

        return sprintf( 'Order total %s is at or above the high-value threshold %s', number_format( $total, 2 ), number_format( $threshold, 2 ) );

    }

    /**
     * IP location vs shipping address mismatch.
     *
     * Reads the IP cache only. ip_data::get_or_fetch() is a blocking call with
     * no backoff, and this runs on the checkout request — an uncached IP skips
     * the signal rather than costing the shopper five seconds. risk_recorder
     * warms the cache at the start of checkout for exactly this reason.
     *
     * @since   1.9.2
     *
     * @param   array   $f      Normalised order fields.
     * @return  string|null
     */
    private static function signal_ip_mismatch( $f ) {

        $ip = (string) $f['ip'];
        if( empty( $ip ) ) return null;

        $geo = db::get_ip_data( $ip );
        if( empty( $geo ) || empty( $geo['country'] ) ) return null;

        $ship_country = strtoupper( (string) $f['country'] );
        if( $ship_country === '' ) return null;

        if( strtoupper( $geo['country'] ) !== $ship_country ) {
            return sprintf( 'IP resolves to %s but the order ships to %s', strtoupper( $geo['country'] ), $ship_country );
        }

        // Same country — compare region. ip-api returns a short region code and
        // WooCommerce stores US states the same way, so these line up.
        $ship_state = strtoupper( (string) $f['state'] );
        if( $ship_state === '' || empty( $geo['region'] ) ) return null;

        if( strtoupper( $geo['region'] ) !== $ship_state ) {
            return sprintf( 'IP resolves to %s but the order ships to %s', strtoupper( $geo['region'] ), $ship_state );
        }

        return null;

    }

}
