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

defined( 'ABSPATH' ) || exit;

use MightyShield\Includes\db;
use MightyShield\Includes\ip_utils;
use MightyShield\Includes\settings;
use MightyShield\Includes\risk_context;
use MightyShield\Includes\ai_detection;

class order_signals {

    /**
     * Catalog key => the method that evaluates it.
     *
     * @since   1.9.2
     */
    const CHECKS = [
        // Cheap, pure-PHP checks first. Not for speed -- emit() runs all of
        // them regardless -- but because the expensive one is obvious this
        // way: signal_address_velocity does up to fifty order lookups and
        // everything else here reads fields already in hand.
        'identity_blocklisted'       => 'signal_identity_blocklisted',
        'country_blocked'            => 'signal_country_blocked',
        'country_high_risk'          => 'signal_country_high_risk',
        'address_reshipper'          => 'signal_reshipper',
        'address_bill_ship_mismatch' => 'signal_bill_ship_mismatch',
        'phone_area_mismatch'        => 'signal_phone_area',
        'phone_voip'                 => 'signal_phone_voip',
        'email_name_mismatch'        => 'signal_email_mismatch',
        'high_value'                 => 'signal_high_value',
        'amount_over_ceiling'        => 'signal_over_ceiling',
        'ip_geo_mismatch'            => 'signal_ip_mismatch',
        'address_velocity'           => 'signal_address_velocity',
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

        // There is deliberately no second pass once the order exists. These
        // four used to run again on the order-processed hooks, which made the
        // score arrive in two halves either side of the order -- so a signal
        // could only ever change the disposal of an order that had already
        // been created, never whether it was created. Both hooks above see
        // every field these checks read.

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

        $bill = function( $field ) use ( $data ) {
            return trim( (string) ( $data[ 'billing_' . $field ] ?? '' ) );
        };

        // Whether a separate delivery address was actually given. WooCommerce
        // posts ship_to_different_address as "1" when the box is ticked; with
        // it unticked every shipping_* field is empty and $pick has already
        // fallen back to billing, so comparing the two would compare billing
        // with itself and never disagree.
        $separate = ! empty( $data['ship_to_different_address'] );

        return [
            'email'            => (string) ( $data['billing_email'] ?? '' ),
            'phone'            => $bill( 'phone' ),
            'first_name'       => $pick( 'first_name' ),
            'last_name'        => $pick( 'last_name' ),
            'address_1'        => $pick( 'address_1' ),
            'postcode'         => $pick( 'postcode' ),
            'country'          => $pick( 'country' ),
            'state'            => $pick( 'state' ),
            'city'             => $pick( 'city' ),
            // The billing side, kept separately so the two can be compared.
            'has_shipping'     => $separate,
            'bill_address_1'   => $bill( 'address_1' ),
            'bill_postcode'    => $bill( 'postcode' ),
            'bill_country'     => $bill( 'country' ),
            'bill_state'       => $bill( 'state' ),
            'bill_city'        => $bill( 'city' ),
            // The buyer's own name. On a gift the parcel carries the
            // recipient's, and the email belongs to the buyer.
            'bill_first_name'  => $bill( 'first_name' ),
            'bill_last_name'   => $bill( 'last_name' ),
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

        // An order with no shipping address at all -- a downloadable or
        // virtual order -- has nothing to compare, and shipping_or_billing()
        // has already fallen back to billing for the fields above.
        $separate = trim( (string) $order->get_shipping_address_1() ) !== '';

        return [
            'email'            => (string) $order->get_billing_email(),
            'phone'            => (string) $order->get_billing_phone(),
            'first_name'       => ai_detection::shipping_or_billing( $order, 'first_name' ),
            'last_name'        => ai_detection::shipping_or_billing( $order, 'last_name' ),
            'address_1'        => ai_detection::shipping_or_billing( $order, 'address_1' ),
            'postcode'         => ai_detection::shipping_or_billing( $order, 'postcode' ),
            'country'          => ai_detection::shipping_or_billing( $order, 'country' ),
            'state'            => ai_detection::shipping_or_billing( $order, 'state' ),
            'city'             => ai_detection::shipping_or_billing( $order, 'city' ),
            'has_shipping'     => $separate,
            'bill_address_1'   => (string) $order->get_billing_address_1(),
            'bill_postcode'    => (string) $order->get_billing_postcode(),
            'bill_country'     => (string) $order->get_billing_country(),
            'bill_state'       => (string) $order->get_billing_state(),
            'bill_city'        => (string) $order->get_billing_city(),
            'bill_first_name'  => (string) $order->get_billing_first_name(),
            'bill_last_name'   => (string) $order->get_billing_last_name(),
            'total'            => (float) $order->get_total(),
            // The address the recorder (or store_api::prepare()) resolved,
            // never the header WooCommerce copied; a forged X-Real-IP used to
            // silence the geo check on the block checkout.
            'ip'               => ip_utils::order_ip( $order ),
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

        // Two passes: answer every check, then emit. The second pass is what
        // lets one check's confidence depend on another's answer regardless
        // of the order they run in.
        $found = [];

        foreach( self::CHECKS as $key => $method ) {

            // Already answered, at validation or by an earlier pass.
            if( risk_context::has( $key ) ) continue;

            $reason = self::$method( $fields );
            if( $reason === null ) continue;

            $found[ $key ] = $reason;

        }

        foreach( $found as $key => $reason ) {

            $confidence = 1.0;

            // Billing and delivery disagreeing, and the delivery address
            // taking other people's orders, are one fact about one parcel.
            // Charged in full together they pushed a first gift to a dorm
            // past the Rejected line; at half, the ambiguous order is held
            // and looked at. See the catalogue comment on address_velocity.
            if( $key === 'address_bill_ship_mismatch'
                && ( isset( $found['address_velocity'] ) || risk_context::has( 'address_velocity' ) ) ) {
                $confidence = 0.5;
            }

            // add() checks the per-signal toggle itself, so there is no second
            // on/off switch here. The old code had two, and only one of them
            // was reachable.
            risk_context::add( $key, $reason, $confidence );

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
     * The $stored argument is gone with the exemption test it existed to
     * switch. Scoring no longer asks whether anyone is allowlisted -- an order
     * is assessed the same way whether it is being checked out or re-rated
     * afterwards, and the allowlist is consulted once, at the point something
     * would be done about the answer. See class-exempt.
     *
     * @param   \WC_Order   $order
     */
    public function assess( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return;

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

        // The identity graph, not the order table. The old query filtered
        // orders by postcode and country -- neither indexed on HPOS -- and then
        // loaded up to fifty full orders to compare street lines in PHP, on
        // every checkout. The graph already holds every recorded order's
        // normalised address as one hashed identity with an index on it, so
        // this is one indexed count. It sees what MightyShield has recorded:
        // every order since install, plus whatever the back-catalogue pass
        // rated, which the setup wizard runs. Built through for_checkout() so
        // the address is normalised and hashed exactly as the recorder did it.
        $set = \MightyShield\Includes\entities::for_checkout( [
            'shipping_address_1' => (string) $f['address_1'],
            'shipping_postcode'  => (string) $f['postcode'],
            'shipping_country'   => (string) $f['country'],
            'billing_email'      => (string) ( $f['email'] ?? '' ),
        ] );

        if( empty( $set['address'] ) ) return null;

        // "Other" buyers: the same customer's own earlier orders to their own
        // house are not a drop address being shared, and counting them put a
        // household that orders monthly over the limit by itself.
        $count = \MightyShield\Includes\entities::orders_at(
            \MightyShield\Includes\entities::hash( 'address', $set['address'] ),
            time() - ( $days * DAY_IN_SECONDS ),
            (int) $f['exclude_order_id'],
            ! empty( $set['email'] ) ? \MightyShield\Includes\entities::hash( 'email', $set['email'] ) : ''
        );

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

        // Nothing to compare is not evidence of anything.
        if( $email === '' || strpos( $email, '@' ) === false ) return null;

        $local = preg_replace( '/[^a-z0-9]/', '', substr( $email, 0, strpos( $email, '@' ) ) );
        if( $local === '' ) return null;

        // Both names. The email belongs to the buyer, and on a gift the buyer's
        // name is on the card, not the parcel -- so comparing only the shipping
        // name fired this on every present ever sent, on top of the
        // billing-vs-delivery signal that already says "this is going
        // somewhere else". Quiet if either name overlaps the mailbox.
        $names = array_filter( [
            strtolower( trim( $f['first_name'] . ' ' . $f['last_name'] ) ),
            strtolower( trim( ( $f['bill_first_name'] ?? '' ) . ' ' . ( $f['bill_last_name'] ?? '' ) ) ),
        ] );

        if( empty( $names ) ) return null;

        foreach( $names as $name ) {

            foreach( preg_split( '/\s+/', $name ) as $token ) {

                $token = preg_replace( '/[^a-z0-9]/', '', $token );

                // Short tokens (initials, "de", "jr") match too easily to be useful.
                if( strlen( $token ) < 3 ) continue;

                if( strpos( $local, $token ) !== false ) return null;

            }

        }

        return 'Neither the delivery name nor the billing name appears in the email address';

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

        $threshold = self::high_value_threshold();
        if( $threshold <= 0 ) return null;

        $total = (float) $f['total'];
        if( $total < $threshold ) return null;

        return sprintf( 'Order total %s is at or above the high-value threshold %s', number_format( $total, 2 ), number_format( $threshold, 2 ) );

    }

    /**
     * The high-value threshold until the store has taught us its own.
     *
     * @since   2.3.0
     */
    const HIGH_VALUE_FALLBACK = 500.0;

    /**
     * What counts as a large order for THIS store.
     *
     * A figure the merchant typed wins. With the setting at 0 this falls back
     * to the store's own 95th percentile, recomputed daily by db::cleanup().
     *
     * The fixed default it replaces was 500.00, and it was wrong for almost
     * everybody. A store selling £20 candles never tripped it, so the signal
     * did nothing; a store selling £4,000 sofas tripped it on every order,
     * which is worse than nothing -- a signal that fires on all of your
     * traffic is not evidence, it just moves the whole score down 15 and makes
     * every threshold above it mean something different from what the merchant
     * configured.
     *
     * Percentile rather than a multiple of the mean, which is what the other
     * plugins do: one £40,000 trade order drags a mean far enough that nothing
     * looks large afterwards. The 95th percentile is where "unusual for this
     * store" genuinely sits and a single outlier cannot move it.
     *
     * @since   2.3.0
     *
     * @return  float   Typed, learned, or the fallback -- never 0.
     */
    public static function high_value_threshold() {

        $configured = (float) settings::get( 'mshield_ai_high_value_amount' );
        if( $configured > 0 ) return $configured;

        $learned = (float) get_option( 'mshield_high_value_learned', 0 );
        if( $learned > 0 ) return $learned;

        // Nothing typed and nothing learned yet -- a young store. The old
        // fixed figure stands in until enough completed orders exist to learn
        // from, so the signal is never simply absent.
        return self::HIGH_VALUE_FALLBACK;

    }

    /**
     * A hard ceiling the merchant set.
     *
     * Separate from high_value on purpose. That one asks "is this unusual for
     * this store", and moves as the store does. This one is a line somebody
     * drew, and a line that moved on its own would not be one.
     *
     * @since   2.3.0
     *
     * @param   array   $f
     * @return  string|null
     */
    private static function signal_over_ceiling( $f ) {

        $ceiling = (float) settings::get( 'mshield_max_order_amount' );
        if( $ceiling <= 0 ) return null;

        $total = (float) $f['total'];
        if( $total <= $ceiling ) return null;

        return sprintf( 'Order total %s is above the ceiling of %s', number_format( $total, 2 ), number_format( $ceiling, 2 ) );

    }

    /**
     * Country the merchant does not sell to.
     *
     * Tested against the DELIVERY country, which is where the goods go. A
     * billing address in a blocked country with delivery somewhere allowed is
     * a different question, and one address_bill_ship_mismatch already asks.
     *
     * @since   2.3.0
     *
     * @param   array   $f
     * @return  string|null
     */
    /**
     * The order's details are on the merchant's blocklist.
     *
     * The IP half of the blocklist is checked by ip_blocklist itself, on
     * woocommerce_checkout_process, because an address is knowable before any
     * of this. Everything else needs the order, so it is checked here.
     *
     * @since   2.3.0
     *
     * @param   array   $f
     * @return  string|null
     */
    private static function signal_identity_blocklisted( $f ) {

        return \MightyShield\Firewall\ip_blocklist::matches_fields( $f );

    }

    private static function signal_country_blocked( $f ) {

        $country = strtoupper( trim( (string) $f['country'] ) );
        if( $country === '' ) return null;

        if( ! in_array( $country, self::country_list( 'mshield_blocked_countries' ), true ) ) return null;

        return sprintf( 'Delivery to %s, which is on your blocked list', $country );

    }

    /**
     * Country the merchant still sells to but wants looked at.
     *
     * @since   2.3.0
     *
     * @param   array   $f
     * @return  string|null
     */
    private static function signal_country_high_risk( $f ) {

        $country = strtoupper( trim( (string) $f['country'] ) );
        if( $country === '' ) return null;

        if( ! in_array( $country, self::country_list( 'mshield_high_risk_countries' ), true ) ) return null;

        return sprintf( 'Delivery to %s, which you treat as higher risk', $country );

    }

    /**
     * Read one of the country settings into a list of uppercase codes.
     *
     * Tolerant of how people actually fill a textarea in: newlines, commas,
     * spaces, lowercase, and stray blank lines all work. Anything that is not
     * two letters is dropped rather than guessed at -- "United Kingdom" typed
     * into a field asking for codes should do nothing, not match a country
     * beginning "Un".
     *
     * @since   2.3.0
     *
     * @param   string  $option
     * @return  string[]
     */
    private static function country_list( $option ) {

        // Deliberately not memoized. This had a static cache keyed by option
        // name, which bought nothing -- get_option() is already served from
        // WordPress's own options cache, and splitting a short string is
        // free -- and cost something real: the list was frozen for the
        // lifetime of the process, so the first call in a request decided the
        // answer for every later one. That is invisible on a checkout, which
        // reads the setting once, and it silently disabled both country
        // checks under test.
        //
        // A cache that can only be wrong is not an optimisation.
        $out = [];

        foreach( preg_split( '/[\s,;]+/', strtoupper( (string) settings::get( $option ) ) ) as $code ) {
            if( preg_match( '/^[A-Z]{2}$/', $code ) ) $out[] = $code;
        }

        return array_values( array_unique( $out ) );

    }

    /**
     * Billing and delivery addresses disagree.
     *
     * Compares street, postcode and country, and needs TWO of the three to
     * disagree before it says anything.
     *
     * That is not caution for its own sake -- it is because the street
     * comparison is the weak one. ai_detection::normalize_address() lowercases
     * and strips punctuation but does not expand abbreviations, so "12 High
     * St" and "12 High Street" are two different strings to it. On its own
     * that would fire on people who typed their own address slightly
     * differently in two boxes, which is most people. Requiring the postcode
     * or the country to disagree as well means a genuine second address, not
     * a second spelling of the first one.
     *
     * @since   2.3.0
     *
     * @param   array   $f
     * @return  string|null
     */
    /**
     * Delivering to an address the merchant has named as a forwarder.
     *
     * Matched two ways, because a merchant will have one or the other to
     * hand: a street line, compared through the same normalizer
     * address_velocity uses, or a bare postcode. A postcode entry is the
     * blunter of the two and catches a whole warehouse; a street line is
     * exact.
     *
     * Ships empty, and should. A bundled list of "known" forwarders is a list
     * of real warehouses, and one wrong entry refuses every order a
     * legitimate business ever places from it. The merchant knows which
     * addresses are costing them.
     *
     * @since   2.3.0
     *
     * @param   array   $f
     * @return  string|null
     */
    private static function signal_reshipper( $f ) {

        $raw = trim( (string) settings::get( 'mshield_reshipper_addresses' ) );

        if( $raw === '' ) return null;

        $street   = ai_detection::normalize_address( (string) $f['address_1'] );
        $postcode = strtoupper( preg_replace( '/[^A-Z0-9]/i', '', (string) $f['postcode'] ) );

        if( $street === '' && $postcode === '' ) return null;

        foreach( preg_split( '/[\r\n]+/', $raw ) as $line ) {

            $line = trim( $line );
            if( $line === '' ) continue;

            // A postcode is short and has no spaces once normalised; anything
            // longer is treated as a street line. Deliberately not a setting:
            // asking a merchant to declare which kind each line is, per line,
            // is a worse experience than getting it right from the shape.
            $as_postcode = strtoupper( preg_replace( '/[^A-Z0-9]/i', '', $line ) );

            if( $postcode !== '' && strlen( $as_postcode ) <= 8 && $as_postcode === $postcode ) {
                return sprintf( 'Delivery postcode %s is on your forwarding-address list', strtoupper( trim( $line ) ) );
            }

            $as_street = ai_detection::normalize_address( $line );

            if( $street !== '' && $as_street !== '' && $as_street === $street ) {
                return 'The delivery address is on your forwarding-address list';
            }

        }

        return null;

    }

    private static function signal_bill_ship_mismatch( $f ) {

        // Nothing was delivered anywhere else, so there is nothing to compare.
        if( empty( $f['has_shipping'] ) ) return null;

        $ship_street = ai_detection::normalize_address( (string) $f['address_1'] );
        $bill_street = ai_detection::normalize_address( (string) $f['bill_address_1'] );

        // An order with only one side filled in is a data problem, not a
        // fraud signal.
        if( $ship_street === '' || $bill_street === '' ) return null;

        $norm_zip = function( $zip ) {
            return strtoupper( preg_replace( '/[^A-Z0-9]/i', '', (string) $zip ) );
        };

        $differs = [];

        if( $ship_street !== $bill_street ) $differs[] = 'street';

        if( $norm_zip( $f['postcode'] ) !== '' && $norm_zip( $f['bill_postcode'] ) !== ''
            && $norm_zip( $f['postcode'] ) !== $norm_zip( $f['bill_postcode'] ) ) {
            $differs[] = 'postcode';
        }

        $ship_country = strtoupper( trim( (string) $f['country'] ) );
        $bill_country = strtoupper( trim( (string) $f['bill_country'] ) );

        if( $ship_country !== '' && $bill_country !== '' && $ship_country !== $bill_country ) {
            $differs[] = 'country';
        }

        if( count( $differs ) < 2 ) return null;

        // A different country is worth naming; the rest is just "not the same
        // place", and a refusal notice should not read back somebody's address
        // to them.
        if( in_array( 'country', $differs, true ) ) {
            return sprintf( 'Card is registered in %s but the order ships to %s', $bill_country, $ship_country );
        }

        return 'Billing and delivery addresses are different';

    }

    /**
     * US phone area code against the state on the order.
     *
     * US numbers only, and only when both sides are present. Everything about
     * this is weak -- see the weight in the catalogue -- so every ambiguity
     * resolves to saying nothing.
     *
     * @since   2.3.0
     *
     * @param   array   $f
     * @return  string|null
     */
    private static function signal_phone_area( $f ) {

        if( strtoupper( trim( (string) $f['country'] ) ) !== 'US' ) return null;

        $state = strtoupper( trim( (string) $f['state'] ) );
        if( $state === '' ) return null;

        $area = self::us_area_code( (string) $f['phone'] );
        if( $area === '' ) return null;

        $map = self::area_code_states();
        if( ! isset( $map[ $area ] ) ) return null;

        if( in_array( $state, $map[ $area ], true ) ) return null;

        return sprintf( 'Phone area code %s belongs to %s, not %s', $area, implode( '/', $map[ $area ] ), $state );

    }

    /**
     * Phone number belongs to a virtual-line service.
     *
     * @since   2.3.0
     *
     * @param   array   $f
     * @return  string|null
     */
    private static function signal_phone_voip( $f ) {

        $area = self::us_area_code( (string) $f['phone'] );
        if( $area === '' ) return null;

        $extra = [];
        foreach( preg_split( '/[\s,;]+/', (string) settings::get( 'mshield_phone_voip_prefixes' ) ) as $code ) {
            if( preg_match( '/^[0-9]{3}$/', $code ) ) $extra[] = $code;
        }

        if( ! in_array( $area, array_merge( self::VOIP_AREA_CODES, $extra ), true ) ) return null;

        return sprintf( 'Phone area code %s is a virtual-line range', $area );

    }

    /**
     * Area codes handed out by virtual-number services rather than carriers.
     *
     * Short and deliberately so. These are the non-geographic NANP ranges that
     * exist to be handed out in bulk -- they are not a guess about a region,
     * and a real person's mobile is never in one.
     *
     * Merchants can add their own on the Scoring tab.
     *
     * @since   2.3.0
     */
    const VOIP_AREA_CODES = [
        // Non-geographic "personal communications" NANP ranges.
        '500', '521', '522', '523', '524', '525', '526', '527', '528', '529',
        '533', '544', '566', '577', '588',
        // Toll-free. Nobody is reached at one of these on a delivery.
        '800', '833', '844', '855', '866', '877', '888',
        // Premium rate.
        '900', '976',
    ];

    /**
     * The area code of a US number, or '' when it is not one.
     *
     * Handles a leading 1 and any punctuation. An area code cannot begin with
     * 0 or 1, which is what rules out most non-US numbers that happen to have
     * ten digits.
     *
     * @since   2.3.0
     *
     * @param   string  $phone
     * @return  string
     */
    private static function us_area_code( $phone ) {

        $digits = preg_replace( '/[^0-9]/', '', (string) $phone );

        if( strlen( $digits ) === 11 && $digits[0] === '1' ) $digits = substr( $digits, 1 );
        if( strlen( $digits ) !== 10 ) return '';

        $area = substr( $digits, 0, 3 );

        if( $area[0] === '0' || $area[0] === '1' ) return '';

        return $area;

    }

    /**
     * US area code to state.
     *
     * Built once per request from AREA_CODES, which is stored the compact way
     * round -- state => codes -- because that is how it is checked and
     * corrected. Area codes that span states (a few do, and every overlay
     * complex adds more) list every state they cover, and a number matching
     * any of them says nothing.
     *
     * An area code that is not in this table says nothing either. The table
     * does not need to be complete to be useful; it needs to never be wrong,
     * because a wrong entry charges a real customer for living somewhere.
     *
     * @since   2.3.0
     *
     * @return  array   area code => state codes.
     */
    private static function area_code_states() {

        static $map = null;

        if( $map !== null ) return $map;

        $map = [];

        foreach( self::AREA_CODES as $state => $codes ) {
            foreach( $codes as $code ) {
                $map[ $code ][] = $state;
            }
        }

        return $map;

    }

    /**
     * State => geographic NANP area codes.
     *
     * Non-geographic ranges (toll-free, premium, personal communications) are
     * deliberately absent: they belong to VOIP_AREA_CODES, where being
     * non-geographic is the point rather than a gap.
     *
     * @since   2.3.0
     */
    const AREA_CODES = [
        'AL' => [ '205', '251', '256', '334', '938' ],
        'AK' => [ '907' ],
        'AZ' => [ '480', '520', '602', '623', '928' ],
        'AR' => [ '327', '479', '501', '870' ],
        'CA' => [ '209', '213', '279', '310', '323', '341', '350', '408', '415', '424', '442', '510', '530', '559', '562', '619', '626', '628', '650', '657', '661', '669', '707', '714', '747', '760', '805', '818', '820', '831', '840', '858', '909', '916', '925', '949', '951' ],
        'CO' => [ '303', '719', '720', '970', '983' ],
        'CT' => [ '203', '475', '860', '959' ],
        'DE' => [ '302' ],
        'DC' => [ '202' ],
        'FL' => [ '239', '305', '321', '324', '352', '386', '407', '448', '561', '656', '689', '727', '728', '754', '772', '786', '813', '850', '863', '904', '941', '954' ],
        'GA' => [ '229', '404', '470', '478', '678', '706', '762', '770', '912', '943' ],
        'HI' => [ '808' ],
        'ID' => [ '208', '986' ],
        'IL' => [ '217', '224', '309', '312', '331', '447', '464', '618', '630', '708', '730', '773', '779', '815', '847', '872' ],
        'IN' => [ '219', '260', '317', '463', '574', '765', '812', '930' ],
        'IA' => [ '319', '515', '563', '641', '712' ],
        'KS' => [ '316', '620', '785', '913' ],
        'KY' => [ '270', '364', '502', '606', '859' ],
        'LA' => [ '225', '318', '337', '504', '985' ],
        'ME' => [ '207' ],
        'MD' => [ '227', '240', '301', '410', '443', '667' ],
        'MA' => [ '339', '351', '413', '508', '617', '774', '781', '857', '978' ],
        'MI' => [ '231', '248', '269', '313', '517', '586', '616', '679', '734', '810', '906', '947', '989' ],
        'MN' => [ '218', '320', '507', '612', '651', '763', '924', '952' ],
        'MS' => [ '228', '601', '662', '769' ],
        'MO' => [ '235', '314', '417', '557', '573', '636', '660', '816' ],
        'MT' => [ '406' ],
        'NE' => [ '308', '402', '531' ],
        'NV' => [ '702', '725', '775' ],
        'NH' => [ '603' ],
        'NJ' => [ '201', '551', '609', '640', '732', '848', '856', '862', '908', '973' ],
        'NM' => [ '505', '575' ],
        'NY' => [ '212', '315', '329', '332', '347', '363', '516', '518', '585', '607', '631', '646', '680', '716', '718', '838', '845', '914', '917', '929', '934' ],
        'NC' => [ '252', '336', '472', '704', '743', '828', '910', '919', '980', '984' ],
        'ND' => [ '701' ],
        'OH' => [ '216', '220', '234', '326', '330', '380', '419', '436', '440', '513', '567', '614', '740', '937' ],
        'OK' => [ '405', '539', '572', '580', '918' ],
        'OR' => [ '458', '503', '541', '971' ],
        'PA' => [ '215', '223', '267', '272', '412', '445', '484', '570', '582', '610', '717', '724', '814', '835', '878' ],
        'RI' => [ '401' ],
        'SC' => [ '803', '821', '839', '843', '854', '864' ],
        'SD' => [ '605' ],
        'TN' => [ '423', '615', '629', '731', '865', '901', '931' ],
        'TX' => [ '210', '214', '254', '281', '325', '346', '361', '409', '430', '432', '469', '512', '682', '713', '726', '737', '806', '817', '830', '832', '903', '915', '936', '940', '945', '956', '972', '979' ],
        'UT' => [ '385', '435', '801' ],
        'VT' => [ '802' ],
        'VA' => [ '276', '434', '540', '571', '703', '757', '804', '826', '948' ],
        'WA' => [ '206', '253', '360', '425', '509', '564' ],
        'WV' => [ '304', '681' ],
        'WI' => [ '262', '274', '353', '414', '534', '608', '715', '920' ],
        'WY' => [ '307' ],
        'PR' => [ '787', '939' ],
        'VI' => [ '340' ],
        'GU' => [ '671' ],
        'AS' => [ '684' ],
        'MP' => [ '670' ],
    ];

    /**
     * IP location vs shipping address mismatch.
     *
     * Reads the IP cache only, and risk_recorder warms it at the start of
     * checkout. Since 2.3.0 that warming is a local database read rather than
     * an HTTP call, so a miss here means the merchant has no MaxMind database
     * installed at all — in which case the signal stays quiet rather than
     * guessing.
     *
     * Country only. This compared region as well until 2.3.0, back when the
     * data came from ip-api. WooCommerce's GeoLite2-Country database resolves
     * to a country and no further, and region was the noisier half anyway: a
     * shopper on a phone routes through whichever city their carrier terminates
     * in, which is regularly a different state from the one they live in.
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

        $ip_country = strtoupper( (string) $geo['country'] );

        if( $ip_country === $ship_country ) return null;

        // The buyer is at home and the parcel is going abroad. That is what a
        // present looks like, and the billing-vs-delivery signal has already
        // charged for the two addresses disagreeing; charging again for the
        // connection agreeing with one of them is the same fact billed twice.
        // A connection that matches NEITHER address is the real signal.
        $bill_country = strtoupper( (string) ( $f['bill_country'] ?? '' ) );
        if( $bill_country !== '' && $ip_country === $bill_country ) return null;

        return sprintf( 'IP resolves to %s but the order ships to %s', $ip_country, $ship_country );

    }

}
