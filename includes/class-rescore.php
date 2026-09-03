<?php
/**
 * Rating an order after the fact.
 *
 * At checkout, twenty-odd layers all contribute to one trust rating. Most of
 * them are looking at the request, not the order: whether a hidden field was
 * filled in, how fast the form was submitted, whether the browser reported a
 * webdriver flag, how many orders that IP placed in the last fifteen minutes.
 * None of that survives into the database, and re-running it now would measure
 * the administrator's own browser sitting on wp-admin.
 *
 * So a rating produced here is PARTIAL, and this class is built to say so
 * rather than to hide it. Ten of the thirty-three signals in the catalogue can
 * be derived from a stored order; the other twenty-three are named in
 * SKIPPED_GROUPS and reported alongside the number. An 88 from this is not the
 * same statement as an 88 from checkout, and a panel that presented them
 * identically would be lying by omission.
 *
 * It is also deliberately READ-ONLY. It records a rating and dispatches
 * nothing: no hold, no cancellation, no 3-D Secure request. Rating a shipped
 * order from last year must never cancel it.
 *
 * @package MightyShield
 * @since   1.9.5
 */
namespace MightyShield\Includes;

class rescore {

    /**
     * What a stored order cannot answer for, in the merchant's words.
     *
     * Shown on the panel. Grouped rather than listed signal by signal, because
     * "the bot checks did not run" is the useful statement and twenty-three
     * signal names are not.
     *
     * @since   1.9.5
     */
    const SKIPPED_GROUPS = [
        'bot'      => 'Bot challenge and honeypot',
        'timing'   => 'Checkout timing',
        'device'   => 'Device fingerprint and browser behaviour',
        'velocity' => 'Live rate limits and velocity windows',
    ];

    /**
     * Signals this can actually reproduce from a stored order.
     *
     * Stated so a test can assert the split rather than trusting the comment,
     * and so a new signal added to the catalogue does not quietly change what
     * "partial" means.
     *
     * @since   1.9.5
     */
    const REPLAYABLE = [
        'address_velocity',
        'email_name_mismatch',
        'high_value',
        'ip_geo_mismatch',
        'ip_datacenter',
        'ip_proxy',
        'entity_chargeback',
        'entity_denied',
        'entity_linked_bad',
        'entity_trusted',
    ];

    /**
     * Rate one stored order.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @param   bool        $use_ai     Run the AI review stage as well.
     * @return  array|\WP_Error  The verdict, plus 'signals' and 'used_ai'.
     */
    public static function run( $order, $use_ai = false ) {

        if( ! is_a( $order, 'WC_Order' ) ) {
            return new \WP_Error( 'mshield_no_order', __( 'That order could not be loaded.', 'mighty-shield' ) );
        }

        if( exempt::is_exempt_order( $order ) ) {
            return new \WP_Error(
                'mshield_exempt',
                __( 'This customer is on the allowlist, so MightyShield does not rate their orders.', 'mighty-shield' )
            );
        }

        // risk_context is process-global static state with no production
        // callers of reset(). An admin request can already have signals in it —
        // ip_blocklisted fires on rest_pre_dispatch — so start clean, and leave
        // clean, or a second rating in the same request inherits the first.
        risk_context::reset();

        try {

            self::collect( $order, $use_ai );

            $verdict            = risk_context::evaluate();
            $verdict['signals'] = risk_context::to_array()['signals'];
            $verdict['reasons'] = risk_context::reasons();
            $verdict['used_ai'] = $use_ai && risk_context::has_ai_trust();

            self::persist( $order, $verdict );

            return $verdict;

        } finally {

            risk_context::reset();

        }

    }

    /**
     * Run every check that a stored order can answer for.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @param   bool        $use_ai
     */
    private static function collect( $order, $use_ai ) {

        // The protection classes only load when protection is switched on, and
        // this class is reachable from the admin either way.
        if( ! class_exists( '\MightyShield\Protection\order_signals' ) ) {
            require_once MSHIELD_PATH . 'protection/class-order-signals.php';
        }

        // The second argument switches the exemption test to the ORDER's
        // identity. Without it the check asks whether the administrator is
        // allowlisted, which on most stores is yes, and every signal below
        // would silently return nothing.
        ( new \MightyShield\Protection\order_signals() )->assess( $order, true );

        // Identity history — the only source of the trust-earning signal, and
        // the reason a re-rate is worth doing at all on an old order.
        $identities = entities::for_order( $order );

        if( ! empty( $identities ) ) {
            entities::assess( $identities );
            entities::record( $identities, $order->get_id() );
        }

        self::assess_ip( $order );

        if( $use_ai ) self::review( $order );

    }

    /**
     * Emit the network signals for an order's IP.
     *
     * Reads the cache only. At checkout the fetch has already happened on an
     * earlier hook; here there is no earlier hook, and a blocking geo lookup
     * inside a button click is not worth the wait — a cache miss skips rather
     * than trips, because absent data is not evidence.
     *
     * Shared with risk_recorder, which used to hold the only copy as a private
     * method.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     */
    public static function assess_ip( $order ) {

        $ip = $order->get_customer_ip_address();
        if( empty( $ip ) ) return;

        $geo = db::get_ip_data( $ip );
        if( empty( $geo ) ) return;

        // 1 yes, 0 no, -1 not reported by the provider. Only a positive is
        // evidence; an unreported field must not read as innocence.
        if( isset( $geo['hosting'] ) && (int) $geo['hosting'] === 1 ) {
            risk_context::add(
                'ip_datacenter',
                sprintf( 'IP belongs to a hosting provider or datacenter (%s)', $geo['asname'] ?: $geo['org'] )
            );
        }

        if( isset( $geo['proxy'] ) && (int) $geo['proxy'] === 1 ) {
            risk_context::add( 'ip_proxy', 'IP is a known proxy, VPN, or Tor exit node' );
        }

    }

    /**
     * Ask the model, when the reviewer asked for it.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     */
    private static function review( $order ) {

        if( ! ai_client::is_ready() ) return;

        if( ! class_exists( '\MightyShield\Protection\ai_reviewer' ) ) {
            require_once MSHIELD_PATH . 'protection/class-ai-reviewer.php';
        }

        \MightyShield\Protection\ai_reviewer::review_now( $order );

    }

    /**
     * Store the rating without destroying what was already known.
     *
     * db::save_risk() is a REPLACE INTO: it deletes the row and inserts a fresh
     * one, so every column not supplied reverts to its default. Called naively
     * from here it would wipe a recorded outcome, null the AI rating, blank the
     * AI verdict, and stamp created_at to now — moving a two-year-old order
     * into this month's statistics. So the existing row is read first and those
     * four columns are carried forward.
     *
     * For an order that has never been rated, created_at is the ORDER's date
     * rather than now, for the same reason: rating a back catalogue should not
     * dump it all into the current window.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @param   array       $verdict
     */
    private static function persist( $order, $verdict ) {

        $order_id = $order->get_id();
        $existing = db::get_risk( $order_id );

        $created = $existing && ! empty( $existing['created_at'] )
            ? $existing['created_at']
            : self::order_date( $order );

        db::save_risk( $order_id, [
            'trust'             => $verdict['trust'],
            'risk_level'        => $verdict['risk_level'],
            'risk_level_source' => $verdict['risk_level_source'],
            // Not an action: nothing was dispatched. The word is what stops a
            // reader assuming the order was held because the panel says High.
            'action_taken'      => 'rated',
            'signals'           => $verdict['signals'],
            'rated_by'          => 'manual',
            'created_at'        => $created,
            // Carried forward, not re-derived. The historical narrative this
            // rating is meant to draw on lives in these.
            'outcome'           => $existing['outcome'] ?? '',
            'ai_verdict'        => $existing['ai_verdict'] ?? '',
            'ai_rating'         => self::ai_rating( $order, $existing, $verdict ),
        ] );

        $order->update_meta_data( '_mshield_risk_trust', $verdict['trust'] );
        $order->update_meta_data( '_mshield_risk_level', $verdict['risk_level'] );
        $order->update_meta_data( '_mshield_rated_by', 'manual' );

        $order->add_order_note( sprintf(
            'MightyShield: rated by hand — trust %s/100 → %s. Signals: %s. %s',
            $verdict['trust'],
            risk_levels::label( $verdict['risk_level'] ),
            $verdict['reasons'] ? implode( '; ', $verdict['reasons'] ) : 'none',
            'This is a partial rating: the checkout-time bot, timing and device checks could not be replayed. No action was taken.'
        ) );

        $order->save();

        db::log_event(
            $order->get_customer_ip_address(),
            'risk_engine',
            'flagged',
            sprintf( 'Order #%d rated by hand: %s/100 → %s', $order_id, $verdict['trust'], $verdict['risk_level'] ),
            '',
            (int) $order_id,
            (float) $verdict['trust']
        );

    }

    /**
     * The AI rating to store: this run's, if the model was asked; otherwise
     * whatever was already there.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @param   array|null  $existing
     * @param   array       $verdict
     * @return  int|null
     */
    private static function ai_rating( $order, $existing, $verdict ) {

        if( ! empty( $verdict['used_ai'] ) ) {
            $fresh = $order->get_meta( '_mshield_ai_rating' );
            if( $fresh !== '' && $fresh !== null ) return (int) $fresh;
        }

        if( $existing && $existing['ai_rating'] !== null && $existing['ai_rating'] !== '' ) {
            return (int) $existing['ai_rating'];
        }

        return null;

    }

    /**
     * An order's creation date, in the UTC format the risk table stores.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @return  string
     */
    private static function order_date( $order ) {

        $date = $order->get_date_created();

        return $date ? gmdate( 'Y-m-d H:i:s', $date->getTimestamp() ) : gmdate( 'Y-m-d H:i:s' );

    }

    /**
     * Whether an order carries a rating at all.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     * @return  array|null  The stored risk row, or null when unrated.
     */
    public static function stored( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return null;

        $row = db::get_risk( $order->get_id() );

        // An order rated before the risk table existed still has the mirrored
        // meta, so fall back to it rather than offering to re-rate an order
        // that plainly was rated.
        if( ! $row ) {

            $trust = $order->get_meta( '_mshield_risk_trust' );
            if( $trust === '' || $trust === null ) return null;

            return [
                'trust'             => (float) $trust,
                'risk_level'        => (string) $order->get_meta( '_mshield_risk_level' ),
                'risk_level_source' => '',
                'action_taken'      => '',
                'signals'           => '',
                'rated_by'          => (string) $order->get_meta( '_mshield_rated_by' ),
                'outcome'           => (string) $order->get_meta( '_mshield_outcome' ),
                'ai_rating'         => null,
            ];

        }

        return $row;

    }

    /**
     * The stored signals, decoded, newest weighting first.
     *
     * @since   1.9.5
     *
     * @param   array|null  $row    A row from stored().
     * @return  array   [ [ key, reason, weight, confidence ], … ]
     */
    public static function signals_of( $row ) {

        if( empty( $row['signals'] ) ) return [];

        $signals = json_decode( (string) $row['signals'], true );

        if( ! is_array( $signals ) ) return [];

        usort( $signals, function( $a, $b ) {
            $wa = (float) ( $a['weight'] ?? 0 ) * (float) ( $a['confidence'] ?? 1 );
            $wb = (float) ( $b['weight'] ?? 0 ) * (float) ( $b['confidence'] ?? 1 );
            return $wb <=> $wa;
        } );

        return $signals;

    }

}
