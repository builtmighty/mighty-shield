<?php
/**
 * What enforcing would actually have done.
 *
 * Observe mode is the best thing in this plugin and, until now, the least
 * useful. It rates every order and records what it would have done, and then
 * leaves the merchant to work out from a log whether turning enforcement on
 * is safe. Nobody can read that off a list of events.
 *
 * This answers the question they actually have: if I enforce, with these
 * thresholds, what happens to orders like the ones I already took? And the
 * half that matters more: how many of the orders it would have turned away
 * turned out to be fine?
 *
 * That second number is the one no fraud plugin shows you, and it is the only
 * one that makes a threshold a decision rather than a guess. A tool that
 * reports what it caught and not what it cost is not telling you whether it
 * is working.
 *
 * Three things this is careful about.
 *
 * It re-derives the level from the STORED trust rating rather than the stored
 * level, so moving a threshold changes the answer. That is the whole point --
 * the merchant is asking about a threshold they have not committed to.
 *
 * It respects signal floors. A rating whose level came from a floor
 * (risk_level_source = 'signal:honeypot') was not reached by arithmetic and
 * no threshold can move it, so it is held fixed. Pretending otherwise would
 * overstate what a threshold change achieves.
 *
 * It says what it does not know. Most orders have no recorded outcome yet --
 * they were neither refunded nor charged back nor reviewed -- and counting
 * those as "fine" would flatter every threshold. They are reported
 * separately, as unknown.
 *
 * @package MightyShield
 * @since   2.3.0
 */
namespace MightyShield\Includes;

defined( 'ABSPATH' ) || exit;

class forecast {

    /**
     * Most ratings to read.
     *
     * The work is per-row and done in PHP, because a signal floor has to be
     * honoured and a threshold is not known to SQL. Five thousand is far more
     * than enough to see the shape of a store's traffic and still runs in
     * milliseconds.
     *
     * @since   2.3.0
     */
    const MAX_ROWS = 5000;

    /**
     * Outcomes that mean the order was bad.
     *
     * A refund is deliberately not here. Most refunds are ordinary retail --
     * wrong size, changed their mind -- and counting them as fraud would make
     * every threshold look better than it is. Reported on its own.
     *
     * @since   2.3.0
     */
    const BAD = [ 'chargeback', 'denied' ];

    /**
     * Work out what enforcing would have done.
     *
     * @since   2.3.0
     *
     * @param   int         $days       How far back to look.
     * @param   array|null  $thresholds level => trust rating. Null uses what
     *                                  the store currently has configured.
     * @return  array
     */
    public static function run( $days = 30, $thresholds = null ) {

        $rows = self::rows( $days );

        if ( $thresholds === null ) {
            $thresholds = [];
            foreach ( array_keys( risk_levels::DEFAULT_THRESHOLDS ) as $level ) {
                $thresholds[ $level ] = risk_levels::threshold( $level );
            }
        }

        $out = [
            'days'       => (int) $days,
            'rated'      => 0,
            'capped'     => count( $rows ) >= self::MAX_ROWS,
            'thresholds' => $thresholds,
            // action => [ total, bad, refunded, good, unknown ]
            'actions'    => [],
            'levels'     => [],
            // The two headline numbers.
            'stopped'    => 0,
            'turned_away'=> 0,
            'unknown'    => 0,
        ];

        foreach ( $rows as $row ) {

            $out['rated']++;

            $level  = self::level_for( $row, $thresholds );
            $action = risk_levels::action( $level );
            $verdict = self::verdict( $row['outcome'] );

            foreach ( [ 'levels' => $level, 'actions' => $action ] as $bucket => $key ) {

                if ( ! isset( $out[ $bucket ][ $key ] ) ) {
                    $out[ $bucket ][ $key ] = [ 'total' => 0, 'bad' => 0, 'refunded' => 0, 'good' => 0, 'unknown' => 0 ];
                }

                $out[ $bucket ][ $key ]['total']++;
                $out[ $bucket ][ $key ][ $verdict ]++;

            }

            // Refusing is the only action a customer cannot recover from
            // without contacting the store, so it is the only one counted
            // here. A hold is a delay, not a lost sale.
            if ( actions::REJECT === $action ) {
                if ( 'bad' === $verdict )      { $out['stopped']++; }
                if ( 'good' === $verdict )     { $out['turned_away']++; }
                if ( 'unknown' === $verdict )  { $out['unknown']++; }
            }

        }

        return $out;

    }

    /**
     * The level a stored rating would land in under a given set of thresholds.
     *
     * @since   2.3.0
     *
     * @param   array   $row
     * @param   array   $thresholds
     * @return  string
     */
    private static function level_for( $row, $thresholds ) {

        // A floor is not arithmetic and no threshold can move it.
        if ( 0 === strpos( (string) $row['risk_level_source'], 'signal:' ) ) {
            return (string) $row['risk_level'];
        }

        $trust = (float) $row['trust'];

        // Most severe first, the same order risk_levels::from_trust() uses,
        // so the forecast and the real decision cannot disagree.
        foreach ( [ risk_levels::REJECTED, risk_levels::HIGH, risk_levels::ELEVATED, risk_levels::LOW ] as $level ) {

            if ( ! isset( $thresholds[ $level ] ) ) { continue; }

            if ( $trust <= (float) $thresholds[ $level ] ) { return $level; }

        }

        return risk_levels::TRUSTED;

    }

    /**
     * How an order turned out, in the three words this report uses.
     *
     * @since   2.3.0
     *
     * @param   string  $outcome
     * @return  string  bad | refunded | good | unknown
     */
    private static function verdict( $outcome ) {

        $outcome = (string) $outcome;

        if ( in_array( $outcome, self::BAD, true ) ) { return 'bad'; }
        if ( 'refunded' === $outcome )               { return 'refunded'; }
        if ( 'approved' === $outcome )               { return 'good'; }

        return 'unknown';

    }

    /**
     * The stored ratings to forecast against.
     *
     * Only ratings produced at checkout. A manual re-rate is partial by
     * construction -- rescore can replay 21 of the 52 signals and says so --
     * so mixing those in would forecast from numbers that were never the
     * whole picture.
     *
     * @since   2.3.0
     *
     * @param   int     $days
     * @return  array
     */
    private static function rows( $days ) {

        global $wpdb;

        // Live checkout ratings ('checkout', or '' from builds that did not yet
        // stamp it) and the post-payment card pass ('card', which is the same
        // order re-rated in place). Not 'manual', which is a partial re-rate,
        // and not 'unrated': that is an outcome recorded against an order that
        // was never rated, and it is stored with trust 0 -- so it would be read
        // here as an order enforcing refused.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned table
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT trust, risk_level, risk_level_source, outcome
             FROM {$wpdb->prefix}mshield_risk
             WHERE created_at >= DATE_SUB( %s, INTERVAL %d DAY )
               AND rated_by IN ( 'checkout', '', 'card' )
             ORDER BY created_at DESC
             LIMIT %d",
            gmdate( 'Y-m-d H:i:s' ),
            max( 1, (int) $days ),
            self::MAX_ROWS
        ), ARRAY_A );

        return is_array( $rows ) ? $rows : [];

    }

    /**
     * One sentence a merchant can act on.
     *
     * Deliberately returns nothing when there is not enough to be honest
     * about. A forecast from nine orders is noise wearing a number, and
     * showing it would be worse than showing nothing -- somebody would
     * enforce on it.
     *
     * @since   2.3.0
     *
     * @param   array   $f  From run().
     * @return  string  Empty when there is nothing worth saying.
     */
    public static function summary( $f ) {

        if ( $f['rated'] < 20 ) { return ''; }

        $refused = isset( $f['actions'][ actions::REJECT ] ) ? $f['actions'][ actions::REJECT ]['total'] : 0;

        if ( 0 === $refused ) {
            return sprintf(
                /* translators: %s: number of orders. */
                _n(
                    'Across your last %s rated order, enforcing would have refused nothing.',
                    'Across your last %s rated orders, enforcing would have refused nothing.',
                    $f['rated'],
                    'mighty-shield'
                ),
                number_format_i18n( $f['rated'] )
            );
        }

        $parts = [];

        $parts[] = sprintf(
            /* translators: 1: orders that would be refused, 2: orders rated. */
            __( 'Enforcing would have refused %1$s of your last %2$s orders.', 'mighty-shield' ),
            number_format_i18n( $refused ),
            number_format_i18n( $f['rated'] )
        );

        if ( $f['stopped'] > 0 ) {
            $parts[] = sprintf(
                /* translators: %s: number of orders. */
                _n( '%s of those did turn out to be fraud.', '%s of those did turn out to be fraud.', $f['stopped'], 'mighty-shield' ),
                number_format_i18n( $f['stopped'] )
            );
        }

        if ( $f['turned_away'] > 0 ) {
            $parts[] = sprintf(
                /* translators: %s: number of orders. */
                _n(
                    '%s completed normally, so you would have turned away a real customer.',
                    '%s completed normally, so you would have turned away that many real customers.',
                    $f['turned_away'],
                    'mighty-shield'
                ),
                number_format_i18n( $f['turned_away'] )
            );
        }

        if ( $f['unknown'] > 0 ) {
            $parts[] = sprintf(
                /* translators: %s: number of orders. */
                __( 'The other %s have no outcome recorded yet.', 'mighty-shield' ),
                number_format_i18n( $f['unknown'] )
            );
        }

        return implode( ' ', $parts );

    }

}
