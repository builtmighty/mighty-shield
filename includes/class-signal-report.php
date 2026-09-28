<?php
/**
 * What each signal has actually been right about, and which pairs of them are
 * saying the same thing twice.
 *
 * The Scoring tab already shows how often a check fires. That is half an
 * answer. A check firing on 40% of orders is either finding a lot of fraud or
 * describing a lot of customers, and "how often" cannot tell those apart --
 * only the outcome can.
 *
 * Two reports come out of the same pass over the stored ratings.
 *
 * ATTRIBUTION. For each signal, of the orders it fired on that reached a
 * known outcome, how many turned out fine. A signal sitting at 100% fine over
 * a meaningful number of orders is charging the merchant's own customers, and
 * the weight should come down. This is the plugin's own advice -- "anything
 * firing on most of your orders is describing your customers rather than your
 * fraudsters" -- finally made checkable instead of left to the eye.
 *
 * CORRELATION. Two signals that fire on almost exactly the same orders are
 * one piece of evidence being charged twice. Nothing is wrong with them
 * individually; together they move the rating twice as far as the merchant
 * thinks, and every threshold above them then means something other than what
 * was configured. The catalogue already worries about this in prose -- the
 * note on device_tz_mismatch says a VPN is usually what makes the timezone
 * disagree -- and this measures it on the store's own traffic.
 *
 * Both are deliberately quiet until there is enough to be honest about. A
 * rate computed from four orders is not a rate.
 *
 * @package MightyShield
 * @since   3.0.0
 */
namespace MightyShield\Includes;

defined( 'ABSPATH' ) || exit;

class signal_report {

    /**
     * Ratings to read. Same ceiling as get_signal_stats(), for the same
     * reason: the JSON has to be decoded per row in PHP.
     *
     * @since   3.0.0
     */
    const MAX_ROWS = 2000;

    /**
     * Orders a signal must have fired on before its outcome rate is reported.
     *
     * @since   3.0.0
     */
    const MIN_FIRED = 10;

    /**
     * Share of known outcomes that must be fine before a signal is called out.
     *
     * Not 1.0. A check that is wrong 19 times out of 20 is still wrong, and
     * waiting for perfection would mean never saying anything.
     *
     * @since   3.0.0
     */
    const FALSE_POSITIVE_RATE = 0.95;

    /**
     * How alike two signals must be before they count as the same evidence.
     *
     * Jaccard: the orders both fired on, over the orders either fired on. 0.8
     * means four in five of the orders that tripped one tripped the other as
     * well, in both directions -- which is not a correlation, it is the same
     * fact arriving twice.
     *
     * @since   3.0.0
     */
    const OVERLAP = 0.8;

    /**
     * Orders a pair must share before the overlap is believable.
     *
     * @since   3.0.0
     */
    const MIN_PAIR = 8;

    /**
     * Read the ratings once and build both reports.
     *
     * @since   3.0.0
     *
     * @param   int     $days
     * @return  array
     */
    public static function analyse( $days = 90 ) {

        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned table
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT signals, outcome FROM {$wpdb->prefix}mshield_risk
             WHERE created_at >= DATE_SUB( %s, INTERVAL %d DAY )
               AND signals <> ''
             ORDER BY id DESC
             LIMIT %d",
            gmdate( 'Y-m-d H:i:s' ),
            max( 1, (int) $days ),
            self::MAX_ROWS
        ), ARRAY_A );

        $signals = [];   // key => counts
        $pairs   = [];   // "a|b" => orders both fired on
        $rated   = 0;

        foreach( (array) $rows as $row ) {

            $keys = self::keys_from( $row['signals'] );
            if( empty( $keys ) ) continue;

            $rated++;

            $verdict = self::verdict( $row['outcome'] );

            foreach( $keys as $key ) {

                if( ! isset( $signals[ $key ] ) ) {
                    $signals[ $key ] = [ 'fired' => 0, 'good' => 0, 'bad' => 0, 'refunded' => 0, 'unknown' => 0 ];
                }

                $signals[ $key ]['fired']++;
                $signals[ $key ][ $verdict ]++;

            }

            // Every unordered pair on this order. Sorted so a|b and b|a are
            // the same bucket.
            sort( $keys );
            $n = count( $keys );

            for( $i = 0; $i < $n; $i++ ) {
                for( $j = $i + 1; $j < $n; $j++ ) {
                    $id = $keys[ $i ] . '|' . $keys[ $j ];
                    $pairs[ $id ] = ( $pairs[ $id ] ?? 0 ) + 1;
                }
            }

        }

        uasort( $signals, function( $a, $b ) { return $b['fired'] <=> $a['fired']; } );

        return [
            'days'    => (int) $days,
            'rated'   => $rated,
            'capped'  => count( (array) $rows ) >= self::MAX_ROWS,
            'signals' => $signals,
            'pairs'   => $pairs,
        ];

    }

    /**
     * Signals that keep firing on orders which turned out fine.
     *
     * @since   3.0.0
     *
     * @param   array   $report From analyse().
     * @return  array   key => [ fired, good, bad, known, rate ]
     */
    public static function false_positives( $report ) {

        $out = [];

        foreach( $report['signals'] as $key => $c ) {

            // A signal nobody has configured out of existence but which the
            // catalogue no longer defines is not worth reporting on.
            if( ! isset( signals::CATALOG[ $key ] ) ) continue;

            if( $c['fired'] < self::MIN_FIRED ) continue;

            // Refunds are not counted either way. Most are ordinary retail,
            // so calling them fraud would excuse a bad signal and calling
            // them fine would flatter one.
            $known = $c['good'] + $c['bad'];

            if( $known < self::MIN_FIRED ) continue;

            $rate = $c['good'] / $known;

            if( $rate < self::FALSE_POSITIVE_RATE ) continue;

            $out[ $key ] = [
                'fired' => $c['fired'],
                'good'  => $c['good'],
                'bad'   => $c['bad'],
                'known' => $known,
                'rate'  => $rate,
            ];

        }

        uasort( $out, function( $a, $b ) { return $b['good'] <=> $a['good']; } );

        return $out;

    }

    /**
     * Pairs of signals that are measuring the same thing.
     *
     * @since   3.0.0
     *
     * @param   array   $report From analyse().
     * @return  array   list of [ a, b, together, overlap, cost ]
     */
    public static function overlaps( $report ) {

        $out = [];

        foreach( $report['pairs'] as $id => $together ) {

            if( $together < self::MIN_PAIR ) continue;

            list( $a, $b ) = explode( '|', $id );

            if( ! isset( $report['signals'][ $a ], $report['signals'][ $b ] ) ) continue;
            if( ! isset( signals::CATALOG[ $a ], signals::CATALOG[ $b ] ) ) continue;

            $either = $report['signals'][ $a ]['fired'] + $report['signals'][ $b ]['fired'] - $together;
            if( $either <= 0 ) continue;

            $overlap = $together / $either;

            if( $overlap < self::OVERLAP ) continue;

            $out[] = [
                'a'         => $a,
                'b'         => $b,
                'together'  => $together,
                'overlap'   => $overlap,
                // What the pair costs an order when both fire, which is the
                // number the merchant is unknowingly applying.
                'cost'      => signals::weight( $a ) + signals::weight( $b ),
            ];

        }

        usort( $out, function( $x, $y ) { return $y['overlap'] <=> $x['overlap']; } );

        return $out;

    }

    /**
     * The signal keys on one stored rating.
     *
     * @since   3.0.0
     *
     * @param   string  $json
     * @return  string[]
     */
    private static function keys_from( $json ) {

        $decoded = json_decode( (string) $json, true );

        if( ! is_array( $decoded ) ) return [];

        $keys = [];

        foreach( $decoded as $signal ) {

            $key = is_array( $signal ) ? ( $signal['key'] ?? '' ) : '';

            if( $key !== '' ) $keys[ $key ] = true;

        }

        return array_keys( $keys );

    }

    /**
     * How an order turned out.
     *
     * @since   3.0.0
     *
     * @param   string  $outcome
     * @return  string
     */
    private static function verdict( $outcome ) {

        $outcome = (string) $outcome;

        if( in_array( $outcome, forecast::BAD, true ) ) return 'bad';
        if( $outcome === 'refunded' )                   return 'refunded';
        if( $outcome === 'approved' )                   return 'good';

        return 'unknown';

    }

}
