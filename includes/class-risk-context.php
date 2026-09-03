<?php
/**
 * Risk context.
 *
 * The per-request signal bus. Every Phase 1 detector emits into this instead of
 * deciding its own block/flag/notify outcome, so that findings compound: three
 * weak signals now add up to one strong verdict rather than producing three
 * order notes nobody reads.
 *
 * Detectors emit. This class accumulates. Phase 2 (decision) reads the result
 * and acts. Keeping those three jobs separate is what makes the outcome
 * explainable — every risk level can be traced back to the exact signals that
 * produced it.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes;

class risk_context {

    /**
     * Tripped signals for this request, keyed by signal key.
     *
     * @since   1.9.0
     */
    private static $signals = [];


    /**
     * The AI review's own rating for this order, 1-100, or null.
     *
     * Stage two. Deliberately NOT a signal: the AI is shown the running trust
     * rating and every tripped signal before it answers, so treating its
     * verdict as another penalty would charge the same evidence twice. It
     * caps instead. See trust().
     *
     * @since   1.9.2
     */
    private static $ai_trust = null;

    /**
     * Record the AI review's rating.
     *
     * @since   1.9.2
     *
     * @param   int|float   $trust      1-100, 100 being a completely ordinary order.
     * @param   array       $reasons    What the model said, for the order note.
     */
    public static function set_ai_trust( $trust, $reasons = [] ) {

        self::$ai_trust = max(
            risk_levels::FLOOR,
            min( risk_levels::BASELINE, (float) $trust )
        );

        self::$ai_reasons = array_values( array_filter( array_map( 'strval', (array) $reasons ) ) );

    }

    /**
     * Reasons the AI gave, for the order note.
     *
     * @since   1.9.2
     */
    private static $ai_reasons = [];

    /**
     * Whether an AI review has answered for this order.
     *
     * @since   1.9.2
     *
     * @return  bool
     */
    public static function has_ai_trust() {

        return self::$ai_trust !== null;

    }

    /**
     * The AI's rating, or null when no review ran.
     *
     * @since   1.9.2
     *
     * @return  float|null
     */
    public static function ai_trust() {

        return self::$ai_trust;

    }

    /**
     * Record a tripped signal.
     *
     * A signal that is unknown, disabled, or already recorded is ignored — a
     * detector that fires twice in one request (classic validation plus the
     * order-processed pass, say) must not double-count.
     *
     * @since   1.9.0
     *
     * @param   string  $key        Signal key, from signals::CATALOG.
     * @param   string  $reason     Human-readable explanation for the log and admin.
     * @param   float   $confidence How sure this detector is, 0.0-1.0. Scales the weight.
     * @return  bool    True when the signal was recorded.
     */
    public static function add( $key, $reason = '', $confidence = 1.0 ) {

        if( ! isset( signals::CATALOG[ $key ] ) ) return false;
        if( isset( self::$signals[ $key ] ) ) return false;
        if( ! signals::is_enabled( $key ) ) return false;

        $confidence = max( 0.0, min( 1.0, (float) $confidence ) );

        self::$signals[ $key ] = [
            'key'        => $key,
            'reason'     => $reason !== '' ? $reason : signals::label( $key ),
            'weight'     => signals::weight( $key ),
            'confidence' => $confidence,
            'floor'      => signals::floor( $key ),
        ];

        return true;

    }

    /**
     * Whether a signal has tripped this request.
     *
     * @since   1.9.0
     *
     * @param   string  $key
     * @return  bool
     */
    public static function has( $key ) {

        return isset( self::$signals[ $key ] );

    }

    /**
     * Every tripped signal.
     *
     * @since   1.9.0
     *
     * @return  array   Keyed by signal key.
     */
    public static function signals() {

        return self::$signals;

    }

    /**
     * The trust rating for this request, from 1 to 100.
     *
     * 100 is totally trustworthy, 1 is as bad as it gets. Every order starts at
     * the baseline and loses trust for each signal that fires, weighted by how
     * sure that detector is — a half-confident detector costs half its weight
     * rather than all-or-nothing, which is what lets soft signals participate
     * without dominating.
     *
     * @since   1.9.0
     *
     * @return  float
     */
    public static function trust() {

        $penalty = 0.0;
        $blamed  = false;   // anything counted against the order
        $vouched = false;   // positive evidence of good history

        foreach( self::$signals as $signal ) {

            $contribution = (float) $signal['weight'] * (float) $signal['confidence'];
            $penalty     += $contribution;

            if( $contribution > 0 ) $blamed  = true;
            if( $contribution < 0 ) $vouched = true;

        }

        $trust = risk_levels::BASELINE - $penalty;

        // Stage two. The model was given this number and every signal behind
        // it, so its answer supersedes rather than adds to them.
        //
        //   lower  the AI can only take trust away
        //   both   the AI's reading replaces the arithmetic entirely, so a
        //          model that recognises an ordinary customer can rescue an
        //          order the signals were too harsh on
        //
        // Either way the two rules below still apply afterwards, so an AI
        // verdict cannot talk an unvouched order into Trusted.
        if( self::$ai_trust !== null ) {

            $trust = settings::get( 'mshield_ai_direction' ) === 'both'
                ? self::$ai_trust
                : min( $trust, self::$ai_trust );

        }

        // Two rules keep the top of the scale meaningful.
        //
        // 1. Absence of evidence is not trust. An unknown customer with nothing
        //    against them starts at the baseline, but must not be treated as a
        //    proven good customer — that is what "monitored" is for.
        //
        // 2. Trust cannot mask evidence. Account takeover looks exactly like a
        //    long clean history plus a sudden anomaly, so letting a good streak
        //    cancel out real signals would make established accounts the most
        //    valuable thing for an attacker to steal.
        //
        // So the top risk level is reachable only with positive evidence AND nothing
        // held against the order. Otherwise a good history still helps — it
        // offsets penalties — but it cannot buy the top risk level outright.
        if( ( ! $vouched || $blamed ) && $trust > risk_levels::LOW_CEILING ) {
            $trust = risk_levels::LOW_CEILING;
        }

        // Clamp into the 1-100 rating.
        $trust = max( risk_levels::FLOOR, min( risk_levels::BASELINE, $trust ) );

        return round( $trust, 2 );

    }

    /**
     * The highest floor risk level any tripped signal forces.
     *
     * @since   1.9.0
     *
     * @return  array   [ 'risk_level' => string|null, 'key' => string|null ]
     */
    public static function floor_level() {

        $level = null;
        $key  = null;

        foreach( self::$signals as $signal ) {

            if( $signal['floor'] === 'none' ) continue;
            if( ! risk_levels::exists( $signal['floor'] ) ) continue;

            if( $level === null || risk_levels::rank( $signal['floor'] ) > risk_levels::rank( $level ) ) {
                $level = $signal['floor'];
                $key  = $signal['key'];
            }

        }

        return [ 'risk_level' => $level, 'key' => $key ];

    }

    /**
     * Resolve the current risk level.
     *
     * The risk level is the more severe of the trust-derived risk level and the highest
     * signal floor. risk_level_source records which of the two decided it, because an
     * unexplainable verdict is an untunable one.
     *
     * @since   1.9.0
     *
     * @return  array   [ 'risk_level' => string, 'trust' => float, 'risk_level_source' => string ]
     */
    public static function evaluate() {

        $trust      = self::trust();
        $from_trust = risk_levels::from_trust( $trust );
        $floor      = self::floor_level();

        // >= not >: when a floor signal is at least as severe as the
        // score-derived risk level, the signal gets the credit. A tie means the
        // signal would have produced this risk level on its own, and attributing it
        // to "score" would hide the one thing the admin needs to see to tune.
        if( $floor['risk_level'] !== null && risk_levels::rank( $floor['risk_level'] ) >= risk_levels::rank( $from_trust ) ) {
            return [
                'risk_level'        => $floor['risk_level'],
                'trust'       => $trust,
                'risk_level_source' => 'signal:' . $floor['key'],
            ];
        }

        // Attribute to the AI when its rating is what produced this level —
        // otherwise the admin sees "trust" and has no way to tell a scored
        // verdict from a reviewed one.
        $source = 'trust';

        if( self::$ai_trust !== null && risk_levels::from_trust( self::$ai_trust ) === $from_trust ) {

            $signals_only = self::signal_trust();

            if( risk_levels::from_trust( $signals_only ) !== $from_trust ) $source = 'ai';

        }

        return [
            'risk_level'        => $from_trust,
            'trust'             => $trust,
            'risk_level_source' => $source,
        ];

    }

    /**
     * The trust rating from the signals alone, ignoring any AI verdict.
     *
     * Used to tell whether the AI actually changed the outcome, and by the AI
     * reviewer itself to decide whether an order is worth a call — that
     * decision has to be made on the pre-review number, or it would depend on
     * the review it is deciding whether to run.
     *
     * @since   1.9.2
     *
     * @return  float
     */
    public static function signal_trust() {

        $ai = self::$ai_trust;

        self::$ai_trust = null;
        $trust = self::trust();
        self::$ai_trust = $ai;

        return $trust;

    }

    /**
     * Reasons for every tripped signal, most heavily weighted first.
     *
     * @since   1.9.0
     *
     * @return  string[]
     */
    public static function reasons() {

        $sorted = self::$signals;

        uasort( $sorted, function( $a, $b ) {
            $a_score = (float) $a['weight'] * (float) $a['confidence'];
            $b_score = (float) $b['weight'] * (float) $b['confidence'];
            return $b_score <=> $a_score;
        } );

        return array_column( $sorted, 'reason' );

    }


    /**
     * Clear the context.
     *
     * Only needed by tests and by long-running processes (WP-CLI, batch
     * imports) that handle more than one order per PHP process. A normal
     * checkout request builds the context once and discards it at shutdown.
     *
     * @since   1.9.0
     */
    public static function reset() {

        self::$signals   = [];
        self::$ai_trust  = null;
        self::$ai_reasons = [];

    }

    /**
     * A compact array suitable for storing on the order and sending to the AI.
     *
     * @since   1.9.0
     *
     * @return  array
     */
    public static function to_array() {

        $verdict = self::evaluate();

        return [
            'trust'       => $verdict['trust'],
            'risk_level'        => $verdict['risk_level'],
            'risk_level_source' => $verdict['risk_level_source'],
            'signals'     => array_values( array_map( function( $signal ) {
                return [
                    'key'        => $signal['key'],
                    'reason'     => $signal['reason'],
                    'weight'     => $signal['weight'],
                    'confidence' => $signal['confidence'],
                ];
            }, self::$signals ) ),
        ];

    }

}
