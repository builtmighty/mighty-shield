<?php
/**
 * The trust dial.
 *
 * One 270-degree gauge, drawn two ways. The Scoring tab draws a SPAN — the
 * stretch of the scale a risk level occupies — and the order panel draws a
 * VALUE — where one particular order landed on it. Same geometry, same ticks,
 * same colour ramp, so a merchant reading 62 on an order recognises which band
 * of the Scoring scale it fell in.
 *
 * The maths lived in two anonymous closures inside admin/views/scoring.php,
 * which meant the only way to draw this dial anywhere else was to copy it. That
 * is how the six range labels drifted away from the ladder they described the
 * last time round.
 *
 * Rendered server-side on purpose: the values only change on page load, and
 * inline SVG inherits the theme's currentColor where a bundled JS gauge library
 * would not.
 *
 * @package MightyShield
 * @since   1.9.5
 */
namespace MightyShield\Includes;

class trust_badge {

    /**
     * Dial geometry, in SVG user units on a 0 0 100 100 viewBox.
     *
     * @since   1.9.5
     */
    const CENTRE = 50.0;
    const RADIUS = 40.0;

    /**
     * Where the dial starts, and how far it sweeps, in degrees.
     *
     * 135 is the lower left; sweeping 270 clockwise ends at 45, the lower
     * right. That leaves the opening at the foot, so 0 and 100 sit at the
     * bottom corners and the scale reads left to right.
     *
     * @since   1.9.5
     */
    const START = 135.0;
    const SWEEP = 270.0;

    /**
     * A point on the dial.
     *
     * Angle 0 is on the X axis and increases clockwise, which is what SVG's
     * Y-down coordinate system gives for free.
     *
     * @since   1.9.5
     *
     * @param   float   $pos    Position on the 0-100 scale.
     * @return  array   [ x, y ], rounded to 3dp.
     */
    public static function point( $pos ) {

        $angle = self::START + ( max( 0.0, min( 100.0, (float) $pos ) ) / 100.0 ) * self::SWEEP;
        $rad   = $angle * M_PI / 180;

        return [
            round( self::CENTRE + self::RADIUS * cos( $rad ), 3 ),
            round( self::CENTRE + self::RADIUS * sin( $rad ), 3 ),
        ];

    }

    /**
     * An arc between two positions on the dial.
     *
     * @since   1.9.5
     *
     * @param   float   $from   Start position, 0-100.
     * @param   float   $to     End position, 0-100.
     * @return  string  An SVG path `d` attribute.
     */
    public static function arc( $from, $to ) {

        list( $x1, $y1 ) = self::point( $from );
        list( $x2, $y2 ) = self::point( $to );

        // Over half the dial needs the large-arc flag, or SVG draws the short
        // way round -- which on a 270-degree dial is the wrong two thirds.
        $large = ( ( (float) $to - (float) $from ) / 100 * self::SWEEP ) > 180 ? 1 : 0;

        return sprintf( 'M %s %s A %s %s 0 %d 1 %s %s', $x1, $y1, self::RADIUS, self::RADIUS, $large, $x2, $y2 );

    }

    /**
     * The CSS class that carries a level's ramp colour.
     *
     * The convention was built inline in the views. Stated here so the panel
     * and the scale cannot disagree about what colour Elevated is.
     *
     * @since   1.9.5
     *
     * @param   string  $level  Risk level key, or '' for none.
     * @return  string
     */
    public static function level_class( $level ) {

        return risk_levels::exists( $level ) ? 's-' . $level : 's-none';

    }

    /**
     * The dial itself.
     *
     * Always draws the ticked track. The filled arc is drawn only when the
     * range is real: thresholds are clamped individually and never ordered
     * against each other, so a merchant can set Rejected above High and invert
     * the ladder. A backwards arc renders as a wild sweep across the dial, so
     * an invalid range gets the bare track and an em dash instead.
     *
     * @since   1.9.5
     *
     * @param   array   $args {
     *     @type float|null  from   Arc start, 0-100. Null draws no arc.
     *     @type float|null  to     Arc end, 0-100.
     *     @type string      text   Centre text. Defaults to an em dash.
     *     @type string      label  Accessible description of the whole dial.
     * }
     * @return  string  SVG markup.
     */
    public static function dial( $args = [] ) {

        $from  = isset( $args['from'] ) ? $args['from'] : null;
        $to    = isset( $args['to'] ) ? $args['to'] : null;
        $text  = isset( $args['text'] ) && $args['text'] !== '' ? $args['text'] : '—';
        $label = isset( $args['label'] ) ? $args['label'] : '';

        $valid = $from !== null && $to !== null && (float) $to >= (float) $from;

        $out = sprintf(
            '<svg class="mshield-gauge" viewBox="0 0 100 100" role="img" aria-label="%s">',
            esc_attr( $label )
        );

        // The track is ticked so it reads as a measured scale rather than a
        // plain ring; the value sits on it nearly solid and slightly thicker,
        // so it reads as filled-in rather than as more ticks.
        $out .= sprintf( '<path class="dial" fill="none" d="%s" />', esc_attr( self::arc( 0, 100 ) ) );

        if( $valid ) {
            $out .= sprintf( '<path class="value" fill="none" d="%s" />', esc_attr( self::arc( $from, $to ) ) );
        }

        $out .= sprintf(
            '<text class="value-text" x="50" y="50" text-anchor="middle" dominant-baseline="central">%s</text>',
            esc_html( $text )
        );

        return $out . '</svg>';

    }

    /**
     * A level's stretch of the scale, for the Scoring tab.
     *
     * The arc starts one below `$from` so consecutive levels meet rather than
     * leaving a tick-width gap between 50 and 51.
     *
     * @since   1.9.5
     *
     * @param   string      $level  Risk level key.
     * @param   int|null    $from   Lowest trust in this level, or null when the
     *                              level is unreachable by score.
     * @param   int|null    $to     Highest trust in this level.
     * @return  string  SVG markup.
     */
    public static function span( $level, $from = null, $to = null ) {

        $label = risk_levels::label( $level );
        $valid = $from !== null && $to !== null && (int) $to >= (int) $from;

        return self::dial( [
            'from'  => $valid ? (int) $from - 1 : null,
            'to'    => $valid ? (int) $to : null,
            'text'  => $valid ? $from . '–' . $to : '—',
            'label' => $valid
                /* translators: 1: level name, 2: lowest trust, 3: highest trust. */
                ? sprintf( __( '%1$s: trust %2$d to %3$d', 'mighty-shield' ), $label, $from, $to )
                /* translators: %s: level name. */
                : sprintf( __( '%s: reachable only from a signal', 'mighty-shield' ), $label ),
        ] );

    }

    /**
     * One order's rating, for the order panel.
     *
     * A null trust is an unrated order, not a zero one — the difference between
     * "we have not looked" and "this is as bad as it gets" is the whole point
     * of the panel's first state.
     *
     * @since   1.9.5
     *
     * @param   float|null  $trust  Trust rating, 1-100, or null when unrated.
     * @param   string      $level  Risk level key, or '' when unrated.
     * @return  string  SVG markup.
     */
    public static function value( $trust = null, $level = '' ) {

        if( $trust === null ) {
            return self::dial( [
                'text'  => '—',
                'label' => __( 'This order has not been rated', 'mighty-shield' ),
            ] );
        }

        $trust = max( (float) risk_levels::FLOOR, min( (float) risk_levels::BASELINE, (float) $trust ) );

        return self::dial( [
            'from'  => 0,
            'to'    => $trust,
            'text'  => (string) (int) round( $trust ),
            'label' => risk_levels::exists( $level )
                /* translators: 1: trust rating, 2: level name. */
                ? sprintf( __( 'Rated %1$d out of 100: %2$s', 'mighty-shield' ), (int) round( $trust ), risk_levels::label( $level ) )
                /* translators: %d: trust rating. */
                : sprintf( __( 'Rated %d out of 100', 'mighty-shield' ), (int) round( $trust ) ),
        ] );

    }

    /**
     * The six spans of the trust scale, derived from the configured thresholds.
     *
     * Follows risk_levels::from_trust()'s own rule — most severe first, each
     * level running from just above the previous threshold to its own — so the
     * scale cannot disagree with the engine that draws the line. Banned is
     * absent by design: it has no threshold and is reachable only from a signal
     * floor.
     *
     * @since   1.9.5
     *
     * @return  array   level key => [ from, to ]
     */
    public static function spans() {

        $span  = [];
        $lower = (int) risk_levels::FLOOR;

        foreach( [ risk_levels::REJECTED, risk_levels::HIGH, risk_levels::ELEVATED, risk_levels::LOW ] as $lk ) {
            $upper       = (int) round( risk_levels::threshold( $lk ) );
            $span[ $lk ] = [ $lower, $upper ];
            $lower       = $upper + 1;
        }

        $span[ risk_levels::TRUSTED ] = [ $lower, (int) risk_levels::BASELINE ];

        return $span;

    }

}
