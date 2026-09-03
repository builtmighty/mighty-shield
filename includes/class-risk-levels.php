<?php
/**
 * The response ladder.
 *
 * Six risk levels, ordered by severity. Everything MightyShield decides about an
 * order resolves to exactly one of them, and the risk level determines whether the
 * payment processor is contacted at all.
 *
 * Orders carry a trust rating from 1 to 100 — 100 totally trustworthy, 1 as
 * bad as it gets. Risk levels are ranges of that rating, so a lower rating always
 * means a more severe response.
 *
 * That last part is the point. Every spam order that reaches the processor
 * counts against the merchant account's decline and fraud ratios, so the three
 * most severe risk levels are defined by what they do NOT do: rejected, banned, and
 * detained never produce an outbound gateway request.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes;

class risk_levels {

    const TRUSTED  = 'trusted';
    const LOW      = 'low';
    const ELEVATED = 'elevated';
    const HIGH     = 'high';
    const REJECTED = 'rejected';
    const BANNED   = 'banned';

    /**
     * The ladder, least to most severe.
     *
     * rank            Comparable severity. Higher wins when two sources
     *                 disagree, which is how a signal floor overrides a lower
     *                 score-derived risk level.
     * action          Default action. Configurable levels store an override.
     * ai              Whether this level is sent to AI review by default.
     * contacts_gateway Historical. contacts_gateway() now derives this from the
     *                 level's ACTION, since that is what actually decides it.
     * creates_order   Whether a WooCommerce order is created at all.
     *
     * @since   1.9.0
     */
    const LADDER = [

        self::TRUSTED => [
            'rank'             => 0,
            'label'            => 'Trusted',
            'description'      => 'Known-good, with a clean order history behind it.',
            'contacts_gateway' => true,
            'creates_order'    => true,
            'action'           => actions::NONE,
            'ai'               => false,
        ],

        self::LOW => [
            'rank'             => 1,
            'label'            => 'Low',
            'description'      => 'Nothing wrong, nothing vouching for it either. Where an unknown customer starts.',
            'contacts_gateway' => true,
            'creates_order'    => true,
            'action'           => actions::FLAG,
            'ai'               => false,
        ],

        self::ELEVATED => [
            'rank'             => 2,
            'label'            => 'Elevated',
            'description'      => 'Something is off, but nothing damning. Ambiguous enough to be worth a check.',
            'contacts_gateway' => true,
            'creates_order'    => true,
            'action'           => actions::VERIFY_3DS,
            'ai'               => true,
        ],

        self::HIGH => [
            'rank'             => 3,
            'label'            => 'High',
            'description'      => 'Likely fraud. Enough against it to be worth stopping before fulfilment.',
            'contacts_gateway' => true,
            'creates_order'    => true,
            'action'           => actions::HOLD_UNPAID,
            'ai'               => true,
        ],

        self::REJECTED => [
            'rank'             => 4,
            'label'            => 'Rejected',
            'description'      => 'Blatant. Refused at validation; no order is created.',
            'contacts_gateway' => false,
            'creates_order'    => false,
            'action'           => actions::REJECT,
            'ai'               => false,
        ],

        self::BANNED => [
            'rank'             => 5,
            'label'            => 'Banned',
            'description'      => 'Known-bad. Refused and persisted to the blocklist.',
            'contacts_gateway' => false,
            'creates_order'    => false,
            'action'           => actions::REJECT,
            'ai'               => false,
        ],
    ];

    /**
     * Default trust thresholds, on the 1-100 trust rating.
     *
     * 100 is totally trustworthy, 1 is as bad as it gets. Read as "at or BELOW
     * this rating, at least this risk level" — lower trust means a more severe
     * response. Evaluated most severe first.
     *
     * Anything above the low ceiling is trusted, which is reachable only
     * with positive evidence of good history AND nothing held against the
     * order. An unknown customer starts at 100 but is capped into low:
     * absence of evidence is not trust. See risk_context::trust().
     *
     * banned is deliberately absent: it is reachable only through a signal
     * floor, never by losing trust. Banning is a statement about a known
     * identity, not about one suspicious-looking order.
     *
     * @since   1.9.0
     */
    const DEFAULT_THRESHOLDS = [
        self::REJECTED => 25.0,
        self::HIGH     => 50.0,
        self::ELEVATED => 75.0,
        self::LOW      => 94.0,
    ];

    /**
     * Levels whose action the merchant chooses.
     *
     * Rejected and Banned are absent on purpose: they are the "immediate"
     * outcomes a scoring signal can force, and their action is what defines
     * them, so there is nothing to configure.
     *
     * @since   1.9.1
     */
    const CONFIGURABLE = [ self::TRUSTED, self::LOW, self::ELEVATED, self::HIGH ];

    /**
     * Highest trust rating an order can hold without positive evidence.
     *
     * @since   1.9.0
     */
    const LOW_CEILING = 94.0;

    /**
     * The rating an order starts from before anything is held against it.
     *
     * @since   1.9.0
     */
    const BASELINE = 100.0;

    /**
     * Lowest possible rating. The scale is 1-100, not 0-100, so that "1" reads
     * as the floor rather than as missing data.
     *
     * @since   1.9.0
     */
    const FLOOR = 1.0;

    /**
     * Whether a risk level string is a real risk level.
     *
     * @since   1.9.0
     *
     * @param   string  $level
     * @return  bool
     */
    public static function exists( $level ) {

        return isset( self::LADDER[ $level ] );

    }

    /**
     * The severity rank of a risk level.
     *
     * An unknown risk level ranks as low rather than 0/trusted — a
     * misconfiguration must never read as "this order is fine".
     *
     * @since   1.9.0
     *
     * @param   string  $level
     * @return  int
     */
    public static function rank( $level ) {

        return isset( self::LADDER[ $level ] ) ? (int) self::LADDER[ $level ]['rank'] : 1;

    }

    /**
     * The more severe of two risk levels.
     *
     * @since   1.9.0
     *
     * @param   string  $a
     * @param   string  $b
     * @return  string
     */
    public static function max( $a, $b ) {

        return self::rank( $a ) >= self::rank( $b ) ? $a : $b;

    }

    /**
     * Whether an order in this risk level may reach the payment processor.
     *
     * @since   1.9.0
     *
     * @param   string  $level
     * @return  bool
     */
    public static function contacts_gateway( $level ) {

        // Fail closed. An unrecognized risk level must not be assumed safe to charge.
        if( ! isset( self::LADDER[ $level ] ) ) return false;

        // The ACTION decides this, not the level. Since 1.9.1 a level's action
        // is configurable, so High reaches the processor when it is set to take
        // payment and hold, and does not when it is set to hold before payment.
        // Reading the static ladder value here would have reported whichever
        // was true on the day the default was written.
        return actions::contacts_gateway( self::action( $level ) );

    }

    /**
     * Whether an order should be created for this risk level.
     *
     * @since   1.9.0
     *
     * @param   string  $level
     * @return  bool
     */
    public static function creates_order( $level ) {

        if( ! isset( self::LADDER[ $level ] ) ) return false;

        return (bool) self::LADDER[ $level ]['creates_order'];

    }

    /**
     * The configured score threshold for a risk level.
     *
     * @since   1.9.0
     *
     * @param   string  $level
     * @return  float|null  Null when the risk level is not score-reachable.
     */
    public static function threshold( $level ) {

        if( ! isset( self::DEFAULT_THRESHOLDS[ $level ] ) ) return null;

        $stored = get_option( 'mshield_level_' . $level . '_threshold', null );

        if( $stored === null || $stored === '' ) {
            return (float) self::DEFAULT_THRESHOLDS[ $level ];
        }

        return (float) $stored;

    }

    /**
     * Resolve a trust rating to a risk level.
     *
     * Lower trust means a more severe risk level, so this compares with <=, not >=.
     *
     * @since   1.9.0
     *
     * @param   float   $trust  Trust rating, 1-100.
     * @return  string
     */
    public static function from_trust( $trust ) {

        $trust = (float) $trust;

        // Most severe first, so the first match wins.
        foreach( [ self::REJECTED, self::HIGH, self::ELEVATED, self::LOW ] as $level ) {

            $threshold = self::threshold( $level );
            if( $threshold === null ) continue;

            if( $trust <= $threshold ) return $level;

        }

        return self::TRUSTED;

    }

    /**
     * The action configured for a risk level.
     *
     * Rejected and Banned ignore whatever is stored: refusing IS the level.
     * A stored value that is not a real action falls back to the level's
     * default rather than to "do nothing" — a typo must not disarm a level.
     *
     * @since   1.9.1
     *
     * @param   string  $level
     * @return  string
     */
    public static function action( $level ) {

        if( ! isset( self::LADDER[ $level ] ) ) return actions::FLAG;

        $default = self::LADDER[ $level ]['action'];

        if( ! \in_array( $level, self::CONFIGURABLE, true ) ) return $default;

        $stored = get_option( 'mshield_level_' . $level . '_action', null );

        if( $stored === null || ! actions::exists( $stored ) ) return $default;

        return $stored;

    }

    /**
     * Whether orders at this risk level are sent to AI review.
     *
     * @since   1.9.1
     *
     * @param   string  $level
     * @return  bool
     */
    public static function ai_review( $level ) {

        if( ! isset( self::LADDER[ $level ] ) ) return false;
        if( ! \in_array( $level, self::CONFIGURABLE, true ) ) return false;

        // Costs money and cannot run without a provider, so an unconfigured
        // install must never queue calls it cannot make.
        if( ! ai_client::is_ready() ) return false;

        $stored = get_option( 'mshield_level_' . $level . '_ai', null );

        if( $stored === null || $stored === '' ) return (bool) self::LADDER[ $level ]['ai'];

        return $stored === 'yes';

    }

    /**
     * The human-readable label of a risk level.
     *
     * @since   1.9.0
     *
     * @param   string  $level
     * @return  string
     */
    public static function label( $level ) {

        return isset( self::LADDER[ $level ] ) ? self::LADDER[ $level ]['label'] : $level;

    }

}
