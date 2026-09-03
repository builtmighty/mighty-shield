<?php
/**
 * Scoring profiles.
 *
 * Three presets for the whole Scoring tab, so a merchant who does not want to
 * make thirty-nine individual judgement calls does not have to make any.
 *
 * ---------------------------------------------------------------------------
 * WHY THESE ARE OVERRIDE TABLES AND NOT A MULTIPLIER — read before editing.
 *
 * A weight is a raw subtraction from a 100-point budget. No normalisation, no
 * diminishing returns: trust = 100 - sum( weight * confidence ). The risk
 * levels are absolute point ranges, and the realistic orders in the scenario
 * suite sit hard against their edges:
 *
 *   Stolen card, drop address      70 points   high       4 points of headroom
 *   Prior denial, otherwise clean  70 points   high       4 points
 *   Traveller on a VPN             40 points   elevated   9 points
 *   Gift order, high value         40 points   elevated   9 points
 *   Sloppy but real                40 points   elevated   9 points
 *
 * So the largest uniform multiplier that does not push the stolen-card order
 * into "rejected" is about 1.07, which is not a product feature. And "high"
 * never contacts the payment processor, so a 1.3x Strict would quietly stop
 * taking money from anyone on a VPN.
 *
 * The catalog also says this directly. Roughly a third of the weights are
 * deliberately low, with the reason written next to them: VPN users, people
 * using assistive technology or a keyboard alone, small businesses ordering
 * from info@, gift senders, new customers, and stores behind a CDN that strips
 * cookies. Scaling those is not "stricter", it is a decision to catch those
 * people, and it is not one a preset should make on a merchant's behalf.
 *
 * Hence: sparse tables. Cautious and Strict list only the signals they move,
 * and every signal named in NEVER_TOUCH is left exactly where the catalog put
 * it. A profile raises what is specific evidence of automation or a stolen
 * card, and nothing else.
 * ---------------------------------------------------------------------------
 *
 * @package MightyShield
 * @since   2.0.0
 */
namespace MightyShield\Includes;

class scoring_profiles {

    /**
     * The option recording which profile was last applied.
     *
     * Deliberately NOT registered to a settings group: applying a profile is an
     * action, not a field, and a registered option with no input on the page is
     * written null on every save of that group.
     *
     * @since   2.0.0
     */
    const OPTION = 'mshield_scoring_profile';

    /**
     * The profile a store is on before anyone chooses.
     *
     * @since   2.0.0
     */
    const DEFAULT_PROFILE = 'balanced';

    /**
     * Signals no profile may move, and why.
     *
     * Two kinds. The first six are floored: a floor bypasses the arithmetic
     * entirely, so changing their weight is a no-op that looks like a change.
     * The rest carry a calibration comment in the catalog explaining that they
     * are deliberately low because they misfire on a real population, or they
     * sit close enough to a risk-level edge that moving them changes what
     * happens to an order the catalog says must be held rather than refused.
     *
     * entity_trusted is absent from this list but is special in its own way.
     * See PROFILES.
     *
     * @since   2.0.0
     */
    const NEVER_TOUCH = [

        // Floored. The weight is decoration.
        'honeypot', 'device_automated', 'captcha_failed',
        'ip_temp_blocked', 'ip_blocklisted', 'entity_chargeback',

        // Deliberately low, per the catalog's own comments.
        'email_role',           // small businesses really do order from info@
        'email_name_mismatch',  // and appears in two scenarios near an edge
        'address_velocity',     // apartment buildings, offices, dorms, families
        'ip_geo_mismatch',      // gifts, travel, mobile carriers, corporate egress
        'ip_proxy',             // VPNs are mainstream, and it double-counts the timezone
        'device_tz_mismatch',   // the other half of that double-count
        'interaction_none',     // keyboard-only and assistive-technology shoppers
        'cookies_none',         // a cookie-stripping CDN would misfire store-wide
        'account_new',          // everyone is new once
        'high_value',           // not suspicious, and it is in three scenarios
        'device_missing',       // pairs with address_fake in the sloppy-but-real case

        // Already four points from refusing an order the catalog says to hold.
        'entity_denied',

    ];

    /**
     * The three profiles.
     *
     * Balanced is empty on purpose: it is the catalog, and applying it deletes
     * the stored overrides rather than writing today's numbers back. That way a
     * future retune of the catalog reaches every Balanced store instead of
     * being frozen out by values written once.
     *
     * entity_trusted may shrink but must never reach zero. The "trusted" risk
     * level exists only because some signal contributed a negative number; the
     * check is on the sign, not the size. Take it to 0 and the top of the scale
     * disappears.
     *
     * @since   2.0.0
     */
    const PROFILES = [

        'balanced' => [
            'label'   => 'Balanced',
            'blurb'   => 'What most stores should use. Catches the obvious attacks and leaves ordinary customers alone.',
            'weights' => [],
            'options' => [],
        ],

        'cautious' => [
            'label'   => 'Cautious',
            'blurb'   => 'For a store seeing more fraud than it used to. Everything specific costs more, and device information starts being collected.',
            'weights' => [
                'email_disposable'   => 52.0,
                'email_no_mx'        => 47.0,
                'address_fake'       => 45.0,
                'zip_state_mismatch' => 40.0,
                'address_unverified' => 35.0,
                'ip_datacenter'      => 47.0,
                'timing_fast'        => 52.0,
                'timing_missing'     => 25.0,
                'device_headless'    => 62.0,
                'input_scripted'     => 68.0,
                'device_velocity'    => 57.0,
                'amount_low'         => 41.0,
                'rate_limited'       => 68.0,
                'velocity_emails'    => 62.0,
                'velocity_orders'    => 57.0,
                'failed_payments'    => 62.0,
                'entity_linked_bad'  => 51.0,
                'entity_trusted'     => -32.0,
            ],
            'options' => [
                'mshield_fingerprint_enabled' => 'yes',
            ],
        ],

        'strict' => [
            'label'   => 'Strict',
            'blurb'   => 'For a store under attack, or one selling things worth stealing. Expect to review more orders by hand.',
            'weights' => [
                'email_disposable'   => 60.0,
                'email_no_mx'        => 55.0,
                'address_fake'       => 50.0,
                'zip_state_mismatch' => 45.0,
                'address_unverified' => 40.0,
                'ip_datacenter'      => 55.0,
                'timing_fast'        => 60.0,
                'timing_missing'     => 30.0,
                'device_headless'    => 70.0,
                'input_scripted'     => 75.0,
                'device_velocity'    => 65.0,
                'amount_low'         => 48.0,
                'rate_limited'       => 75.0,
                'velocity_emails'    => 70.0,
                'velocity_orders'    => 65.0,
                'failed_payments'    => 70.0,
                'entity_linked_bad'  => 58.0,
                'entity_trusted'     => -25.0,
            ],
            'options' => [
                'mshield_fingerprint_enabled' => 'yes',
            ],
        ],

    ];

    /**
     * Whether a name is one of the three.
     *
     * @since   2.0.0
     *
     * @param   string  $profile
     * @return  bool
     */
    public static function exists( $profile ) {

        return isset( self::PROFILES[ (string) $profile ] );

    }

    /**
     * Every option a profile is allowed to write.
     *
     * The single source of truth for what a profile governs, used by apply(),
     * by current(), and by the test that asserts nothing else moved.
     *
     * @since   2.0.0
     *
     * @return  string[]
     */
    public static function governs() {

        $options = [];

        foreach( array_keys( signals::CATALOG ) as $key ) {
            $options[] = 'mshield_sig_' . $key . '_weight';
            $options[] = 'mshield_sig_' . $key . '_enabled';
        }

        foreach( self::PROFILES as $profile ) {
            foreach( array_keys( $profile['options'] ) as $option ) {
                if( ! \in_array( $option, $options, true ) ) $options[] = $option;
            }
        }

        return $options;

    }

    /**
     * What one profile expects every governed option to be.
     *
     * null means "no stored value" — the catalog default, reached by deleting
     * the option rather than writing the number. Comparing against null is what
     * lets a fresh store with no options at all read as Balanced.
     *
     * @since   2.0.0
     *
     * @param   string  $profile
     * @return  array   option => expected value, or null for "unset"
     */
    public static function expected( $profile ) {

        if( ! self::exists( $profile ) ) return [];

        $spec     = self::PROFILES[ $profile ];
        $expected = [];

        foreach( array_keys( signals::CATALOG ) as $key ) {

            $expected[ 'mshield_sig_' . $key . '_weight' ] =
                isset( $spec['weights'][ $key ] ) ? (float) $spec['weights'][ $key ] : null;

            // Every profile runs every signal. A merchant who switches one off
            // is doing something a preset has no opinion about, which is
            // exactly why that makes them Custom.
            $expected[ 'mshield_sig_' . $key . '_enabled' ] = null;

        }

        foreach( self::PROFILES as $other ) {
            foreach( array_keys( $other['options'] ) as $option ) {
                $expected[ $option ] = isset( $spec['options'][ $option ] ) ? $spec['options'][ $option ] : null;
            }
        }

        return $expected;

    }

    /**
     * The profile the store is actually on.
     *
     * Derived, never stored. The recorded option says which profile was last
     * applied; this compares that profile's expectations against what is really
     * in the database and returns 'custom' the moment anything differs.
     *
     * Deriving it rather than storing a flag is what makes "it goes to Custom
     * when you change something" true without a single save hook. It also means
     * a merchant who tunes a row and then puts it back returns to their profile,
     * which a stored flag would get wrong.
     *
     * @since   2.0.0
     *
     * @return  string  A profile key, or 'custom'.
     */
    public static function current() {

        $claimed = get_option( self::OPTION, self::DEFAULT_PROFILE );

        if( ! self::exists( $claimed ) ) $claimed = self::DEFAULT_PROFILE;

        return self::matches( $claimed ) ? $claimed : 'custom';

    }

    /**
     * Whether the stored values are exactly what a profile expects.
     *
     * @since   2.0.0
     *
     * @param   string  $profile
     * @return  bool
     */
    public static function matches( $profile ) {

        return self::differences( $profile ) === [];

    }

    /**
     * Which governed options differ from what a profile expects.
     *
     * @since   2.0.0
     *
     * @param   string  $profile
     * @return  string[]    Option names.
     */
    public static function differences( $profile ) {

        if( ! self::exists( $profile ) ) return [];

        $differs = [];

        foreach( self::expected( $profile ) as $option => $want ) {

            $have = get_option( $option, null );

            // An unset option and an empty one both mean "use the default",
            // which is what a null expectation is asking for. signals::weight()
            // treats them identically, so this has to as well.
            if( $want === null ) {
                if( $have !== null && $have !== '' ) $differs[] = $option;
                continue;
            }

            if( $have === null || $have === '' ) { $differs[] = $option; continue; }

            // Weights are floats and arrive from the database as strings.
            if( is_float( $want ) ) {
                if( abs( (float) $have - $want ) > 0.001 ) $differs[] = $option;
                continue;
            }

            if( (string) $have !== (string) $want ) $differs[] = $option;

        }

        return $differs;

    }

    /**
     * How many rows the merchant has tuned away from their own profile.
     *
     * Shown in the confirmation before a switch, because switching overwrites
     * them. Note what this deliberately is NOT: the number of options that
     * differ from the profile being switched TO. Balanced and Strict disagree
     * about eighteen weights by design, and warning that a switch would
     * "replace 18 trust costs you have changed" when the merchant has changed
     * nothing is both false and alarming.
     *
     * Zero unless the store is Custom, which is the point.
     *
     * @since   2.0.0
     *
     * @return  int
     */
    public static function hand_tuned_count() {

        $claimed = get_option( self::OPTION, self::DEFAULT_PROFILE );

        if( ! self::exists( $claimed ) ) $claimed = self::DEFAULT_PROFILE;

        return count( self::differences( $claimed ) );

    }

    /**
     * Apply a profile.
     *
     * A null expectation is applied by DELETING the option, not by writing the
     * catalog number. signals::weight() falls back to the catalog when the
     * option is absent, so deleting keeps a Balanced store tracking the catalog
     * rather than pinned to whatever it happened to say on the day.
     *
     * @since   2.0.0
     *
     * @param   string  $profile
     * @return  bool    False when the name is not a profile.
     */
    public static function apply( $profile ) {

        if( ! self::exists( $profile ) ) return false;

        foreach( self::expected( $profile ) as $option => $want ) {

            if( $want === null ) {
                delete_option( $option );
                continue;
            }

            // Clamped here as well as in the settings sanitiser, because this
            // writes straight past it.
            if( is_float( $want ) ) $want = max( -100.0, min( 100.0, $want ) );

            update_option( $option, $want );

        }

        update_option( self::OPTION, $profile );

        return true;

    }

    /**
     * Translated labels and blurbs, including the derived 'custom' state.
     *
     * Written out rather than run through __() with a variable, which the
     * string extractor cannot see and so would ship untranslatable.
     *
     * @since   2.0.0
     *
     * @return  array   key => [ 'label', 'blurb' ]
     */
    public static function copy() {

        return [
            'balanced' => [
                'label' => __( 'Balanced', 'mighty-shield' ),
                'blurb' => __( 'What most stores should use. Catches the obvious attacks and leaves ordinary customers alone.', 'mighty-shield' ),
            ],
            'cautious' => [
                'label' => __( 'Cautious', 'mighty-shield' ),
                'blurb' => __( 'For a store seeing more fraud than it used to. Everything specific costs more, and device information starts being collected.', 'mighty-shield' ),
            ],
            'strict' => [
                'label' => __( 'Strict', 'mighty-shield' ),
                'blurb' => __( 'For a store under attack, or one selling things worth stealing. Expect to review more orders by hand.', 'mighty-shield' ),
            ],
            'custom' => [
                'label' => __( 'Custom', 'mighty-shield' ),
                'blurb' => __( 'Your own trust costs. This appears on its own as soon as you change a row below, and stays until every row matches one of the three again.', 'mighty-shield' ),
            ],
        ];

    }

    /**
     * The label for a profile key, including 'custom'.
     *
     * @since   2.0.0
     *
     * @param   string  $profile
     * @return  string
     */
    public static function label( $profile ) {

        $copy = self::copy();

        return isset( $copy[ $profile ] ) ? $copy[ $profile ]['label'] : (string) $profile;

    }

}
