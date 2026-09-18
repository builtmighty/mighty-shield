<?php
/**
 * ZIP/State Mismatch Validator.
 *
 * Detects US orders where the billing ZIP code prefix does not match the billing state.
 * Pure PHP, no external API. Also serves as Smarty API fallback.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\risk_context;

class zip_state_validator {

    /**
     * ZIP prefix to state mapping.
     *
     * Maps 3-digit ZIP prefixes to US state/territory abbreviations.
     *
     * @since   1.0.0
     */
    private static $zip_state_map = null;

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        if( settings::get( 'mshield_zip_state_enabled' ) !== 'yes' ) return;

        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess_checkout' ], 15, 2 );

    }

    /**
     * Score the ZIP against the state. Runs before any order exists.
     *
     * This check used to refuse on its own, and shipped that way. A mismatched
     * postcode is a typo far more often than it is fraud, so it is worth 35
     * trust and nothing else -- enough to put an otherwise ordinary order into
     * Elevated, not enough to turn anyone away by itself. A merchant who wants
     * it to refuse raises its weight on the Scoring tab.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object, unused — this layer does not refuse.
     */
    public function assess_checkout( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        $reason = self::assess(
            isset( $data['billing_country'] ) ? $data['billing_country'] : '',
            isset( $data['billing_state'] ) ? $data['billing_state'] : '',
            isset( $data['billing_postcode'] ) ? $data['billing_postcode'] : ''
        );

        if( $reason === null ) return;

        db::log_event( ip_utils::get_client_ip(), 'classic_checkout', 'flagged', $reason );

    }

    /**
     * Check the ZIP against the state and record a mismatch.
     *
     * The one place this check turns into a signal, called by both checkouts.
     * The Store API called verify_zip_state() and blocked on the answer without
     * ever recording it, so a mismatch cost an order nothing on the block
     * checkout unless the setting was turned all the way up to block.
     *
     * verify_zip_state() is deliberately tri-state: true is a match, a string
     * is a mismatch, and null means the prefix is not in the map and nothing
     * can be said. Only a string is evidence, which is why the test below is
     * written out rather than collapsed to a boolean.
     *
     * @since   2.0.0
     *
     * @param   string  $country    Billing country code.
     * @param   string  $state      Billing state.
     * @param   string  $zipcode    Billing postcode.
     * @return  string|null Mismatch reason, or null when there is nothing to report.
     */
    public static function assess( $country, $state, $zipcode ) {

        // The map is US-only, so there is nothing to check anywhere else.
        if( $country !== 'US' ) return null;

        $result = self::verify_zip_state( trim( (string) $state ), trim( (string) $zipcode ) );

        if( $result === true || $result === null ) return null;

        risk_context::add( 'zip_state_mismatch', $result );

        return $result;

    }

    /**
     * Verify ZIP/state match.
     *
     * Public static so Smarty verifier can call as fallback.
     *
     * @since   1.0.0
     *
     * @param   string  $state      Two-letter state abbreviation.
     * @param   string  $zipcode    ZIP code (5 or 9 digit).
     * @return  true|string|null    True if valid, error string if mismatch, null if unable to verify.
     */
    public static function verify_zip_state( $state, $zipcode ) {

        if( empty( $state ) || empty( $zipcode ) ) return null;

        // Extract first 3 digits.
        $zip_clean = preg_replace( '/[^0-9]/', '', $zipcode );
        if( strlen( $zip_clean ) < 3 ) return null;

        $prefix = substr( $zip_clean, 0, 3 );
        $map    = self::get_zip_state_map();

        if( ! isset( $map[ $prefix ] ) ) return null;

        $expected_states = $map[ $prefix ];
        $state_upper     = strtoupper( trim( $state ) );

        if( ! in_array( $state_upper, $expected_states, true ) ) {
            return sprintf(
                'ZIP/State mismatch: ZIP %s belongs to %s, not %s',
                $zipcode,
                implode( '/', $expected_states ),
                $state_upper
            );
        }

        return true;

    }

    /**
     * Get the ZIP prefix to state mapping.
     *
     * @since   1.0.0
     *
     * @return  array
     */
    private static function get_zip_state_map() {

        if( self::$zip_state_map !== null ) return self::$zip_state_map;

        // Build mapping: 3-digit prefix => array of valid state abbreviations.
        $ranges = [
            [ '005', '005', [ 'NY' ] ],
            // Puerto Rico is 006-007 and 009. The US Virgin Islands sit inside
            // that range at 008 -- lumping them in as PR meant a VI customer
            // entering their own territory was told their ZIP "belongs to PR",
            // with no way through on a check that ships set to refuse.
            [ '006', '007', [ 'PR' ] ],
            [ '008', '008', [ 'VI' ] ],
            [ '009', '009', [ 'PR' ] ],
            [ '010', '027', [ 'MA' ] ],
            [ '028', '029', [ 'RI' ] ],
            [ '030', '038', [ 'NH' ] ],
            [ '039', '049', [ 'ME' ] ],
            [ '050', '059', [ 'VT' ] ],
            [ '060', '069', [ 'CT' ] ],
            [ '070', '089', [ 'NJ' ] ],
            [ '090', '099', [ 'AE' ] ],  // Military (Europe).
            [ '100', '149', [ 'NY' ] ],
            [ '150', '196', [ 'PA' ] ],
            [ '197', '199', [ 'DE' ] ],
            [ '200', '205', [ 'DC', 'VA' ] ],
            [ '206', '219', [ 'MD' ] ],
            [ '220', '246', [ 'VA' ] ],
            [ '247', '268', [ 'WV' ] ],
            [ '270', '289', [ 'NC' ] ],
            [ '290', '299', [ 'SC' ] ],
            [ '300', '319', [ 'GA' ] ],
            [ '320', '339', [ 'FL' ] ],
            [ '340', '340', [ 'AA' ] ],  // Military (Americas).
            [ '350', '369', [ 'AL' ] ],
            [ '370', '385', [ 'TN' ] ],
            [ '386', '397', [ 'MS' ] ],
            [ '400', '427', [ 'KY' ] ],
            [ '430', '459', [ 'OH' ] ],
            [ '460', '479', [ 'IN' ] ],
            [ '480', '499', [ 'MI' ] ],
            [ '500', '528', [ 'IA' ] ],
            [ '530', '549', [ 'WI' ] ],
            [ '550', '567', [ 'MN' ] ],
            [ '570', '577', [ 'SD' ] ],
            [ '580', '588', [ 'ND' ] ],
            [ '590', '599', [ 'MT' ] ],
            [ '600', '629', [ 'IL' ] ],
            [ '630', '658', [ 'MO' ] ],
            [ '660', '679', [ 'KS' ] ],
            [ '680', '693', [ 'NE' ] ],
            [ '700', '714', [ 'LA' ] ],
            [ '716', '729', [ 'AR' ] ],
            [ '730', '749', [ 'OK' ] ],
            [ '750', '799', [ 'TX' ] ],
            [ '800', '816', [ 'CO' ] ],
            [ '820', '831', [ 'WY' ] ],
            [ '832', '838', [ 'ID' ] ],
            [ '840', '847', [ 'UT' ] ],
            [ '850', '865', [ 'AZ' ] ],
            [ '870', '884', [ 'NM' ] ],
            [ '889', '898', [ 'NV' ] ],
            [ '900', '908', [ 'CA' ] ],
            [ '910', '928', [ 'CA' ] ],
            [ '930', '961', [ 'CA' ] ],
            [ '967', '968', [ 'HI' ] ],
            // 969 is not just Guam. The Northern Marianas, Micronesia, the
            // Marshall Islands and Palau all live in it, and every one of them
            // was refused.
            [ '969', '969', [ 'GU', 'MP', 'FM', 'MH', 'PW' ] ],
            [ '970', '979', [ 'OR' ] ],
            [ '980', '994', [ 'WA' ] ],
            [ '995', '999', [ 'AK' ] ],
        ];

        self::$zip_state_map = [];

        foreach( $ranges as $range ) {
            $start  = (int) $range[0];
            $end    = (int) $range[1];
            $states = $range[2];

            for( $i = $start; $i <= $end; $i++ ) {
                $key = str_pad( (string) $i, 3, '0', STR_PAD_LEFT );
                self::$zip_state_map[ $key ] = $states;
            }
        }

        return self::$zip_state_map;

    }

}
