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
use MightyShield\Includes\response;

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

        add_action( 'woocommerce_after_checkout_validation', [ $this, 'block_zip_state_mismatch' ], 15, 2 );
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'flag_zip_state_mismatch' ], 5, 3 );

    }

    /**
     * Block ZIP/state mismatch before order creation.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function block_zip_state_mismatch( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        $action = settings::get( 'mshield_zip_state_action' );
        if( $action !== 'block' ) return;

        $reason = self::assess(
            isset( $data['billing_country'] ) ? $data['billing_country'] : '',
            isset( $data['billing_state'] ) ? $data['billing_state'] : '',
            isset( $data['billing_postcode'] ) ? $data['billing_postcode'] : ''
        );

        if( $reason === null ) return;

        db::log_event( ip_utils::get_client_ip(), 'classic_checkout', 'blocked', $reason );
        $errors->add( 'mighty_shield_zip_state', response::with_note( __( 'Please verify your billing ZIP code and state.', 'mighty-shield' ) ) );

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
     * Flag ZIP/state mismatch after order creation.
     *
     * @since   1.0.0
     *
     * @param   int     $order_id   Order ID.
     * @param   array   $posted     Posted data.
     * @param   object  $order      WC_Order object.
     */
    public function flag_zip_state_mismatch( $order_id, $posted, $order ) {

        if( \MightyShield\Includes\exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $action = settings::get( 'mshield_zip_state_action' );
        if( $action === 'block' ) return;

        $result = self::assess( $order->get_billing_country(), $order->get_billing_state(), $order->get_billing_postcode() );

        if( $result === null ) return;

        \MightyShield\Includes\response::flag( $order, 'zip_state_mismatch', $result, false, 'classic_checkout' );

        if( $action === 'notify' ) {
            $this->send_admin_notification( $order, $result );
        }

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
            [ '006', '009', [ 'PR' ] ],
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
            [ '969', '969', [ 'GU' ] ],
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

    /**
     * Send admin notification email.
     *
     * @since   1.0.0
     *
     * @param   object  $order  WC_Order object.
     * @param   string  $reason Reason for flagging.
     */
    private function send_admin_notification( $order, $reason ) {

        $admin_email = get_option( 'admin_email' );
        $subject     = sprintf( '[MightyShield] ZIP/State mismatch on order #%d', $order->get_id() );
        $message     = sprintf(
            "A ZIP/state mismatch was detected by MightyShield.\n\nOrder: #%d\nReason: %s\nCustomer: %s (%s)\nAddress: %s, %s %s\nIP: %s\n\nReview this order: %s",
            $order->get_id(),
            $reason,
            $order->get_formatted_billing_full_name(),
            $order->get_billing_email(),
            $order->get_billing_city(),
            $order->get_billing_state(),
            $order->get_billing_postcode(),
            $order->get_customer_ip_address(),
            $order->get_edit_order_url()
        );

        wp_mail( $admin_email, $subject, $message );

    }

}
