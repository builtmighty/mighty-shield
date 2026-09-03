<?php
/**
 * SkyVerge framework adapter — Square, Authorize.Net, Braintree.
 *
 * These three ship the same payment framework, so one adapter covers all of
 * them. That is most of the non-Stripe estate in one place.
 *
 * The framework exposes AVS and CSC results on its response object and fires
 * `wc_payment_gateway_{id}_add_transaction_data` with the order AND that
 * response — the only hook in the framework that carries both. The gateways
 * themselves only ever put those results into an order note, and only when
 * their own fraud filter already flagged the transaction, so reading them here
 * is the difference between having the signal and not.
 *
 * No 3-D Secure. The framework has no per-order way to request it: Square and
 * Braintree decide it at tokenisation time in the browser, and Authorize.Net
 * has no equivalent at all. Claiming otherwise would be worse than not offering
 * it, so this adapter reports the capability honestly and the challenged risk level
 * simply does less on these gateways.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes\Gateways;

use MightyShield\Protection\card_signals;

class adapter_skyverge implements gateway_adapter {

    /**
     * @since 1.9.0
     */
    public static function handles() {

        return [
            'square_credit_card',
            'authorize_net_cim_credit_card',
            'braintree_credit_card',
            'braintree_paypal',
        ];

    }

    /**
     * @since 1.9.0
     */
    public static function supports( $capability, $gateway ) {

        if( ! \in_array( $gateway, self::handles(), true ) ) return false;

        // Card signals yes; 3-D Secure no — see the class note.
        return $capability === 'card_signals';

    }

    /**
     * @since 1.9.0
     */
    public static function request_3ds( $order ) {

        return false;

    }

    /**
     * @since 1.9.0
     */
    public static function listen() {

        foreach( self::handles() as $gateway ) {
            add_action( 'wc_payment_gateway_' . $gateway . '_add_transaction_data', [ __CLASS__, 'on_transaction' ], 10, 3 );
        }

    }

    /**
     * Read AVS and CSC off a completed transaction.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @param   mixed       $response   Framework response object, may be null.
     * @param   mixed       $gateway    Gateway instance.
     */
    public static function on_transaction( $order, $response = null, $gateway = null ) {

        if( ! $order instanceof \WC_Order ) return;
        if( ! is_object( $response ) ) return;

        $avs = method_exists( $response, 'get_avs_result' ) ? (string) $response->get_avs_result() : '';
        $csc = method_exists( $response, 'get_csc_result' ) ? (string) $response->get_csc_result() : '';

        if( $avs === '' && $csc === '' ) return;

        card_signals::ingest_normalised( $order, [
            'avs_zip'    => self::avs_to_check( $avs ),
            'avs_street' => self::avs_to_street( $avs ),
            'cvc'        => self::csc_to_check( $csc ),
            'raw_avs'    => $avs,
            'raw_csc'    => $csc,
        ] );

    }

    /**
     * Map an AVS code to a postcode verdict.
     *
     * These are the standard single-letter card-network codes, shared across
     * processors. Only codes that definitively say "the postcode did not match"
     * count as a failure — anything meaning unavailable, unsupported or not
     * checked stays unknown, because a bank declining to run the check says
     * nothing about the shopper.
     *
     * @since   1.9.0
     *
     * @param   string  $code
     * @return  string  pass | fail | unavailable
     */
    private static function avs_to_check( $code ) {

        $code = strtoupper( trim( $code ) );
        if( $code === '' ) return 'unavailable';

        // Y/X/D/M: address and postcode both matched. Z/W/P: postcode matched.
        if( \in_array( $code[0], [ 'Y', 'X', 'D', 'M', 'Z', 'W', 'P' ], true ) ) return 'pass';

        // A/B: address matched, postcode did NOT. N: neither matched.
        if( \in_array( $code[0], [ 'A', 'B', 'N', 'C' ], true ) ) return 'fail';

        return 'unavailable';

    }

    /**
     * Map an AVS code to a street verdict.
     *
     * @since   1.9.0
     *
     * @param   string  $code
     * @return  string  pass | fail | unavailable
     */
    private static function avs_to_street( $code ) {

        $code = strtoupper( trim( $code ) );
        if( $code === '' ) return 'unavailable';

        // A/B/Y/X/D/M: street matched.
        if( \in_array( $code[0], [ 'A', 'B', 'Y', 'X', 'D', 'M' ], true ) ) return 'pass';

        // Z/W/P: postcode matched but street did not. N/C: neither.
        if( \in_array( $code[0], [ 'Z', 'W', 'P', 'N', 'C' ], true ) ) return 'fail';

        return 'unavailable';

    }

    /**
     * Map a CSC/CVV code to a verdict.
     *
     * @since   1.9.0
     *
     * @param   string  $code
     * @return  string  pass | fail | unavailable
     */
    private static function csc_to_check( $code ) {

        $code = strtoupper( trim( $code ) );
        if( $code === '' ) return 'unavailable';

        if( $code[0] === 'M' ) return 'pass';   // Matched.
        if( $code[0] === 'N' ) return 'fail';   // Did not match.

        // P (not processed), S (not present), U (issuer unavailable) — all
        // mean nobody checked, which is not evidence either way.
        return 'unavailable';

    }

}
