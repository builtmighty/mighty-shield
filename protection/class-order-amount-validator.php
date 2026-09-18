<?php
/**
 * Order Amount Validator.
 *
 * Flags or blocks suspicious order amounts (micro-charges used for card testing).
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\risk_context;

class order_amount_validator {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess_checkout' ], 10, 2 );

    }

    /**
     * Score the cart total. Runs before any order exists.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object, unused — this layer does not refuse.
     */
    public function assess_checkout( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        // No order exists yet at validation time, so the cart is the only total
        // there is. The Store API reads its draft order instead. The two can
        // differ once fees are involved.
        if( ! function_exists( 'WC' ) || ! WC()->cart ) return;

        $reason = self::assess( (float) WC()->cart->get_total( 'edit' ) );
        if( $reason === null ) return;

        db::log_event( ip_utils::get_client_ip(), 'classic_checkout', 'flagged', $reason );

    }

    /**
     * Compare an order total against the minimum and record anything under it.
     *
     * The one place this check turns into a signal, called by both checkouts.
     * The Store API carried its own copy of the comparison, blocked on it, and
     * never recorded it, so a card tester probing with a one dollar order
     * scored nothing on the block checkout.
     *
     * @since   2.0.0
     *
     * @param   float   $total  Order or cart total.
     * @return  string|null Reason the amount is suspicious, or null if it is not.
     */
    public static function assess( $total ) {

        $min = (float) settings::get( 'mshield_min_order_amount' );

        // Zero switches the check off entirely.
        if( $min <= 0 ) return null;

        $total = (float) $total;
        if( $total >= $min ) return null;

        $reason = sprintf( 'Suspicious order amount: $%s (minimum: $%s)', number_format( $total, 2 ), number_format( $min, 2 ) );

        risk_context::add( 'amount_low', $reason );

        return $reason;

    }

}
