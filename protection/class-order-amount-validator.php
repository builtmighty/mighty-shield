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
use MightyShield\Includes\response;

class order_amount_validator {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Block mode: validate BEFORE order creation to prevent orphaned orders.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'block_suspicious_amount' ], 10, 2 );

        // Flag/notify mode: run AFTER order creation so we can add notes/meta.
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'flag_suspicious_amount' ], 5, 3 );

    }

    /**
     * Block suspicious amounts before order creation.
     *
     * Only runs when action mode is 'block'.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function block_suspicious_amount( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        $action = settings::get( 'mshield_suspicious_amount_action' );
        if( $action !== 'block' ) return;

        // No order exists yet at validation time, so the cart is the only
        // total there is. The flag path below, and the Store API, read the
        // order instead. The two can differ once fees are involved.
        $reason = self::assess( (float) WC()->cart->get_total( 'edit' ) );
        if( $reason === null ) return;

        db::log_event( ip_utils::get_client_ip(), 'classic_checkout', 'blocked', $reason );
        $errors->add( 'mighty_shield_amount', response::with_note( __( 'This order could not be processed. Please contact support.', 'mighty-shield' ) ) );

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

    /**
     * Flag or notify on suspicious amounts after order creation.
     *
     * Only runs when action mode is 'flag' or 'notify'.
     *
     * @since   1.0.0
     *
     * @param   int     $order_id   Order ID.
     * @param   array   $posted     Posted data.
     * @param   object  $order      WC_Order object.
     */
    public function flag_suspicious_amount( $order_id, $posted, $order ) {

        if( \MightyShield\Includes\exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $action = settings::get( 'mshield_suspicious_amount_action' );
        if( $action === 'block' ) return;

        $reason = self::assess( (float) $order->get_total() );
        if( $reason === null ) return;

        \MightyShield\Includes\response::flag( $order, 'suspicious_amount', $reason, false, 'classic_checkout' );

        if( $action === 'notify' ) {
            $this->send_admin_notification( $order, $reason );
        }

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
        $subject     = sprintf( '[MightyShield] Suspicious order #%d', $order->get_id() );
        $message     = sprintf(
            "A suspicious order has been flagged by MightyShield.\n\nOrder: #%d\nAmount: %s\nReason: %s\nCustomer: %s (%s)\nIP: %s\n\nReview this order: %s",
            $order->get_id(),
            $order->get_formatted_order_total(),
            $reason,
            $order->get_formatted_billing_full_name(),
            $order->get_billing_email(),
            $order->get_customer_ip_address(),
            $order->get_edit_order_url()
        );

        wp_mail( $admin_email, $subject, $message );

    }

}
