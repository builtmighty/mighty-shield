<?php
/**
 * AI Reviewer.
 *
 * Runs last, after every other check, on the order-processed hook — which
 * WooCommerce fires BEFORE the gateway is charged. That ordering is what makes
 * authorize-only possible: by the time payment runs we already know whether to
 * reserve the funds or settle them.
 *
 * Do NOT set the order On-hold from here. woocommerce_valid_order_statuses_for_payment
 * is [pending, failed], so an On-hold order returns needs_payment() === false and
 * WooCommerce skips payment entirely — no capture AND no authorization. Force
 * authorize-only on the gateway instead and let the order land On-hold after.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\exempt;
use MightyShield\Includes\ai_detection;
use MightyShield\Includes\ai_client;
use MightyShield\Includes\ai_capture;

class ai_reviewer {

    /**
     * Orders already reviewed this request, so the classic and Store API hooks
     * cannot double-review the same order.
     *
     * @since   1.9.0
     */
    private $reviewed = [];

    /**
     * Construct.
     *
     * @since   1.9.0
     */
    public function __construct() {

        if( settings::get( 'mshield_ai_enabled' ) !== 'yes' ) return;

        // Priority 20/30 puts this after every existing layer on both paths.
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'review_classic' ], 20, 3 );
        add_action( 'woocommerce_store_api_checkout_order_processed', [ $this, 'review_store_api' ], 30, 1 );

        if( is_admin() ) {
            add_action( 'admin_notices', [ '\MightyShield\Includes\ai_client', 'render_degraded_notice' ] );
        }

    }

    /**
     * Classic checkout entry point.
     *
     * @since   1.9.0
     *
     * @param   int         $order_id
     * @param   array       $posted
     * @param   \WC_Order   $order
     */
    public function review_classic( $order_id, $posted, $order ) {

        $this->review( $order );

    }

    /**
     * Block (Store API) checkout entry point.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     */
    public function review_store_api( $order ) {

        $this->review( $order );

    }

    /**
     * Score the order, escalate to the AI, and act on the verdict.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     */
    private function review( $order ) {

        if( ! is_object( $order ) || ! method_exists( $order, 'get_id' ) ) return;

        $order_id = $order->get_id();
        if( isset( $this->reviewed[ $order_id ] ) ) return;
        $this->reviewed[ $order_id ] = true;

        if( exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        // 1. Score the suspicious signals.
        $result  = ai_detection::score_order( $order );
        $score   = $result['score'];
        $signals = $result['signals'];

        // 2. Decide whether this order is worth an AI call.
        if( settings::get( 'mshield_ai_method' ) !== 'all' ) {
            if( $score < ai_detection::threshold() ) return;
        }

        // 3. Ask the model for a rating.
        $rating = ai_client::review( $this->build_prompt( $order ) );

        // Fail open. A provider outage must never hold a legitimate order —
        // ai_client has already logged the degradation and alerted the admin.
        if( is_wp_error( $rating ) ) return;

        // 4. Record the verdict on the order regardless of outcome.
        $order->update_meta_data( '_mshield_ai_rating', $rating );
        $order->update_meta_data( '_mshield_ai_score', $score );
        $order->update_meta_data( '_mshield_ai_signals', $signals );

        $threshold = (int) settings::get( 'mshield_ai_rating_threshold' );

        if( $rating > $threshold ) {
            $order->save();
            return;
        }

        // 5. Suspected fraud — reserve the funds without settling them.
        $this->hold( $order, $rating, $score, $signals );

    }

    /**
     * Force authorize-only and mark the order for review.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @param   int         $rating
     * @param   float       $score
     * @param   array       $signals
     */
    private function hold( $order, $rating, $score, $signals ) {

        // Only attempt authorize-only when the store asked for it. When it did
        // but this order's gateway cannot, fall back to flagging and say so —
        // a merchant must never believe funds were merely reserved when they
        // were actually taken.
        $auth_only = false;

        if( settings::get( 'mshield_ai_verdict_action' ) === 'authorize' ) {
            $auth_only = ai_capture::force_auth_only( $order );
        }

        $reason = sprintf( 'AI fraud review rated this order %d/10', $rating );

        $note = $reason . ' (suspicion score ' . $score . '/' . ai_detection::max_score() . ').';
        if( ! empty( $signals ) ) {
            $note .= ' Signals: ' . implode( '; ', $signals ) . '.';
        }
        if( $auth_only ) {
            $note .= ' The charge has been authorized but NOT captured — approve to capture, or deny to release it.';
        } elseif( settings::get( 'mshield_ai_verdict_action' ) === 'authorize' ) {
            $note .= ' This gateway cannot authorize without capturing, so the payment WAS taken in full — review and refund if fraudulent.';
        } else {
            $note .= ' The order is held for review. The payment was taken in full — review and refund if fraudulent.';
        }

        $order->add_order_note( 'MightyShield: ' . $note );

        // Distinct from _mshield_flagged: this layer runs last, and reusing the
        // shared key would silently overwrite whichever earlier layer flagged
        // the order.
        $order->update_meta_data( '_mshield_ai_flagged', 'ai_review' );
        $order->update_meta_data( '_mshield_ai_authorized_only', $auth_only ? 'yes' : 'no' );

        if( ! $order->get_meta( '_mshield_flagged' ) ) {
            $order->update_meta_data( '_mshield_flagged', 'ai_review' );
        }

        $order->save();

        db::log_event( ip_utils::get_client_ip(), 'ai_review', 'flagged', $reason );

        // The gateway sets On-hold itself when it authorizes. Only step in when
        // it did not, and never before payment.
        if( ! $auth_only ) {
            add_action( 'woocommerce_payment_complete', [ $this, 'hold_after_payment' ], 999, 1 );
        }

        if( settings::get( 'mshield_ai_notify_admin' ) === 'yes' ) {
            $this->send_admin_notification( $order, $rating, $score, $signals, $auth_only );
        }

    }

    /**
     * Move a flagged order to On-hold once payment has actually been taken.
     *
     * Only used for gateways that cannot authorize without capturing.
     *
     * @since   1.9.0
     *
     * @param   int     $order_id
     */
    public function hold_after_payment( $order_id ) {

        $order = wc_get_order( $order_id );
        if( ! $order ) return;

        if( $order->get_meta( '_mshield_ai_flagged' ) !== 'ai_review' ) return;
        if( $order->get_status() === 'on-hold' ) return;

        $order->update_status( 'on-hold', __( 'MightyShield: held for AI fraud review.', 'mighty-shield' ) );

    }

    /**
     * Build the fraud-review prompt.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  string
     */
    private function build_prompt( $order ) {

        $products = [];
        foreach( $order->get_items() as $item ) {
            $products[] = $item->get_name();
        }

        $payment = $order->get_payment_method_title();
        if( empty( $payment ) ) $payment = $order->get_payment_method();

        return sprintf(
            "You are an e-commerce fraud detection expert. Rate this order data from 1-10, with 1 being fraudulent and 10 being squeaky clean. Give me only an x/10 rating.\n\n" .
            "Billing: %s\n" .
            "Shipping: %s\n" .
            "Email Address: %s\n" .
            "Phone: %s\n" .
            "IP: %s\n" .
            "Customer: %s\n" .
            "Order Value: %s\n" .
            "Product(s): %s\n" .
            "Payment: %s",
            $this->format_address( $order, 'billing' ),
            $this->format_address( $order, 'shipping' ),
            $order->get_billing_email(),
            $order->get_billing_phone(),
            $order->get_customer_ip_address(),
            $order->get_user_id() ? 'Registered customer' : 'Guest',
            html_entity_decode( wp_strip_all_tags( wc_price( $order->get_total(), [ 'currency' => $order->get_currency() ] ) ), ENT_QUOTES ),
            implode( ', ', $products ),
            $payment
        );

    }

    /**
     * Format one address block as "Name, Street, City, ST 12345".
     *
     * Shipping falls back to billing so virtual orders still produce a usable
     * line rather than a row of commas.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @param   string      $type   'billing' or 'shipping'.
     * @return  string
     */
    private function format_address( $order, $type ) {

        if( $type === 'billing' ) {
            $parts = [
                trim( $order->get_billing_first_name() . ' ' . $order->get_billing_last_name() ),
                $order->get_billing_address_1(),
                $order->get_billing_city(),
                trim( $order->get_billing_state() . ' ' . $order->get_billing_postcode() ),
            ];
        } else {
            $parts = [
                trim( ai_detection::shipping_or_billing( $order, 'first_name' ) . ' ' . ai_detection::shipping_or_billing( $order, 'last_name' ) ),
                ai_detection::shipping_or_billing( $order, 'address_1' ),
                ai_detection::shipping_or_billing( $order, 'city' ),
                trim( ai_detection::shipping_or_billing( $order, 'state' ) . ' ' . ai_detection::shipping_or_billing( $order, 'postcode' ) ),
            ];
        }

        return implode( ', ', array_filter( array_map( 'trim', $parts ) ) );

    }

    /**
     * Email the store admin about a held order.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @param   int         $rating
     * @param   float       $score
     * @param   array       $signals
     * @param   bool        $auth_only
     */
    private function send_admin_notification( $order, $rating, $score, $signals, $auth_only ) {

        $subject = sprintf( '[MightyShield] AI flagged order #%d (%d/10)', $order->get_id(), $rating );

        $message = sprintf(
            "MightyShield's AI fraud review rated an order as likely fraudulent.\n\n" .
            "Order: #%d\n" .
            "AI rating: %d/10 (holding at or below %d)\n" .
            "Suspicion score: %s/%s\n" .
            "Signals: %s\n" .
            "Customer: %s (%s)\n" .
            "IP: %s\n" .
            "Payment: %s\n\n" .
            "%s\n\n" .
            "Review this order: %s",
            $order->get_id(),
            $rating,
            (int) settings::get( 'mshield_ai_rating_threshold' ),
            $score,
            ai_detection::max_score(),
            empty( $signals ) ? 'none' : implode( '; ', $signals ),
            $order->get_formatted_billing_full_name(),
            $order->get_billing_email(),
            $order->get_customer_ip_address(),
            $order->get_payment_method_title(),
            $auth_only
                ? "The charge was AUTHORIZED but NOT captured. The funds are reserved, not taken. Capture it to complete the sale, or let the authorization expire (about 7 days on most gateways) to release it. An authorization you never act on is a lost sale."
                : "This gateway cannot authorize without capturing, so the payment WAS taken in full. Refund the order if it turns out to be fraudulent.",
            $order->get_edit_order_url()
        );

        wp_mail( settings::notification_recipients(), $subject, $message );

    }

}
