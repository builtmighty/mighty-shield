<?php
/**
 * Payment-instrument intelligence.
 *
 * The processor knows things about a card that the checkout form never reveals:
 * whether the billing address matched, whether the CVC matched, which country
 * issued it, whether it is prepaid, and a stable fingerprint identifying the
 * card itself. None of that was being read.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS CAN AND CANNOT DO
 *
 * These signals arrive AFTER payment, so they cannot influence the risk level of the
 * order that produced them. Two things make them worth having anyway:
 *
 * 1. A successful charge with a failed AVS or CVC check is one of the strongest
 *    stolen-card tells there is. The money is already taken, but the goods have
 *    not shipped — surfacing it before fulfilment is the whole win.
 * 2. The card fingerprint links orders that share a card but share nothing else.
 *    When one of them is later charged back, the outcome loop penalises every
 *    identity on it — email, device, address — and those ARE known before
 *    payment on the next order.
 *
 * Where these come from varies by processor and is entirely the adapters'
 * problem — Stripe supplies them on its webhook stream, the SkyVerge gateways
 * (Square, Authorize.Net, Braintree) on a transaction hook. A processor with no
 * adapter simply supplies nothing, and the checks below never run.
 *
 * Note: no processor here returns a BIN/IIN — Stripe gives last4, brand,
 * country and funding, and the SkyVerge gateways give AVS and CVC codes only.
 * Where a stable card fingerprint is available it is used as the card identity
 * instead, which is the better signal regardless: it is stable across
 * customers.
 * ---------------------------------------------------------------------------
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\db;
use MightyShield\Includes\entities;
use MightyShield\Includes\settings;

class card_signals {

    /**
     * Check results that count as a genuine mismatch.
     *
     * "unavailable" and "unchecked" are NOT failures — plenty of legitimate
     * issuers simply do not run the check, and treating silence as a mismatch
     * would flag a large slice of ordinary orders.
     *
     * @since   1.9.0
     */
    const FAILED = [ 'fail' ];

    /**
     * Construct.
     *
     * @since   1.9.0
     */
    public function __construct() {

        // Nothing hooked here any more. Each gateway adapter listens for
        // whatever its processor offers and hands the result to
        // ingest_normalised() below, so this class never has to know which
        // processor an order went through.

    }

    /**
     * Record card details supplied by a gateway adapter.
     *
     * Adapters translate their processor's own vocabulary into this shape, so
     * the judgement below is written once and applies everywhere. A processor
     * that cannot supply a field simply omits it, and an omitted field is never
     * treated as evidence.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @param   array       $data   Any of: fingerprint, brand, last4, country,
     *                              funding, avs_street, avs_zip, cvc, three_d,
     *                              risk_level, risk_score.
     */
    public static function ingest_normalised( $order, $data ) {

        if( ! $order instanceof \WC_Order || empty( $data ) ) return;

        // Recorded once. Processors redeliver webhooks, and a second pass must
        // not re-flag an order a merchant has already reviewed and cleared.
        if( $order->get_meta( '_mshield_card_read' ) === 'yes' ) return;

        $data = array_merge( [
            'fingerprint' => '', 'brand' => '', 'last4' => '', 'country' => '',
            'funding' => '', 'avs_street' => '', 'avs_zip' => '', 'cvc' => '',
            'three_d' => '', 'risk_level' => '', 'risk_score' => '',
        ], $data );

        foreach( $data as $key => $value ) {
            if( $value !== '' && $value !== null ) {
                $order->update_meta_data( '_mshield_card_' . $key, sanitize_text_field( (string) $value ) );
            }
        }

        $order->update_meta_data( '_mshield_card_read', 'yes' );

        // The card becomes an identity in its own right, so orders sharing a
        // card but nothing else are linked. Only some processors expose a
        // stable fingerprint; the rest still get the AVS and CVC judgement.
        if( ! empty( $data['fingerprint'] ) ) {
            entities::record( [ 'card_fp' => $data['fingerprint'] ], $order->get_id() );
        }

        $order->save();

        self::evaluate( $order, $data );

    }

    /**
     * Decide whether the card details warrant a human look.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @param   array       $data
     */
    private static function evaluate( $order, $data ) {

        $reasons = [];

        $zip_failed = \in_array( $data['avs_zip'], self::FAILED, true );
        $cvc_failed = \in_array( $data['cvc'], self::FAILED, true );

        if( $zip_failed ) {
            $reasons[] = __( 'the billing postcode did not match the card', 'mighty-shield' );
        }

        if( \in_array( $data['avs_street'], self::FAILED, true ) ) {
            $reasons[] = __( 'the billing street address did not match the card', 'mighty-shield' );
        }

        if( $cvc_failed ) {
            $reasons[] = __( 'the security code did not match', 'mighty-shield' );
        }

        // Card issued in a different country to where the order is going. On
        // its own this is weak — expats and travellers are ordinary — so it
        // only counts alongside something else.
        $ship_country = strtoupper( (string) ( $order->get_shipping_country() ?: $order->get_billing_country() ) );

        if( $data['country'] !== '' && $ship_country !== '' && $data['country'] !== $ship_country && ! empty( $reasons ) ) {
            $reasons[] = sprintf(
                /* translators: 1: card country, 2: destination country. */
                __( 'the card was issued in %1$s but the order ships to %2$s', 'mighty-shield' ),
                $data['country'],
                $ship_country
            );
        }

        // A prepaid card on a high-value physical order is rarely legitimate.
        if( $data['funding'] === 'prepaid' && (float) $order->get_total() >= (float) settings::get( 'mshield_ai_high_value_amount' ) ) {
            $reasons[] = __( 'a prepaid card was used for a high-value order', 'mighty-shield' );
        }

        // Stripe already scored this order with Radar. Read it rather than
        // guessing at what it would have said.
        if( $data['risk_level'] === 'highest' || $data['risk_level'] === 'elevated' ) {
            $reasons[] = sprintf(
                /* translators: %s: Stripe Radar risk level. */
                __( 'Stripe rated the payment risk as %s', 'mighty-shield' ),
                $data['risk_level']
            );
        }

        if( empty( $reasons ) ) return;

        $note = __( 'MightyShield: this payment went through, but', 'mighty-shield' ) . ' ' . implode( '; ', $reasons ) . '. '
              . __( 'Review before shipping. A successful charge that fails these checks is a common sign of a stolen card.', 'mighty-shield' );

        $order->add_order_note( $note );
        $order->update_meta_data( '_mshield_card_flagged', 'yes' );

        if( ! $order->get_meta( '_mshield_flagged' ) ) {
            $order->update_meta_data( '_mshield_flagged', 'card_signals' );
        }

        $order->save();

        db::log_event(
            $order->get_customer_ip_address(),
            'card_signals',
            'flagged',
            sprintf( 'Order #%d: %s', $order->get_id(), implode( '; ', $reasons ) ),
            '',
            (int) $order->get_id()
        );

        delete_transient( 'mshield_ai_pending_count' );

        // Both address AND security code failing is strong enough to stop
        // fulfilment rather than just annotate it. Anything weaker only flags —
        // the money is already taken, and holding every mismatched order would
        // punish a lot of legitimate customers whose bank simply declined to
        // run the check.
        $hold = $zip_failed && $cvc_failed;

        if( $hold && settings::get( 'mshield_card_hold_on_mismatch' ) === 'yes' && $order->has_status( [ 'processing', 'completed' ] ) ) {

            $order->update_status( 'on-hold', __( 'MightyShield: held before shipping. The card failed both the address and the security code checks.', 'mighty-shield' ) );

        }

    }

}
