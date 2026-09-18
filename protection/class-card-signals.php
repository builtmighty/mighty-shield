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
 * These signals arrive AFTER payment. The charge has happened, so nothing here
 * can prevent one — but the goods have not shipped, and stopping the parcel is
 * most of the win. A successful charge with a failed AVS or CVC check is one of
 * the strongest stolen-card tells there is.
 *
 * What it can no longer do is decide. Until 2.2.0 this class formed its own
 * verdict from its own evidence and put the order on hold itself, governed by a
 * single checkbox on the Blocking tab — a second fraud engine with one lever,
 * whose weighting the merchant could not see or argue with. Now every finding
 * is a signal with a weight on the Scoring tab, and decide() replays the
 * checkout verdict, adds them to it, and hands the result to the same ladder
 * every other layer answers to.
 *
 * The card fingerprint also links orders that share a card but share nothing
 * else. When one of them is later charged back, the outcome loop penalises
 * every identity on it, and those ARE known before payment on the next order.
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
use MightyShield\Includes\response;
use MightyShield\Includes\risk_context;
use MightyShield\Includes\risk_levels;
use MightyShield\Includes\actions;

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

        self::decide( $order, $data );

    }

    /**
     * Read back what the processor said about an order's card.
     *
     * The mirror of the meta writes in ingest_normalised(). Returns the same
     * shape emit() takes, so a re-rate later can replay the card without the
     * processor being asked again.
     *
     * @since   2.2.0
     *
     * @param   \WC_Order   $order
     * @return  array   Empty when no processor has answered for this order.
     */
    public static function stored( $order ) {

        if( ! $order instanceof \WC_Order ) return [];
        if( $order->get_meta( '_mshield_card_read' ) !== 'yes' ) return [];

        $data = [];

        foreach( [
            'fingerprint', 'brand', 'last4', 'country', 'funding',
            'avs_street', 'avs_zip', 'cvc', 'three_d', 'risk_level', 'risk_score',
        ] as $key ) {
            $data[ $key ] = (string) $order->get_meta( '_mshield_card_' . $key );
        }

        return $data;

    }

    /**
     * Score the card, then let the engine decide.
     *
     * Everything this class learns arrives after payment, on a webhook or a
     * gateway hook, and until 2.2.0 that made it a second fraud engine: it
     * formed its own verdict from its own evidence and held the order on a
     * single checkbox of its own, with no weight the merchant could see and no
     * way to disagree with one part of it.
     *
     * Now it scores like everything else. The complication is that
     * risk_context is per-request and this request is a webhook, so the
     * checkout's own signals are not in it. Scoring here without putting them
     * back would judge the order on its card alone and throw away everything
     * the checkout knew — an order that tripped six things at checkout and has
     * a mismatched CVC would come out looking like an order that tripped one.
     *
     * So the stored verdict is replayed first. db::save_risk() wrote the whole
     * signal set as JSON at checkout; risk_context::restore() puts it back, the
     * card signals are added on top, and the ladder decides once, on the
     * complete picture.
     *
     * @since   2.2.0
     *
     * @param   \WC_Order   $order
     * @param   array       $data
     */
    private static function decide( $order, $data ) {

        // Start clean. This runs on a webhook, and anything left in the context
        // from an earlier order in the same process would be attributed to this
        // one.
        risk_context::reset();

        $stored = db::get_risk( $order->get_id() );

        if( ! empty( $stored['signals'] ) ) {
            $signals = json_decode( (string) $stored['signals'], true );
            if( is_array( $signals ) ) risk_context::restore( $signals );
        }

        $emitted = self::emit( $order, $data );

        // The card has a name now, which it did not at checkout, so this is the
        // first moment its own history can be read. A card carrying a
        // chargeback raises entity_chargeback on its own -- there is no
        // card-history signal, because that one already exists and applies to
        // every identity equally.
        $identities = entities::for_order( $order );
        if( ! empty( $identities ) ) entities::assess( $identities );

        // Nothing new to say. Re-dispatching the same verdict would re-flag an
        // order a merchant may already have reviewed, which is what the
        // _mshield_card_read guard above exists to prevent on a redelivery.
        if( $emitted === 0 && ! risk_context::has( 'entity_chargeback' ) ) {
            risk_context::reset();
            return;
        }

        $verdict = risk_context::evaluate();

        // What the level says to do, then what is still possible now the charge
        // has happened. Refusing, authorizing and 3-D Secure are all off the
        // table by definition at this point.
        $action = actions::resolve_post_payment( risk_levels::action( $verdict['risk_level'] ) );

        // Persist before acting, and keep the row's place in the reporting
        // windows: this is the same order re-rated, not a new one.
        db::save_risk( $order->get_id(), [
            'trust'             => $verdict['trust'],
            'risk_level'        => $verdict['risk_level'],
            'risk_level_source' => $verdict['risk_level_source'],
            'action_taken'      => response::is_enforcing() ? $action : 'observed',
            'signals'           => risk_context::to_array()['signals'],
            'rated_by'          => 'card',
            'created_at'        => $stored['created_at'] ?? '',
            'outcome'           => $stored['outcome'] ?? '',
            'ai_rating'         => isset( $stored['ai_rating'] ) && $stored['ai_rating'] !== null ? (int) $stored['ai_rating'] : null,
            'ai_verdict'        => $stored['ai_verdict'] ?? '',
        ] );

        $order->update_meta_data( '_mshield_risk_trust', $verdict['trust'] );
        $order->update_meta_data( '_mshield_risk_level', $verdict['risk_level'] );
        $order->save();

        if( response::is_enforcing() && $action !== actions::NONE ) {

            response::dispatch( $order, $action, sprintf(
                'The payment processor answered after checkout. Trust rating %s/100 → %s. Signals: %s.',
                $verdict['trust'],
                risk_levels::label( $verdict['risk_level'] ),
                implode( '; ', risk_context::reasons() )
            ) );

        }

        risk_context::reset();

    }

    /**
     * Turn the processor's answer into signals. Emits and nothing else.
     *
     * This used to be evaluate(): it built a list of reasons, wrote a note, and
     * then held the order itself when both the address and the security code
     * failed, gated on a checkbox of its own. The judgement was sound and the
     * place was wrong -- one lever for five different findings, on a page that
     * is supposed to be about what happens to a score rather than how one is
     * made.
     *
     * Each finding is now a row on the Scoring tab with its own weight. The
     * defaults reproduce the old behaviour exactly: AVS and CVC are 35 each, so
     * both failing is 70, which is a trust rating of 30, which is High, whose
     * default action is to hold. The difference is that a merchant who thinks a
     * failed CVC alone is worth holding can now say so.
     *
     * Public because the card is one of the few things a stored order CAN be
     * re-rated on: every field is on the order as meta, so rescore replays it
     * through here rather than keeping a second copy of the judgement.
     *
     * @since   2.2.0
     *
     * @param   \WC_Order   $order
     * @param   array       $data
     * @return  int         Signals emitted.
     */
    public static function emit( $order, $data ) {

        $emitted = 0;

        $add = function( $key, $reason ) use ( &$emitted ) {
            if( risk_context::add( $key, $reason ) ) $emitted++;
        };

        // AVS. Street and postcode are two readings of one check, so they share
        // a signal -- charging an order twice for one failed address check would
        // double-count the same fact, which is exactly what the weights are
        // tuned to avoid.
        $street_failed = \in_array( $data['avs_street'], self::FAILED, true );
        $zip_failed    = \in_array( $data['avs_zip'], self::FAILED, true );

        if( $street_failed || $zip_failed ) {

            $which = $street_failed && $zip_failed
                ? __( 'the billing street address and postcode did not match the card', 'mighty-shield' )
                : ( $street_failed
                    ? __( 'the billing street address did not match the card', 'mighty-shield' )
                    : __( 'the billing postcode did not match the card', 'mighty-shield' ) );

            $add( 'card_avs_fail', $which );

        }

        if( \in_array( $data['cvc'], self::FAILED, true ) ) {
            $add( 'card_cvc_fail', __( 'the security code did not match', 'mighty-shield' ) );
        }

        // Card issued in a different country to where the order is going.
        //
        // This used to be suppressed unless something else had already tripped,
        // because on its own it is weak. That suppression is what weights are
        // for: at 15 it cannot reach anything by itself and it compounds
        // properly with the rest, which is what it was always trying to do.
        $ship_country = strtoupper( (string) ( $order->get_shipping_country() ?: $order->get_billing_country() ) );

        if( $data['country'] !== '' && $ship_country !== '' && $data['country'] !== $ship_country ) {
            $add( 'card_country_mismatch', sprintf(
                /* translators: 1: card country, 2: destination country. */
                __( 'the card was issued in %1$s but the order ships to %2$s', 'mighty-shield' ),
                $data['country'],
                $ship_country
            ) );
        }

        // A prepaid card on a high-value physical order is rarely legitimate.
        $high_value = (float) settings::get( 'mshield_ai_high_value_amount' );

        if( $data['funding'] === 'prepaid' && $high_value > 0 && (float) $order->get_total() >= $high_value ) {
            $add( 'card_prepaid_high_value', __( 'a prepaid card was used for a high-value order', 'mighty-shield' ) );
        }

        // The processor already scored this payment. Read what it said rather
        // than guessing at what it would have said.
        if( $data['risk_level'] === 'highest' || $data['risk_level'] === 'elevated' ) {
            $add( 'card_processor_risk', sprintf(
                /* translators: %s: the processor's own risk level. */
                __( 'the payment processor rated this payment %s risk', 'mighty-shield' ),
                $data['risk_level']
            ) );
        }

        if( $emitted > 0 ) {

            $order->update_meta_data( '_mshield_card_flagged', 'yes' );

            // The reason shown in Fraud Review's "why it is held" column. A
            // label, not a decision -- the engine still decides what happens.
            // Without it a card-held order read as "flagged by the risk
            // rating", which is true and useless: the whole point of getting
            // the processor's answer is being told what it said.
            if( $order->get_meta( '_mshield_flagged' ) === '' ) {
                $order->update_meta_data( '_mshield_flagged', 'card_signals' );
            }

            db::log_event(
                $order->get_customer_ip_address(),
                'card_signals',
                'flagged',
                sprintf( 'Order #%d: %s', $order->get_id(), implode( '; ', risk_context::reasons() ) ),
                '',
                (int) $order->get_id()
            );

        }

        return $emitted;

    }

}
