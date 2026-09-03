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
 * @since   1.8.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\exempt;
use MightyShield\Includes\ai_detection;
use MightyShield\Includes\ai_client;
use MightyShield\Includes\risk_context;
use MightyShield\Includes\risk_levels;
use MightyShield\Includes\entities;

class ai_reviewer {

    /**
     * Orders already reviewed this request, so the classic and Store API hooks
     * cannot double-review the same order.
     *
     * @since   1.8.0
     */
    private $reviewed = [];

    /**
     * Construct.
     *
     * @since   1.8.0
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
     * @since   1.8.0
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
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     */
    public function review_store_api( $order ) {

        $this->review( $order );

    }

    /**
     * Score the order, escalate to the AI, and act on the verdict.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     */
    private function review( $order ) {

        if( ! is_object( $order ) || ! method_exists( $order, 'get_id' ) ) return;

        $order_id = $order->get_id();
        if( isset( $this->reviewed[ $order_id ] ) ) return;
        $this->reviewed[ $order_id ] = true;

        if( exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        // 1. Decide whether this order is worth paying for an opinion on.
        //    Judged on the signal score alone: the AI's own rating cannot be
        //    an input to the decision about whether to ask for it.
        if( ! $this->worth_reviewing() ) return;

        $this->ask( $order );

    }

    /**
     * Review one order because a person asked for it.
     *
     * Skips both gates that guard the automatic path, deliberately:
     *
     *   worth_reviewing()  exists to decide whether a verdict is worth paying
     *                      for on an order nobody has looked at. A reviewer who
     *                      clicked the button has already decided.
     *   is_exempt()        asks whether the CURRENT REQUEST is allowlisted, and
     *                      in wp-admin that is the administrator, not the
     *                      shopper. The order's own exemption was checked by
     *                      rescore before it got here.
     *
     * Everything after the gates is identical to the checkout path, so a manual
     * review is the same call, the same prompt and the same meta as an
     * automatic one.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     */
    public static function review_now( $order ) {

        if( ! is_a( $order, 'WC_Order' ) ) return;

        ( new self() )->ask( $order );

    }

    /**
     * Ask the model about one order and record what it says.
     *
     * @since   1.9.5
     *
     * @param   \WC_Order   $order
     */
    private function ask( $order ) {

        // 2. Ask the model, giving it everything the plugin already knows.
        $verdict = ai_client::review( $this->build_prompt( $order ) );

        // Fail open. A provider outage must never hold a legitimate order —
        // ai_client has already logged the degradation and alerted the admin.
        if( is_wp_error( $verdict ) || ! is_array( $verdict ) ) return;

        $reasons = (array) ( $verdict['reasons'] ?? [] );
        $rating  = (int) $verdict['trust'];

        // 3. Record it. Same 1-100 scale as everything else — the model is
        //    asked for a trust rating, so there is nothing to convert.
        $order->update_meta_data( '_mshield_ai_rating', $rating );
        $order->update_meta_data( '_mshield_ai_verdict', $verdict['verdict'] );
        $order->update_meta_data( '_mshield_ai_confidence', $verdict['confidence'] );
        $order->update_meta_data( '_mshield_ai_reasons', $reasons );

        $note = sprintf( 'AI review rated this order %d/100.', $rating );
        if( ! empty( $reasons ) ) $note .= ' Why: ' . implode( '; ', $reasons ) . '.';

        $order->add_order_note( 'MightyShield: ' . $note );
        $order->save();

        db::log_event(
            ip_utils::get_client_ip(),
            'ai_review',
            'flagged',
            sprintf( 'AI review rated this order %d/100', $rating ),
            '',
            (int) $order->get_id()
        );

        // 4. Hand it to the ladder. The rating caps the trust score; the level
        //    that falls out decides the action. Nothing is held here — two
        //    systems deciding the same thing is how they came to disagree.
        risk_context::set_ai_trust( $rating, $reasons );

        if( settings::get( 'mshield_ai_notify_admin' ) === 'yes' ) {
            $this->notify_admin( $order, $rating, $reasons );
        }

    }





    /**
     * Whether this order is worth spending an AI call on.
     *
     * Gated on the risk level rather than the old four-signal score, which decides
     * spend where it can actually change something:
     *
     *   trusted            skip — a known-good customer does not need an opinion
     *   rejected / banned  skip — already decided; a second opinion changes nothing
     *   everything else    review
     *
     * "All orders" still overrides this for stores that want a verdict on
     * every order regardless of cost.
     *
     * @since   1.9.0
     *
     * @return  bool
     */
    private function worth_reviewing() {

        // Nothing to spend a call on without a configured provider.
        if( ! ai_client::is_ready() ) return false;

        // The pre-review level: scored from the signals alone. Using the
        // post-review number would mean the decision to buy an opinion
        // depended on the opinion.
        $level = risk_levels::from_trust( risk_context::signal_trust() );

        // Rejected and banned orders never reach an order-processed hook, but
        // guard anyway: a second opinion cannot change an already-refused
        // checkout, and paying for one would be pure waste.
        if( $level === risk_levels::REJECTED || $level === risk_levels::BANNED ) return false;

        // Which levels are worth a verdict is now the merchant's call, set per
        // level on the Blocking tab beside that level's action.
        return risk_levels::ai_review( $level );

    }



    /**
     * Build the fraud-review prompt.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @return  string
     */
    private function build_prompt( $order ) {

        $products = [];
        foreach( $order->get_items() as $item ) {
            $products[] = $item->get_name() . ' x' . $item->get_quantity();
        }

        $payment = $order->get_payment_method_title();
        if( empty( $payment ) ) $payment = $order->get_payment_method();

        $prompt  = "You are reviewing a single e-commerce order for fraud on behalf of the shop owner.\n\n";

        $prompt .= "Judge the order as a whole. Most orders are placed by ordinary customers, and the cost of wrongly "
                 . "refusing a real one is a lost sale and an angry buyer — so do not treat individually unremarkable "
                 . "details as damning. What matters is whether the details fit together into a coherent picture of a "
                 . "real person buying something, or whether they only make sense as an attempt to look like one.\n\n";

        $redact = settings::get( 'mshield_ai_redact_pii' ) === 'yes';

        $prompt .= "ORDER\n";
        $prompt .= sprintf( "Billing: %s\n", $this->format_address( $order, 'billing', $redact ) );
        $prompt .= sprintf( "Shipping: %s\n", $this->format_address( $order, 'shipping', $redact ) );
        $prompt .= sprintf( "Email: %s\n", self::redact_email( $order->get_billing_email(), $redact ) );
        $prompt .= sprintf( "Phone: %s\n", $redact ? self::mask( (string) $order->get_billing_phone(), 4 ) : $order->get_billing_phone() );
        $prompt .= sprintf( "IP: %s\n", $redact ? self::coarsen_ip( (string) $order->get_customer_ip_address() ) : $order->get_customer_ip_address() );
        $prompt .= sprintf( "Customer: %s\n", $this->customer_summary( $order ) );
        $prompt .= sprintf( "Order value: %s\n", html_entity_decode( wp_strip_all_tags( wc_price( $order->get_total(), [ 'currency' => $order->get_currency() ] ) ), ENT_QUOTES ) );
        $prompt .= sprintf( "Items: %s\n", implode( ', ', $products ) );
        $prompt .= sprintf( "Payment method: %s\n", $payment );

        // Everything the plugin has already worked out. Previously none of this
        // reached the model, so it was asked to judge an order with strictly
        // less information than the code calling it already had.
        $context = risk_context::to_array();

        $prompt .= sprintf( "\nAUTOMATED CHECKS\nTrust rating so far: %s/100 (100 = totally trustworthy)\n", $context['trust'] );

        if( empty( $context['signals'] ) ) {

            $prompt .= "No automated check flagged anything on this order.\n";

        } else {

            $prompt .= "The following were flagged. Each line is what tripped, and how much trust it cost:\n";

            foreach( $context['signals'] as $signal ) {
                $prompt .= sprintf(
                    "- %s (cost %s)\n",
                    $signal['reason'],
                    round( (float) $signal['weight'] * (float) $signal['confidence'], 1 )
                );
            }

        }

        $history = $this->history_summary( $order );
        if( $history !== '' ) $prompt .= "\nHISTORY\n" . $history;

        $prompt .= "\nThe automated checks are signals, not conclusions. Say so if you think they have "
                 . "misread an ordinary order, and say so just as plainly if the order looks wrong for a reason "
                 . "they did not catch. Write your reasons for the shop owner, who has to decide whether to ship.";

        return $prompt;

    }

    /**
     * One line describing who placed the order.
     *
     * Account age matters: an account created minutes before a large order is
     * a different proposition to a three-year-old one.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  string
     */
    private function customer_summary( $order ) {

        $user_id = $order->get_user_id();

        if( ! $user_id ) return 'Guest (no account)';

        $user = get_userdata( $user_id );
        if( ! $user ) return 'Registered customer';

        $age_days = ( time() - strtotime( $user->user_registered ) ) / DAY_IN_SECONDS;

        if( $age_days < 1 ) {
            return 'Registered customer, account created today';
        }

        return sprintf( 'Registered customer, account %d days old', (int) $age_days );

    }

    /**
     * What is known about the identities behind this order.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  string
     */
    private function history_summary( $order ) {

        $rows = entities::get_many( entities::for_order( $order ) );
        if( empty( $rows ) ) return '';

        $lines = [];

        foreach( $rows as $type => $row ) {

            $orders = (int) $row['order_count'];
            if( $orders <= 1 ) continue;

            $line = sprintf( 'This %s has been seen on %d previous orders', entities::type_label( $type ), $orders - 1 );

            $bad = [];
            if( (int) $row['chargeback_count'] > 0 ) $bad[] = sprintf( '%d chargeback(s)', (int) $row['chargeback_count'] );
            if( (int) $row['denied_count'] > 0 )     $bad[] = sprintf( '%d denied in review', (int) $row['denied_count'] );
            if( (int) $row['refund_count'] > 0 )     $bad[] = sprintf( '%d refunded', (int) $row['refund_count'] );

            $line .= empty( $bad )
                ? ', all without incident.'
                : ', including ' . implode( ', ', $bad ) . '.';

            $lines[] = $line;

        }

        return empty( $lines ) ? '' : implode( "\n", $lines ) . "\n";

    }

    /**
     * Format one address block as "Name, Street, City, ST 12345".
     *
     * Shipping falls back to billing so virtual orders still produce a usable
     * line rather than a row of commas.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @param   string      $type   'billing' or 'shipping'.
     * @return  string
     */
    private function format_address( $order, $type, $redact = false ) {

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

        $line = implode( ', ', array_filter( array_map( 'trim', $parts ) ) );

        if( ! $redact ) return $line;

        // Drop the name AND the street. $parts[0] is the customer's name and
        // [1] is the street line — masking only [0] left the full address in
        // the prompt, which is most of what redaction was meant to remove.
        //
        // City, state and postcode stay: a fraud check needs to see whether the
        // locality hangs together, and those identify an area rather than a
        // person.
        $parts[0] = self::mask( (string) $parts[0], 0 );
        $parts[1] = self::mask( (string) $parts[1], 0 );

        return implode( ', ', array_filter( array_map( 'trim', $parts ) ) );

    }

    /**
     * Replace all but the last few characters of a value.
     *
     * @since   1.9.0
     *
     * @param   string  $value
     * @param   int     $keep   Trailing characters to preserve.
     * @return  string
     */
    private static function mask( $value, $keep = 0 ) {

        $value = trim( $value );
        if( $value === '' ) return '';

        if( $keep <= 0 || strlen( $value ) <= $keep ) return '[redacted]';

        return '[redacted]' . substr( $value, -$keep );

    }

    /**
     * Reduce an email to the parts a fraud check actually uses.
     *
     * The domain and the shape of the local part are what matter — whether it
     * is disposable, whether it resembles the customer's name, whether it looks
     * machine-generated. The exact mailbox does not.
     *
     * @since   1.9.0
     *
     * @param   string  $email
     * @param   bool    $redact
     * @return  string
     */
    private static function redact_email( $email, $redact ) {

        $email = (string) $email;
        if( ! $redact || $email === '' ) return $email;

        $at = strrpos( $email, '@' );
        if( $at === false ) return '[redacted]';

        $local  = substr( $email, 0, $at );
        $domain = substr( $email, $at + 1 );

        return sprintf( '[%d chars, %s]@%s',
            strlen( $local ),
            preg_match( '/\d{3,}/', $local ) ? 'contains digits' : 'no digit run',
            $domain
        );

    }

    /**
     * Drop the host part of an IP, keeping the network.
     *
     * @since   1.9.0
     *
     * @param   string  $ip
     * @return  string
     */
    private static function coarsen_ip( $ip ) {

        if( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            $p = explode( '.', $ip );
            return $p[0] . '.' . $p[1] . '.' . $p[2] . '.x';
        }

        return $ip === '' ? '' : '[redacted]';

    }

    /**
     * Tell the store admin an order came back badly rated.
     *
     * Deliberately does not say what happened to the order: that is decided by
     * the level the rating produces and the action set for it, which this class
     * no longer knows about.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @param   int         $rating     1-100.
     * @param   array       $reasons
     */
    private function notify_admin( $order, $rating, $reasons ) {

        $message = sprintf(
            "MightyShield's AI review rated an order %d/100 (100 is a completely ordinary order).\n\n" .
            "Order: #%d\n" .
            "Why: %s\n" .
            "Customer: %s (%s)\n" .
            "IP: %s\n" .
            "Payment: %s\n\n" .
            "This rating caps the order's trust score. What happens next is the action set for\n" .
            "the resulting risk level on the Blocking tab.\n\n" .
            "Review this order: %s",
            $rating,
            $order->get_id(),
            empty( $reasons ) ? 'no specific reasons given' : implode( '; ', $reasons ),
            $order->get_formatted_billing_full_name(),
            $order->get_billing_email(),
            $order->get_customer_ip_address(),
            $order->get_payment_method_title(),
            $order->get_edit_order_url()
        );

        wp_mail(
            settings::notification_recipients(),
            sprintf( '[MightyShield] AI rated order #%d at %d/100', $order->get_id(), $rating ),
            $message
        );

    }

}
