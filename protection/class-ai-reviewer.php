<?php
/**
 * AI Reviewer.
 *
 * Stage two of three. Every detector has scored by the time this runs, and
 * nothing has been decided yet: it goes at priority 90 on the validation hook,
 * after the last detector and before risk_recorder at 99.
 *
 * It used to run on the order-processed hooks. That put the model's opinion
 * after the order existed and after the only point where a checkout can be
 * refused, so the one verdict a merchant actually pays for could never prevent
 * a sale — it could only change what happened to an order that had already
 * been created.
 *
 * Because there is no order yet, the model is shown a snapshot rather than a
 * WC_Order, and the verdict it returns is applied in two pieces: the rating
 * reaches the ladder immediately through risk_context, and the paperwork waits
 * in persist() for risk_recorder to hand it an order.
 *
 * Do NOT set an order On-hold from here. woocommerce_valid_order_statuses_for_payment
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
     * Whether this request has already been reviewed.
     *
     * @since   1.8.0
     */
    private $reviewed = false;

    /**
     * The verdict from this request's review, waiting for an order to land on.
     *
     * The review now happens before the order exists, so there is nothing to
     * write meta to at the moment the model answers. The rating reaches the
     * ladder immediately, through risk_context::set_ai_trust(); this holds the
     * paperwork -- rating, verdict, confidence, reasons -- until
     * risk_recorder has an order and calls persist().
     *
     * Static because the object that asked and the recorder that persists are
     * different instances.
     *
     * @since   2.2.0
     */
    private static $pending = null;

    /**
     * Construct.
     *
     * @since   1.8.0
     */
    public function __construct() {

        // Registered before the feature's own guards, not after. A merchant who
        // reacts to a credentials error by clearing the bad key stops the class
        // short at the guard below -- and used to stop seeing the warning about
        // the very key they had just cleared, which reads as fixed.
        if( is_admin() ) {
            add_action( 'admin_notices', [ '\MightyShield\Includes\ai_client', 'render_degraded_notice' ] );
        }

        if( settings::get( 'mshield_ai_enabled' ) !== 'yes' ) return;

        // Stage two of three, and it runs at validation — after every detector
        // has scored and before risk_recorder decides at 99. It used to run on
        // the order-processed hooks, which put the model's opinion after the
        // order existed and after the only moment a checkout could be refused,
        // so the one verdict the merchant pays for could never prevent a sale.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'review_classic' ], 90, 2 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'review_store_api' ], 90, 2 );

    }

    /**
     * Classic checkout, at validation — before any order exists.
     *
     * @since   1.8.0
     *
     * @param   array       $data   Checkout posted data.
     * @param   \WP_Error   $errors Unused — the reviewer scores, it does not refuse.
     */
    public function review_classic( $data, $errors ) {

        if( exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        $this->review( self::snapshot_from_checkout( $data ) );

    }

    /**
     * Block checkout, at validation.
     *
     * The Store API populates the draft order from the request before this
     * hook, so there is a real order to read here — but it is still a draft,
     * and the verdict is applied the same way as on classic.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order          $order
     * @param   \WP_REST_Request   $request
     */
    public function review_store_api( $order, $request ) {

        if( ! is_a( $order, 'WC_Order' ) ) return;
        if( exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $this->review( self::snapshot_from_order( $order ) );

    }

    /**
     * Escalate to the AI and record the verdict.
     *
     * @since   1.8.0
     *
     * @param   array   $snapshot   From snapshot_from_order() / _from_checkout().
     */
    private function review( $snapshot ) {

        // One review per request. Both checkouts fire exactly one of the two
        // entry points above, so this only guards a theme or plugin that
        // triggers validation twice.
        if( $this->reviewed ) return;
        $this->reviewed = true;

        // 1. Decide whether this order is worth paying for an opinion on.
        //    Judged on the signal score alone: the AI's own rating cannot be
        //    an input to the decision about whether to ask for it.
        if( ! $this->worth_reviewing() ) return;

        $this->ask( $snapshot );

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

        ( new self() )->ask( self::snapshot_from_order( $order ) );

        // A person is waiting on the screen for this, so it is written through
        // now rather than left for the recorder that will not run.
        self::persist( $order );

    }

    /**
     * Ask the model and record what it says.
     *
     * @since   1.9.5
     *
     * @param   array   $snapshot
     */
    private function ask( $snapshot ) {

        // 2. Ask the model, giving it everything the plugin already knows.
        $verdict = ai_client::review( $this->build_prompt( $snapshot ) );

        // Fail open. A provider outage must never hold a legitimate order —
        // ai_client has already logged the degradation and alerted the admin.
        if( is_wp_error( $verdict ) || ! is_array( $verdict ) ) return;

        $reasons = (array) ( $verdict['reasons'] ?? [] );
        $rating  = (int) $verdict['trust'];

        // 3. Hold the paperwork until there is an order to put it on.
        self::$pending = [
            'rating'     => $rating,
            'verdict'    => $verdict['verdict'],
            'confidence' => $verdict['confidence'],
            'reasons'    => $reasons,
        ];

        db::log_event(
            ip_utils::get_client_ip(),
            'ai_review',
            'flagged',
            sprintf( 'AI review rated this order %d/100', $rating )
        );

        // 4. Hand it to the ladder, now, while the decision is still ahead of
        //    us. The rating caps the trust score; the level that falls out
        //    decides the action. Nothing is held here — two systems deciding
        //    the same thing is how they came to disagree.
        risk_context::set_ai_trust( $rating, $reasons );

    }

    /**
     * Write this request's verdict onto an order, once one exists.
     *
     * Called by risk_recorder. A no-op when no review ran, which is the common
     * case: worth_reviewing() only says yes for the levels the merchant marked
     * for review on the Blocking tab.
     *
     * @since   2.2.0
     *
     * @param   \WC_Order   $order
     */
    public static function persist( $order ) {

        if( self::$pending === null ) return;
        if( ! is_a( $order, 'WC_Order' ) ) return;

        $pending = self::$pending;

        // Cleared before the writes, not after: this must not run twice on one
        // order if both a recorder and a manual re-rate reach it.
        self::$pending = null;

        $order->update_meta_data( '_mshield_ai_rating', $pending['rating'] );
        $order->update_meta_data( '_mshield_ai_verdict', $pending['verdict'] );
        $order->update_meta_data( '_mshield_ai_confidence', $pending['confidence'] );
        $order->update_meta_data( '_mshield_ai_reasons', $pending['reasons'] );

        $note = sprintf( 'AI review rated this order %d/100.', $pending['rating'] );
        if( ! empty( $pending['reasons'] ) ) $note .= ' Why: ' . implode( '; ', $pending['reasons'] ) . '.';

        $order->add_order_note( 'MightyShield: ' . $note );
        $order->save();

        if( settings::get( 'mshield_ai_notify_admin' ) === 'yes' ) {
            self::notify_admin( $order, $pending['rating'], $pending['reasons'] );
        }

    }

    /**
     * Forget any verdict left over from a previous order in this process.
     *
     * A web request handles one checkout and exits, so this exists for WP-CLI,
     * batch imports and the test suites — the same reason risk_context::reset()
     * does.
     *
     * @since   2.2.0
     */
    public static function reset() {

        self::$pending = null;

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

        // A signal floor cannot be argued with, so do not pay to try.
        //
        // evaluate() takes the more severe of the floor and the score, and the
        // model only moves the score — so on an order floored by a hidden trap
        // field, a failed bot challenge or a card with a chargeback against it,
        // the verdict is already settled and the call would change nothing at
        // any price. This is checked before the level, not after, because it is
        // true whichever level the floor produced.
        if( risk_context::floor_level()['risk_level'] !== null ) return false;

        // The pre-review level: scored from the signals alone. Using the
        // post-review number would mean the decision to buy an opinion
        // depended on the opinion.
        $level = risk_levels::from_trust( risk_context::signal_trust() );

        // Which levels are worth a verdict is the merchant's call, set as
        // "Send to Review" on the AI Review tab.
        //
        // Rejected is among the levels they may choose, which it could not have
        // been before 2.2.0: the review ran after the order existed and a
        // rejected checkout never got that far. It runs at validation now, so a
        // merchant who would rather not refuse anybody on arithmetic alone can
        // put the model in front of that decision. Banned is not offered —
        // it is reachable only through a floor, which the guard above has
        // already returned on.
        return risk_levels::ai_review( $level );

    }



    /**
     * Everything the prompt needs, read from a finished or draft order.
     *
     * @since   2.2.0
     *
     * @param   \WC_Order   $order
     * @return  array
     */
    private static function snapshot_from_order( $order ) {

        $items = [];
        foreach( $order->get_items() as $item ) {
            $items[] = $item->get_name() . ' x' . $item->get_quantity();
        }

        $payment = $order->get_payment_method_title();
        if( empty( $payment ) ) $payment = $order->get_payment_method();

        $ship = function( $field ) use ( $order ) {
            return ai_detection::shipping_or_billing( $order, $field );
        };

        return [
            'billing'  => [
                'name'      => trim( $order->get_billing_first_name() . ' ' . $order->get_billing_last_name() ),
                'address_1' => (string) $order->get_billing_address_1(),
                'city'      => (string) $order->get_billing_city(),
                'state'     => (string) $order->get_billing_state(),
                'postcode'  => (string) $order->get_billing_postcode(),
            ],
            'shipping' => [
                'name'      => trim( $ship( 'first_name' ) . ' ' . $ship( 'last_name' ) ),
                'address_1' => $ship( 'address_1' ),
                'city'      => $ship( 'city' ),
                'state'     => $ship( 'state' ),
                'postcode'  => $ship( 'postcode' ),
            ],
            'email'      => (string) $order->get_billing_email(),
            'phone'      => (string) $order->get_billing_phone(),
            'ip'         => (string) $order->get_customer_ip_address(),
            'user_id'    => (int) $order->get_user_id(),
            'total'      => (float) $order->get_total(),
            'currency'   => (string) $order->get_currency(),
            'items'      => $items,
            'payment'    => (string) $payment,
            'identities' => entities::for_order( $order ),
        ];

    }

    /**
     * The same snapshot, from a classic checkout that has no order yet.
     *
     * Shipping falls back to billing field by field, matching
     * ai_detection::shipping_or_billing() on the order side — virtual orders
     * leave shipping blank rather than mirroring billing, and a prompt full of
     * empty shipping lines reads to the model as a suspicious order rather
     * than a downloadable one.
     *
     * @since   2.2.0
     *
     * @param   array   $data   Checkout posted data.
     * @return  array
     */
    private static function snapshot_from_checkout( $data ) {

        $billing = function( $field ) use ( $data ) {
            return trim( (string) ( $data[ 'billing_' . $field ] ?? '' ) );
        };

        $shipping = function( $field ) use ( $data, $billing ) {
            $value = trim( (string) ( $data[ 'shipping_' . $field ] ?? '' ) );
            return $value !== '' ? $value : $billing( $field );
        };

        $items = [];
        $total = 0.0;

        if( function_exists( 'WC' ) && WC()->cart ) {

            foreach( WC()->cart->get_cart() as $line ) {
                if( empty( $line['data'] ) || ! is_object( $line['data'] ) ) continue;
                $items[] = $line['data']->get_name() . ' x' . ( (int) ( $line['quantity'] ?? 1 ) );
            }

            $total = (float) WC()->cart->get_total( 'edit' );

        }

        $payment = (string) ( $data['payment_method'] ?? '' );

        // The posted value is a gateway id; the model is shown the same
        // customer-facing title it gets from an order.
        if( $payment !== '' && function_exists( 'WC' ) && WC()->payment_gateways() ) {
            $gateways = WC()->payment_gateways()->payment_gateways();
            if( isset( $gateways[ $payment ] ) ) $payment = $gateways[ $payment ]->get_title();
        }

        return [
            'billing'  => [
                'name'      => trim( $billing( 'first_name' ) . ' ' . $billing( 'last_name' ) ),
                'address_1' => $billing( 'address_1' ),
                'city'      => $billing( 'city' ),
                'state'     => $billing( 'state' ),
                'postcode'  => $billing( 'postcode' ),
            ],
            'shipping' => [
                'name'      => trim( $shipping( 'first_name' ) . ' ' . $shipping( 'last_name' ) ),
                'address_1' => $shipping( 'address_1' ),
                'city'      => $shipping( 'city' ),
                'state'     => $shipping( 'state' ),
                'postcode'  => $shipping( 'postcode' ),
            ],
            'email'      => $billing( 'email' ),
            'phone'      => $billing( 'phone' ),
            'ip'         => ip_utils::get_client_ip(),
            'user_id'    => get_current_user_id(),
            'total'      => $total,
            'currency'   => function_exists( 'get_woocommerce_currency' ) ? get_woocommerce_currency() : '',
            'items'      => $items,
            'payment'    => $payment,
            'identities' => entities::for_checkout( $data ),
        ];

    }

    /**
     * Build the fraud-review prompt.
     *
     * @since   1.8.0
     *
     * @param   array   $snapshot
     * @return  string
     */
    private function build_prompt( $snapshot ) {

        $prompt  = "You are reviewing a single e-commerce order for fraud on behalf of the shop owner.\n\n";

        $prompt .= "Judge the order as a whole. Most orders are placed by ordinary customers, and the cost of wrongly "
                 . "refusing a real one is a lost sale and an angry buyer — so do not treat individually unremarkable "
                 . "details as damning. What matters is whether the details fit together into a coherent picture of a "
                 . "real person buying something, or whether they only make sense as an attempt to look like one.\n\n";

        $redact = settings::get( 'mshield_ai_redact_pii' ) === 'yes';

        $prompt .= "ORDER\n";
        $prompt .= sprintf( "Billing: %s\n", $this->format_address( $snapshot['billing'], $redact ) );
        $prompt .= sprintf( "Shipping: %s\n", $this->format_address( $snapshot['shipping'], $redact ) );
        $prompt .= sprintf( "Email: %s\n", self::redact_email( $snapshot['email'], $redact ) );
        $prompt .= sprintf( "Phone: %s\n", $redact ? self::mask( $snapshot['phone'], 4 ) : $snapshot['phone'] );
        $prompt .= sprintf( "IP: %s\n", $redact ? self::coarsen_ip( $snapshot['ip'] ) : $snapshot['ip'] );
        $prompt .= sprintf( "Customer: %s\n", $this->customer_summary( $snapshot['user_id'] ) );
        $prompt .= sprintf( "Order value: %s\n", html_entity_decode( wp_strip_all_tags( wc_price( $snapshot['total'], [ 'currency' => $snapshot['currency'] ] ) ), ENT_QUOTES ) );
        $prompt .= sprintf( "Items: %s\n", implode( ', ', $snapshot['items'] ) );
        $prompt .= sprintf( "Payment method: %s\n", $snapshot['payment'] );

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

        $history = $this->history_summary( $snapshot['identities'] );
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
     * @param   int     $user_id
     * @return  string
     */
    private function customer_summary( $user_id ) {

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
     * @param   array   $identities  type => normalized value.
     * @return  string
     */
    private function history_summary( $identities ) {

        if( empty( $identities ) ) return '';

        $rows = entities::get_many( $identities );
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
     * @param   array   $address    One half of a snapshot: name, address_1,
     *                              city, state, postcode.
     * @param   bool    $redact
     * @return  string
     */
    private function format_address( $address, $redact = false ) {

        $parts = [
            (string) ( $address['name'] ?? '' ),
            (string) ( $address['address_1'] ?? '' ),
            (string) ( $address['city'] ?? '' ),
            trim( ( $address['state'] ?? '' ) . ' ' . ( $address['postcode'] ?? '' ) ),
        ];

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
    private static function notify_admin( $order, $rating, $reasons ) {

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
