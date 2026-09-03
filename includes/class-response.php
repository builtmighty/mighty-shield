<?php
/**
 * Response ladder — Phase 2 enforcement.
 *
 * Turns a risk level into an action, and does it without letting a detained or
 * refused order reach the payment processor. That last part is the whole point:
 * every spam order a gateway sees counts against the merchant account's decline
 * and fraud ratios, so "reject before the processor" is a business requirement,
 * not an optimization.
 *
 * ---------------------------------------------------------------------------
 * THE FREE-ORDER TRAP — read before changing anything here.
 *
 * Both checkout paths call $order->payment_complete() on their no-payment
 * branch (WC_Checkout::process_order_without_payment, and Store API
 * CheckoutTrait::process_without_payment). payment_complete() marks the order
 * PAID and reduces stock.
 *
 * So the obvious implementation — make needs_payment() return false, by setting
 * the order on-hold or filtering woocommerce_cart_needs_payment — hands out free
 * goods. An attacker who could reliably trigger a detain would get merchandise
 * for nothing, which is far worse than the fraud being prevented.
 *
 * Neither branch is usable: one charges, the other gives the goods away. So
 * enforcement never lets the dispatch be reached, using a different mechanism
 * per path. See detain_classic() and detain_store_api().
 * ---------------------------------------------------------------------------
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes;

class response {

    /**
     * Enforcement is opt-in.
     *
     * A store upgrading into this version must not silently change how its
     * checkout behaves. Until the merchant switches to "enforce", every risk level is
     * recorded and nothing is acted on — which is also how the risk level thresholds
     * get tuned against real traffic before they are trusted with revenue.
     *
     * @since   1.9.0
     *
     * @return  bool
     */
    public static function is_enforcing() {

        return settings::get( 'mshield_enforcement_mode' ) === 'enforce';

    }

    /**
     * Whether a risk level should be refused outright, before an order exists.
     *
     * @since   1.9.0
     *
     * @param   string  $level
     * @return  bool
     */
    public static function refuses( $level ) {

        // Both halves matter. A terminal level always refuses whatever is
        // stored against it, and a configurable level refuses when its chosen
        // action says so.
        if( ! risk_levels::creates_order( $level ) ) return true;

        return risk_levels::action( $level ) === actions::REJECT;

    }

    /**
     * Whether a risk level should be held without contacting the processor.
     *
     * @since   1.9.0
     *
     * @param   string  $level
     * @return  bool
     */
    public static function detains( $level ) {

        return risk_levels::action( $level ) === actions::HOLD_UNPAID;

    }

    /**
     * The customer-facing message for a refusal.
     *
     * Deliberately generic and rotating. The old fixed string was an oracle: a
     * scripted attacker submits variations, times the response, reads the exact
     * error, and binary-searches until something passes. Making refusals look
     * like an ordinary issuer decline — and vary — does not stop a determined
     * attacker, but it destroys their iteration rate, which is what actually
     * makes an attack unprofitable.
     *
     * @since   1.9.0
     *
     * @return  string
     */
    public static function refusal_message() {

        $messages = self::refusal_messages();

        return self::with_note( $messages[ array_rand( $messages ) ] );

    }

    /**
     * Every refusal message, in order.
     *
     * Split out so the Blocking tab can show a merchant exactly what a refused
     * customer reads, which is the only way to write a useful note to append
     * to it.
     *
     * @since   2.0.0
     *
     * @return  string[]
     */
    public static function refusal_messages() {

        return [
            __( 'We were unable to process your payment. Please try a different payment method or contact your bank.', 'mighty-shield' ),
            __( 'Your payment could not be authorized. Please check your details and try again.', 'mighty-shield' ),
            __( 'This transaction was declined. Please contact your card issuer for more information.', 'mighty-shield' ),
        ];

    }

    /**
     * Append the merchant's own note to a customer-facing refusal.
     *
     * Refusals are deliberately vague, because a specific one is an oracle an
     * attacker can iterate against. The cost of that vagueness is paid by the
     * occasional real customer who gets caught and has no idea who to talk to.
     * This is where the merchant puts the phone number.
     *
     * Every refusal goes through here, so the note is either on all of them or
     * none. A contact line that appeared on one refusal out of eleven would
     * read as a bug to the one customer who saw it and to the one who did not.
     *
     * The note is stored already sanitised to the tags both checkouts render
     * (see admin_page::sanitize_refusal_note), so it is concatenated as-is.
     *
     * @since   2.0.0
     *
     * @param   string  $message    The refusal message.
     * @return  string
     */
    public static function with_note( $message ) {

        $note = trim( (string) settings::get( 'mshield_refusal_note' ) );

        if( $note === '' ) return $message;

        return $message . ' ' . $note;

    }

    /**
     * Stall before refusing.
     *
     * Card-testing scripts are throughput machines; a fast, constant-time
     * failure is what makes them cheap to run. The delay is randomized so the
     * response time itself cannot be used to distinguish a MightyShield refusal
     * from a genuine gateway decline.
     *
     * Skipped entirely when the store has tarpitting switched off, since it does
     * hold a PHP worker for the duration.
     *
     * @since   1.9.0
     */
    public static function tarpit() {

        if( settings::get( 'mshield_tarpit_enabled' ) !== 'yes' ) return;

        $min = (int) settings::get( 'mshield_tarpit_min_ms' );
        $max = (int) settings::get( 'mshield_tarpit_max_ms' );

        if( $max <= 0 || $max < $min ) return;

        usleep( random_int( max( 0, $min ), $max ) * 1000 );

    }

    /**
     * Whether a risk level should be challenged rather than allowed or held.
     *
     * @since   1.9.0
     *
     * @param   string  $level
     * @return  bool
     */
    public static function challenges( $level ) {

        return risk_levels::action( $level ) === actions::VERIFY_3DS;

    }

    /**
     * Apply the step-up challenge to an ambiguous order.
     *
     * The challenged risk level exists for orders that are suspicious but plausible —
     * the ones where blocking loses real revenue and allowing loses real money.
     * Forcing 3-D Secure resolves that without a human: a genuine cardholder
     * completes their bank's prompt, someone using a stolen card cannot, and
     * liability for the chargeback moves to the issuer either way.
     *
     * Gateway-capability-gated, and additive. When the processor cannot do it
     * the order proceeds exactly as it would have — the challenge is a bonus
     * where available, never a requirement, because across a fleet of stores on
     * different processors it has to degrade to "no challenge" and never to
     * "broken checkout".
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @param   string      $reason
     * @return  bool    True when a challenge was actually arranged.
     */
    public static function challenge( $order, $reason = '' ) {

        // No separate on/off switch any more: choosing this action for a level
        // IS the switch.
        $applied = gateways::request_3ds( $order );

        $order->update_meta_data( '_mshield_challenged', $applied ? '3ds' : 'unavailable' );

        if( $applied ) {

            $order->add_order_note( 'MightyShield: ' . __( 'Additional card verification (3-D Secure) was required for this order.', 'mighty-shield' ) . ( $reason !== '' ? ' ' . $reason : '' ) );

            db::log_event(
                ip_utils::get_client_ip(),
                'risk_engine',
                'flagged',
                'Step-up 3-D Secure requested: ' . $reason,
                '',
                (int) $order->get_id()
            );

        } else {

            // Say so plainly rather than implying a check happened. A merchant
            // must never believe an order was verified when it was not.
            $order->add_order_note( 'MightyShield: ' . __( 'This order was rated suspicious, but the payment method does not support additional card verification, so it proceeded without it.', 'mighty-shield' ) . ( $reason !== '' ? ' ' . $reason : '' ) );

        }

        $order->save();

        return $applied;

    }

    /**
     * Hold an order on classic checkout without contacting the processor.
     *
     * Runs on woocommerce_checkout_order_processed, which fires before the
     * payment branch, and terminates the request itself — so WooCommerce never
     * reaches either dispatch.
     *
     * Falling through instead is not an option. Removing the gateway from
     * get_available_payment_gateways() does make process_order_payment() return
     * early without contacting anything, but execution then lands in
     * send_ajax_failure_response(), which unconditionally responds
     * result => failure. The shopper would see a bare failure on an order that
     * was in fact accepted for review.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @param   string      $reason
     */
    public static function detain_classic( $order, $reason = '' ) {

        self::mark_detained( $order, $reason );

        if( function_exists( 'wc_empty_cart' ) ) wc_empty_cart();

        $url = $order->get_checkout_order_received_url();

        /**
         * Filter the URL a detained shopper is sent to.
         *
         * @since 1.9.0
         *
         * @param string    $url    Order-received URL.
         * @param \WC_Order $order  The detained order.
         */
        $url = apply_filters( 'mshield_detained_redirect', $url, $order );

        if( wp_doing_ajax() ) {
            // wp_send_json() ends the request itself.
            wp_send_json( [ 'result' => 'success', 'redirect' => $url ] );
        }

        wp_safe_redirect( $url );
        exit;

    }

    /**
     * Hold an order on the Store API (block checkout) without contacting the
     * processor.
     *
     * A REST request cannot exit — the Blocks client needs a well-formed
     * response — so instead of terminating, this replaces the single action the
     * route dispatches payment through. Every gateway registers on that action,
     * so clearing it and substituting our own handler is gateway-agnostic.
     *
     * IMPORTANT: the order stays "pending" here on purpose. The route chooses
     * its branch with `if ( $this->order->needs_payment() )`, and an on-hold
     * order reports needs_payment() === false, which routes into
     * process_without_payment() → payment_complete() → a free order. The status
     * change happens inside our payment handler, after the branch is chosen.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @param   string      $reason
     */
    public static function detain_store_api( $order, $reason = '' ) {

        // Remember why, so the substituted handler can write the note.
        $order->update_meta_data( '_mshield_detain_reason', $reason );
        $order->save();

        remove_all_actions( 'woocommerce_rest_checkout_process_payment_with_context' );

        add_action(
            'woocommerce_rest_checkout_process_payment_with_context',
            [ __CLASS__, 'store_api_payment_result' ],
            10,
            2
        );

    }

    /**
     * Stand in for the payment gateway on a detained Store API checkout.
     *
     * Reports success without any outbound request, and moves the order to
     * on-hold now that the route has already committed to the payment branch.
     *
     * @since   1.9.0
     *
     * @param   object  $context        PaymentContext.
     * @param   object  $result         PaymentResult, passed by reference.
     */
    public static function store_api_payment_result( $context, &$result ) {

        // PaymentContext exposes its order through __get() only — there is no
        // get_order() method, and it defines no __isset(), so both
        // method_exists() and isset() report false for it. Read the property
        // directly; __get() returns null for anything it does not recognise.
        $order = is_object( $context ) ? $context->order : null;

        // Without the order there is nothing to hold. Reporting success here
        // would tell the shopper the order went through while it silently
        // stayed pending and unreviewed — so fail the payment instead. A
        // shopper seeing an error on a suspicious order is recoverable; a
        // detain that quietly does not detain is not.
        if( ! $order instanceof \WC_Order ) {

            db::log_event(
                ip_utils::get_client_ip(),
                'risk_engine',
                'blocked',
                'Detain could not resolve the order from the payment context — failed the payment rather than letting it through unheld.'
            );

            if( is_object( $result ) && method_exists( $result, 'set_status' ) ) {
                $result->set_status( 'failure' );
            }

            return;

        }

        self::mark_detained( $order, (string) $order->get_meta( '_mshield_detain_reason' ) );

        if( is_object( $result ) && method_exists( $result, 'set_redirect_url' ) ) {
            $result->set_redirect_url(
                apply_filters( 'mshield_detained_redirect', $order->get_checkout_order_received_url(), $order )
            );
        }

        if( is_object( $result ) && method_exists( $result, 'set_status' ) ) {
            $result->set_status( 'success' );
        }

    }

    /**
     * Record the detain on the order.
     *
     * Never sets date_paid and never calls payment_complete() — the order is
     * genuinely unpaid, and recording otherwise would corrupt reporting and
     * reconciliation.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @param   string      $reason
     */
    private static function mark_detained( $order, $reason ) {

        $note = __( 'MightyShield: held for review before payment. No charge has been attempted and the payment processor was never contacted.', 'mighty-shield' );

        if( $reason !== '' ) {
            $note .= ' ' . $reason;
        }

        $order->update_meta_data( '_mshield_detained', 'yes' );
        $order->update_meta_data( '_mshield_flagged', 'detained' );
        $order->add_order_note( $note );

        // update_status() saves, so no separate save() call is needed.
        $order->update_status( 'on-hold', __( 'MightyShield: detained for review.', 'mighty-shield' ) );

        delete_transient( 'mshield_ai_pending_count' );

        db::log_event(
            ip_utils::get_client_ip(),
            'risk_engine',
            'blocked',
            'Order detained before payment: ' . $reason,
            '',
            (int) $order->get_id(),
            (float) $order->get_meta( '_mshield_risk_trust' ) ?: null
        );

    }

    /**
     * Whether an order was detained by this engine.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  bool
     */
    public static function is_detained( $order ) {

        return is_object( $order ) && $order->get_meta( '_mshield_detained' ) === 'yes';

    }

    /**
     * Release a detained order so the customer can pay for it.
     *
     * Used when a merchant approves a detained order. Nothing is charged here —
     * no card details were ever captured — so the customer is sent a link to pay
     * through the real gateway.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  string      The payment URL to send the customer.
     */
    public static function release( $order ) {

        $order->update_meta_data( '_mshield_detained', 'released' );
        $order->add_order_note( __( 'MightyShield: released from review. The customer can now pay for this order.', 'mighty-shield' ) );
        $order->update_status( 'pending', __( 'MightyShield: released for payment.', 'mighty-shield' ) );

        delete_transient( 'mshield_ai_pending_count' );

        return $order->get_checkout_payment_url();

    }

    /**
     * Mark an order for a human to look at, without changing anything else.
     *
     * The order goes through, the customer notices nothing, and the merchant
     * gets a note plus a row in the review queue.
     *
     * This is the one implementation. It was open-coded in nine places —
     * store_api plus each classic layer — which is why the note wording, the
     * log source, and whether the order was saved all differed slightly
     * depending on which check happened to fire.
     *
     * @since   1.9.1
     *
     * @param   \WC_Order   $order
     * @param   string      $slug       What flagged it.
     * @param   string      $reason     Human-readable, goes on the order note.
     * @param   bool        $notify     Also email the admin.
     * @param   string      $source     Log source column.
     * @return  bool
     */
    public static function flag( $order, $slug, $reason = '', $notify = false, $source = 'risk_engine' ) {

        if( ! is_a( $order, 'WC_Order' ) ) return false;

        if( $reason === '' ) $reason = __( 'Flagged for review.', 'mighty-shield' );

        db::log_event( ip_utils::get_client_ip(), $source, 'flagged', $reason, '', $order->get_id() );

        $order->add_order_note( 'MightyShield: ' . $reason );

        // Never overwrite an existing flag: the first thing to notice is the
        // more specific answer to "why is this here".
        if( $order->get_meta( '_mshield_flagged' ) === '' ) {
            $order->update_meta_data( '_mshield_flagged', $slug );
        }

        $order->save();

        delete_transient( 'mshield_ai_pending_count' );

        if( $notify ) self::notify_admin( $order, $reason );

        return true;

    }

    /**
     * Email the store admin about a flagged order.
     *
     * @since   1.9.1
     *
     * @param   \WC_Order   $order
     * @param   string      $reason
     */
    private static function notify_admin( $order, $reason ) {

        wp_mail(
            get_option( 'admin_email' ),
            sprintf( '[MightyShield] %s on order #%d', $reason, $order->get_id() ),
            sprintf(
                "MightyShield flagged an order.\n\nOrder: #%d\nReason: %s\nCustomer: %s (%s)\nIP: %s\n\nReview this order: %s",
                $order->get_id(),
                $reason,
                $order->get_formatted_billing_full_name(),
                $order->get_billing_email(),
                $order->get_customer_ip_address(),
                $order->get_edit_order_url()
            )
        );

    }

    /**
     * Reserve the funds without taking them, then hold the order.
     *
     * The gateway is asked to authorize rather than charge, and it sets the
     * order On-hold itself once it does. MightyShield must NOT set On-hold
     * here: woocommerce_valid_order_statuses_for_payment is [pending, failed],
     * so an order already On-hold gets neither a capture nor an authorization —
     * it simply never pays.
     *
     * Approving later captures; refusing voids, with nothing to refund.
     *
     * @since   1.9.1
     *
     * @param   \WC_Order   $order
     * @param   string      $reason
     * @return  bool    True when the authorization was actually arranged.
     */
    public static function hold_authorized( $order, $reason = '' ) {

        if( ! is_a( $order, 'WC_Order' ) ) return false;

        $applied = ai_capture::force_auth_only( $order );

        $order->update_meta_data( '_mshield_hold', $applied ? 'authorized' : 'unavailable' );
        $order->update_meta_data( '_mshield_flagged', 'risk_hold' );
        $order->add_order_note( 'MightyShield: ' . (
            $applied
                ? __( 'Held for review. The card was authorized but not charged. Approving captures the payment; refusing voids it with nothing to refund.', 'mighty-shield' )
                : __( 'Held for review. This payment method cannot authorize without charging, so it was handled as a hold before payment instead.', 'mighty-shield' )
        ) . ( $reason !== '' ? ' ' . $reason : '' ) );
        $order->save();

        delete_transient( 'mshield_ai_pending_count' );

        db::log_event(
            ip_utils::get_client_ip(),
            'risk_engine',
            'flagged',
            'Order authorized and held for review: ' . $reason,
            '',
            $order->get_id()
        );

        return $applied;

    }

    /**
     * Take the payment in full, then hold the order before fulfilment.
     *
     * The status change has to wait for woocommerce_payment_complete — setting
     * On-hold any earlier stops the payment happening at all, for the same
     * reason as hold_authorized(). So this registers the hold and lets the
     * charge run first.
     *
     * @since   1.9.1
     *
     * @param   \WC_Order   $order
     * @param   string      $reason
     * @return  bool
     */
    public static function hold_paid( $order, $reason = '' ) {

        if( ! is_a( $order, 'WC_Order' ) ) return false;

        $order->update_meta_data( '_mshield_hold', 'paid' );
        $order->update_meta_data( '_mshield_flagged', 'risk_hold' );
        $order->add_order_note( 'MightyShield: ' . __( 'Held for review after payment. The money has been taken but the order will not be fulfilled until you release it.', 'mighty-shield' ) . ( $reason !== '' ? ' ' . $reason : '' ) );
        $order->save();

        add_action( 'woocommerce_payment_complete', [ __CLASS__, 'hold_after_payment' ], 999 );

        db::log_event(
            ip_utils::get_client_ip(),
            'risk_engine',
            'flagged',
            'Order held for review after payment: ' . $reason,
            '',
            $order->get_id()
        );

        return true;

    }

    /**
     * Put a paid order On-hold once the charge has settled.
     *
     * @since   1.9.1
     *
     * @param   int     $order_id
     */
    public static function hold_after_payment( $order_id ) {

        $order = wc_get_order( $order_id );
        if( ! $order ) return;

        if( $order->get_meta( '_mshield_hold' ) !== 'paid' ) return;
        if( $order->get_status() === 'on-hold' ) return;

        $order->update_status( 'on-hold', __( 'MightyShield: held for review.', 'mighty-shield' ) );

        delete_transient( 'mshield_ai_pending_count' );

    }

    /**
     * Run the action a risk level resolved to.
     *
     * Called only for orders that exist — rejection happens earlier, at
     * validation, where there is no order to act on. Returns the action that
     * actually ran, which is not always the one asked for: resolve() walks the
     * fallback chain when this order's gateway cannot do what was chosen.
     *
     * @since   1.9.1
     *
     * @param   \WC_Order   $order
     * @param   string      $action     Action key from the level.
     * @param   string      $reason
     * @return  string      The action that ran.
     */
    public static function dispatch( $order, $action, $reason = '' ) {

        $action = actions::resolve( $action, $order );

        switch( $action ) {

            case actions::FLAG:
                self::flag( $order, 'risk_engine', $reason !== '' ? $reason : __( 'Flagged by the risk rating.', 'mighty-shield' ) );
                break;

            case actions::VERIFY_3DS:
                self::challenge( $order, $reason );
                break;

            case actions::HOLD_AUTHORIZED:
                self::hold_authorized( $order, $reason );
                break;

            case actions::HOLD_PAID:
                self::hold_paid( $order, $reason );
                break;

            case actions::HOLD_UNPAID:
                // Terminates the request on classic checkout, so it must be
                // last and the caller must have finished persisting.
                if( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
                    self::detain_store_api( $order, $reason );
                } else {
                    self::detain_classic( $order, $reason );
                }
                break;

            case actions::NONE:
            default:
                break;

        }

        return $action;

    }

}
