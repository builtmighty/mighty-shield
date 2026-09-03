<?php
/**
 * Risk recorder.
 *
 * Phase 1's terminus. Runs last on both checkout paths, adds the signals that
 * can only be derived once the whole order exists (identity history, IP
 * intelligence), then persists the verdict.
 *
 * In the default "observe" mode it takes NO action: every existing layer still
 * enforces its own block/flag decision exactly as before, and this only records
 * what risk level the order would have landed in. That is what lets the thresholds be
 * tuned against real traffic before they are trusted with revenue.
 *
 * Once the merchant switches to "enforce", the same verdict drives the response
 * ladder — refusals at validation, detains before payment. See class-response.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\exempt;
use MightyShield\Includes\entities;
use MightyShield\Includes\ip_data;
use MightyShield\Includes\risk_context;
use MightyShield\Includes\risk_levels;
use MightyShield\Includes\response;
use MightyShield\Includes\actions;
use MightyShield\Includes\rescore;

class risk_recorder {

    /**
     * Orders already recorded this request.
     *
     * @since   1.9.0
     */
    private $recorded = [];

    /**
     * Construct.
     *
     * @since   1.9.0
     */
    public function __construct() {

        // Priority 50 puts this after every other layer on both paths,
        // including the AI reviewer at 20/30, so the context is complete.
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'record_classic' ], 50, 3 );
        add_action( 'woocommerce_store_api_checkout_order_processed', [ $this, 'record_store_api' ], 50, 1 );

        // Refusals have to happen before the order exists, so they run at the
        // end of validation (priority 99, after every detector) rather than at
        // order-processed like the detain path.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'refuse_classic' ], 99, 2 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'refuse_store_api' ], 99, 2 );

        // Wipe the signal context before anything writes to it, on whichever
        // path this order arrived by.
        //
        // risk_context is process-global static state and add() is
        // first-write-wins, so two orders scored in ONE PHP process would give
        // the second one the first's signals and silently refuse its own. That
        // cannot happen in a web request, which handles one checkout — but
        // nothing in the design says so, and Action Scheduler, WP-CLI or a
        // future batch endpoint would all break it quietly rather than loudly.
        //
        // Priority -1: ahead of cookie_check and warm_ip_cache at 0, which are
        // the first things that emit.
        add_action( 'woocommerce_checkout_process', [ $this, 'begin' ], -1 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'begin' ], -1 );

        // Warm the IP cache early. signal_ip_mismatch() reads the cache only
        // and skips on a miss, and db::cleanup() drops IPs absent from the log
        // — so a first-time attacker's IP was never cached and the signal could
        // never fire, which is precisely when it was needed. Fetching here, off
        // the validation path, means the data is present by scoring time.
        add_action( 'woocommerce_checkout_process', [ $this, 'warm_ip_cache' ], 0 );

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
    public function record_classic( $order_id, $posted, $order ) {

        $this->record( $order );

    }

    /**
     * Block (Store API) checkout entry point.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     */
    public function record_store_api( $order ) {

        $this->record( $order );

    }

    /**
     * Refuse a blatant order on classic checkout, before it is created.
     *
     * Runs at the end of validation so nothing is persisted and no gateway is
     * ever contacted — the whole point of the rejected/banned risk levels.
     *
     * @since   1.9.0
     *
     * @param   array       $data   Checkout posted data.
     * @param   \WP_Error   $errors
     */
    public function refuse_classic( $data, $errors ) {

        if( ! response::is_enforcing() ) return;
        if( exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        $level = $this->level_with_identities( entities::for_checkout( $data ) );

        if( ! response::refuses( $level ) ) return;

        db::log_event(
            ip_utils::get_client_ip(),
            'risk_engine',
            'blocked',
            sprintf( 'Refused before order creation (%s): %s', $level, implode( '; ', risk_context::reasons() ) ),
            '',
            // No order id — a refusal happens before one exists, which is the
            // whole point of refusing there.
            0,
            risk_context::trust()
        );

        if( $level === risk_levels::BANNED ) $this->persist_ban();

        response::tarpit();

        $errors->add( 'mighty_shield_risk', response::refusal_message() );

    }

    /**
     * Refuse a blatant order on the Store API, before payment.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order           $order
     * @param   \WP_REST_Request    $request
     */
    public function refuse_store_api( $order, $request ) {

        if( ! response::is_enforcing() ) return;
        if( ! class_exists( '\Automattic\WooCommerce\StoreApi\Exceptions\RouteException' ) ) return;
        if( exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $level = $this->level_with_identities( entities::for_order( $order ) );

        if( ! response::refuses( $level ) ) return;

        db::log_event(
            ip_utils::get_client_ip(),
            'risk_engine',
            'blocked',
            sprintf( 'Refused before payment (%s): %s', $level, implode( '; ', risk_context::reasons() ) ),
            '',
            (int) $order->get_id(),
            risk_context::trust()
        );

        if( $level === risk_levels::BANNED ) $this->persist_ban();

        response::tarpit();

        throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
            'mighty_shield_risk',
            response::refusal_message(),
            400
        );

    }

    /**
     * Resolve the risk level from everything known before the order exists.
     *
     * The detectors have already emitted by this point; this adds the identity
     * history, which is available pre-order because entities are derived from
     * the submitted checkout fields rather than from a saved order.
     *
     * @since   1.9.0
     *
     * @param   array   $identities  type => normalized value, from entities::for_*().
     * @return  string
     */
    private function level_with_identities( $identities ) {

        if( ! empty( $identities ) ) entities::assess( $identities );

        return risk_context::evaluate()['risk_level'];

    }

    /**
     * Persist a ban so the next attempt is refused by the firewall, cheaply.
     *
     * @since   1.9.0
     */
    private function persist_ban() {

        $ip = ip_utils::get_client_ip();
        if( empty( $ip ) ) return;

        if( class_exists( '\MightyShield\Firewall\ip_blocklist' ) ) {
            \MightyShield\Firewall\ip_blocklist::add_ip( $ip, 'MightyShield', 'Banned by the risk engine' );
        }

    }

    /**
     * Start this order with an empty signal context.
     *
     * @since   2.0.0
     */
    public function begin() {

        risk_context::reset();

    }

    /**
     * Fetch and cache IP intelligence for this visitor.
     *
     * Fail-open and best-effort: a slow or unavailable provider must never
     * cost a shopper their checkout, so a miss simply leaves the network
     * signals unevaluated.
     *
     * @since   1.9.0
     */
    public function warm_ip_cache() {

        if( exempt::is_exempt( isset( $_POST['billing_email'] ) ? sanitize_email( wp_unslash( $_POST['billing_email'] ) ) : '' ) ) return;

        $ip = ip_utils::get_client_ip();
        if( empty( $ip ) ) return;

        // Already cached — nothing to do, and no network call.
        if( db::get_ip_data( $ip ) ) return;

        ip_data::get_or_fetch( $ip );

    }

    /**
     * Add the late signals and persist the verdict.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     */
    private function record( $order ) {

        if( ! is_object( $order ) || ! method_exists( $order, 'get_id' ) ) return;

        $order_id = $order->get_id();
        if( isset( $this->recorded[ $order_id ] ) ) return;
        $this->recorded[ $order_id ] = true;

        if( exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        // Identity history — the signals that only memory can provide.
        $identities = entities::for_order( $order );

        if( ! empty( $identities ) ) {
            entities::assess( $identities );
            entities::record( $identities, $order_id );
        }

        // Network intelligence.
        $this->assess_ip( $order );

        $verdict = risk_context::evaluate();

        $enforcing = response::is_enforcing();

        // What the level is configured to do, then what this order's gateway
        // can actually do about it. They differ when a fallback kicks in, and
        // it is the resolved one that gets recorded — a report saying
        // "authorized and held" for an order the processor could only flag
        // would be worse than no report.
        $chosen   = risk_levels::action( $verdict['risk_level'] );
        $resolved = $enforcing ? actions::resolve( $chosen, $order ) : $chosen;

        // Settle the reject-to-hold fallback BEFORE anything is written down.
        //
        // Rejection happens at validation, before an order exists, so it cannot
        // be carried out from here. An order that only reaches "rejected" once
        // it exists — a late signal, an AI verdict — is held instead, because
        // failing towards "stopped" is the safe direction.
        //
        // This used to happen after save_risk(), so the row claimed
        // action_taken=reject for an order that was actually held, and the
        // report disagreed with the order in front of it.
        if( $enforcing && $resolved === actions::REJECT ) $resolved = actions::HOLD_UNPAID;

        // Persist BEFORE acting. The hold-before-payment action terminates the
        // request on classic checkout to stop WooCommerce reaching the payment
        // branch, so anything written after it would never run.
        db::save_risk( $order_id, [
            'trust'             => $verdict['trust'],
            'risk_level'        => $verdict['risk_level'],
            'risk_level_source' => $verdict['risk_level_source'],
            'action_taken'      => $enforcing ? $resolved : 'observed',
            'signals'           => risk_context::to_array()['signals'],
        ] );

        // Mirrored onto the order so the risk level is visible in the admin without
        // a join, and so the review queue can sort on it.
        $order->update_meta_data( '_mshield_risk_trust', $verdict['trust'] );
        $order->update_meta_data( '_mshield_risk_level', $verdict['risk_level'] );
        $order->save();

        // Only note the order when there is something worth reading. A clean
        // order does not need a "nothing was wrong" note on every checkout.
        if( risk_levels::rank( $verdict['risk_level'] ) >= risk_levels::rank( risk_levels::ELEVATED ) ) {

            $order->add_order_note( sprintf(
                'MightyShield: trust rating %s/100 → %s (%s). Signals: %s.%s',
                $verdict['trust'],
                risk_levels::label( $verdict['risk_level'] ),
                $verdict['risk_level_source'],
                implode( '; ', risk_context::reasons() ),
                $enforcing ? '' : ' No action taken — scoring is in observation mode.'
            ) );

        }

        if( ! $enforcing ) return;

        if( $resolved === actions::NONE ) return;

        $reason = sprintf(
            'Trust rating %s/100 → %s (%s). Signals: %s.',
            $verdict['trust'],
            risk_levels::label( $verdict['risk_level'] ),
            $verdict['risk_level_source'],
            implode( '; ', risk_context::reasons() )
        );

        // Everything here runs on the order-processed hook, which fires before
        // the gateway is charged — so a 3DS request or an authorize-only filter
        // is in place by the time the payment intent is created.
        //
        // dispatch() picks the right mechanism for hold-before-payment: classic
        // can terminate the request, a REST route cannot. See class-response
        // for why neither can simply let WooCommerce skip payment.
        response::dispatch( $order, $resolved, $reason );

    }


    /**
     * Emit the network signals for this order's IP.
     *
     * Reads the cache only — the fetch already happened in warm_ip_cache() on
     * an earlier hook, so this never makes a blocking call.
     *
     * The implementation lives on rescore, which needs the same ten lines to
     * rate an order after the fact. It was private here, so the only way to
     * reuse it was to copy it — and a second copy of "what counts as a
     * datacenter IP" is exactly the kind of duplicate that drifts.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     */
    private function assess_ip( $order ) {

        rescore::assess_ip( $order );

    }

}
