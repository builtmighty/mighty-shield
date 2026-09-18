<?php
/**
 * What happens to an order once it has a risk level.
 *
 * Scoring decides how bad an order looks. This decides what to do about it.
 * The two were fused until 1.9.1 — a level implied exactly one action, so
 * "hold this one but only authorize the card" was not expressible.
 *
 * Three of the seven depend on the store's environment rather than on a
 * setting: 3-D Secure and authorize-only need a payment gateway willing to do
 * them, and AI review needs a configured provider. Those are reported honestly
 * rather than silently doing nothing:
 *
 *   is_available()  can ANY active gateway do this — drives the admin.
 *   resolve()       can THIS order's gateway do this — drives dispatch, and
 *                   returns the fallback when it cannot.
 *
 * Every action either runs or degrades to a named fallback. None of them can
 * quietly no-op, because an action that silently does nothing is worse than one
 * that was never offered.
 *
 * @package MightyShield
 * @since   1.9.1
 */
namespace MightyShield\Includes;

class actions {

    const NONE            = 'none';
    const FLAG            = 'flag';
    const VERIFY_3DS      = 'verify_3ds';
    const HOLD_AUTHORIZED = 'hold_authorized';
    const HOLD_UNPAID     = 'hold_unpaid';
    const HOLD_PAID       = 'hold_paid';
    const REJECT          = 'reject';

    /**
     * The catalogue.
     *
     * Reject leads, then the rest run least to most disruptive. That looks
     * inconsistent written down and is right on the screen: declaration order
     * IS the order of the stepper on the Blocking tab, and refusing the
     * checkout outright is the step before "do nothing to it", not the step
     * after the three holds. The stepper runs "turn them away" to "let them
     * through", and the catalogue has to be written the way it is read.
     *
     * label     Shown in the admin.
     * desc      One plain sentence, shown on hover. Written for a shop owner.
     * money     What happens to the customer's money. Displayed, because it is
     *           the difference that actually matters between the three holds.
     * gateway   Whether the payment processor is contacted at all.
     * needs     Environment capability required, or '' when always available.
     * fallback  Action to run instead when `needs` is not met. '' when the
     *           action can always run.
     *
     * @since   1.9.1
     */
    const CATALOG = [

        self::REJECT => [
            'label'    => 'Reject',
            'desc'     => 'The checkout is refused before an order exists. The payment processor is never contacted and the customer sees a decline.',
            'money'    => 'Untouched',
            'gateway'  => false,
            'needs'    => '',
            'fallback' => '',
        ],

        self::NONE => [
            'label'    => 'No action',
            'desc'     => 'The order goes through untouched. It is still rated and recorded.',
            'money'    => 'Charged as normal',
            'gateway'  => true,
            'needs'    => '',
            'fallback' => '',
        ],

        self::FLAG => [
            'label'    => 'Flag for review',
            'desc'     => 'The order goes through and is marked for you to look at later. The customer notices nothing.',
            'money'    => 'Charged as normal',
            'gateway'  => true,
            'needs'    => '',
            'fallback' => '',
        ],

        self::VERIFY_3DS => [
            'label'    => '3-D Secure verification',
            'desc'     => 'The customer confirms the payment with their bank. Genuine cardholders pass; someone using a stolen card cannot, and liability for a dispute moves to the card issuer.',
            'money'    => 'Charged as normal, once verified',
            'gateway'  => true,
            'needs'    => '3ds',
            'fallback' => self::FLAG,
        ],

        self::HOLD_PAID => [
            'label'    => 'Take payment, then hold',
            'desc'     => 'The card is charged in full and the order is held before fulfilment. Releasing it ships; refusing it means refunding.',
            'money'    => 'Taken in full',
            'gateway'  => true,
            'needs'    => '',
            'fallback' => '',
        ],

        self::HOLD_AUTHORIZED => [
            'label'    => 'Authorize, then hold',
            'desc'     => 'The funds are reserved on the card but not taken, and the order is held. Releasing it captures the money; refusing it voids cleanly with nothing to refund.',
            'money'    => 'Reserved, not taken',
            'gateway'  => true,
            'needs'    => 'auth_only',
            'fallback' => self::HOLD_UNPAID,
        ],

        self::HOLD_UNPAID => [
            'label'    => 'Hold before payment',
            'desc'     => 'The order is created and held without contacting the payment processor at all. Nothing is charged, authorized, or counted against your merchant account.',
            'money'    => 'Untouched',
            'gateway'  => false,
            'needs'    => '',
            'fallback' => '',
        ],

    ];

    /**
     * Actions a risk level may be configured to take.
     *
     * Rejected and Banned are excluded from configuration entirely, so this is
     * every action.
     *
     * @since   1.9.1
     *
     * @return  string[]
     */
    public static function keys() {

        return array_keys( self::CATALOG );

    }

    /**
     * Whether an action key is real.
     *
     * @since   1.9.1
     *
     * @param   string  $action
     * @return  bool
     */
    public static function exists( $action ) {

        return isset( self::CATALOG[ $action ] );

    }

    /**
     * The human-readable label of an action.
     *
     * @since   1.9.1
     *
     * @param   string  $action
     * @return  string
     */
    public static function label( $action ) {

        return isset( self::CATALOG[ $action ] ) ? self::CATALOG[ $action ]['label'] : $action;

    }

    /**
     * The one-line explanation shown on hover.
     *
     * @since   1.9.1
     *
     * @param   string  $action
     * @return  string
     */
    public static function desc( $action ) {

        return isset( self::CATALOG[ $action ]['desc'] ) ? self::CATALOG[ $action ]['desc'] : '';

    }

    /**
     * What happens to the customer's money under this action.
     *
     * @since   1.9.1
     *
     * @param   string  $action
     * @return  string
     */
    public static function money( $action ) {

        return isset( self::CATALOG[ $action ]['money'] ) ? self::CATALOG[ $action ]['money'] : '';

    }

    /**
     * Whether this action lets the order reach the payment processor.
     *
     * Fails closed: an unknown action is assumed not to be safe to charge.
     *
     * @since   1.9.1
     *
     * @param   string  $action
     * @return  bool
     */
    public static function contacts_gateway( $action ) {

        if( ! isset( self::CATALOG[ $action ] ) ) return false;

        return (bool) self::CATALOG[ $action ]['gateway'];

    }

    /**
     * The capability an action needs, or '' when it always works.
     *
     * @since   1.9.1
     *
     * @param   string  $action
     * @return  string
     */
    public static function needs( $action ) {

        return isset( self::CATALOG[ $action ]['needs'] ) ? self::CATALOG[ $action ]['needs'] : '';

    }

    /**
     * What runs instead when the required capability is missing.
     *
     * @since   1.9.1
     *
     * @param   string  $action
     * @return  string  '' when the action needs no fallback.
     */
    public static function fallback( $action ) {

        return isset( self::CATALOG[ $action ]['fallback'] ) ? self::CATALOG[ $action ]['fallback'] : '';

    }

    /**
     * Whether any active gateway can perform this action.
     *
     * Store-wide, for the admin. A store with both Stripe and a bank transfer
     * gateway reports 3-D Secure as available, because it is — for the orders
     * that go through Stripe. resolve() is what decides per order.
     *
     * @since   1.9.1
     *
     * @param   string  $action
     * @return  bool
     */
    public static function is_available( $action ) {

        $needs = self::needs( $action );

        if( $needs === '' ) return self::exists( $action );

        // Through gateways::supports(), never around it -- asking ai_capture
        // directly skipped the mshield_gateway_supports filter, so a gateway a
        // store had taught MightyShield about showed as capable on Payment and
        // was refused here.
        if( $needs === '3ds' || $needs === 'auth_only' ) return gateways::any_supports( $needs );

        // An unrecognised requirement is treated as unmet rather than met, so a
        // typo in the catalogue disables an action instead of promising one.
        return false;

    }

    /**
     * Whether one specific gateway can perform this action.
     *
     * @since   1.9.1
     *
     * @param   string  $action
     * @param   string  $gateway    Gateway ID.
     * @return  bool
     */
    public static function gateway_can( $action, $gateway ) {

        $needs = self::needs( $action );

        if( $needs === '' ) return self::exists( $action );
        if( $gateway === '' ) return false;

        if( $needs === '3ds' || $needs === 'auth_only' ) return gateways::supports( $needs, $gateway );

        return false;

    }

    /**
     * What is still available once the money has moved.
     *
     * The card checks answer after payment — the processor is the only source
     * for them and it speaks on a webhook — so the second scoring pass reaches
     * a verdict at a point where half the ladder is no longer physically
     * possible. Refusing needs there to be no order, authorizing needs the
     * charge not to have happened, and 3-D Secure needs something left to
     * verify.
     *
     * Rather than let dispatch() attempt one of those, each degrades to the
     * nearest thing that is still true. Holding a paid order is the honest
     * landing place for everything that would have stopped it: the money is
     * taken, the goods have not shipped, and a human decides.
     *
     * This is the same contract resolve() follows for gateway capability —
     * every action either runs or degrades to a named fallback, and none of
     * them may quietly do nothing.
     *
     * @since   2.2.0
     *
     * @param   string  $action
     * @return  string
     */
    public static function resolve_post_payment( $action ) {

        switch( $action ) {

            // Nothing to refuse, nothing to authorize, and detaining would
            // mean an unpaid hold on an order that is paid.
            case self::REJECT:
            case self::HOLD_UNPAID:
            case self::HOLD_AUTHORIZED:
                return self::HOLD_PAID;

            // Too late to ask the cardholder's bank anything.
            case self::VERIFY_3DS:
                return self::FLAG;

            case self::NONE:
            case self::FLAG:
            case self::HOLD_PAID:
                return $action;

        }

        // Unknown action: flag, the same floor resolve() falls back to. An
        // order somebody was told about is recoverable; one silently passed
        // over is not.
        return self::FLAG;

    }

    /**
     * The action that will actually run for this order.
     *
     * Follows the fallback chain until it reaches something this order's
     * gateway can do. Bounded by the catalogue size so a mis-edited catalogue
     * cannot loop forever.
     *
     * @since   1.9.1
     *
     * @param   string      $action
     * @param   \WC_Order   $order
     * @return  string
     */
    public static function resolve( $action, $order ) {

        if( ! self::exists( $action ) ) return self::FLAG;

        $gateway = is_a( $order, 'WC_Order' ) ? (string) $order->get_payment_method() : '';

        $seen = [];

        while( self::exists( $action ) && ! isset( $seen[ $action ] ) ) {

            $seen[ $action ] = true;

            if( self::gateway_can( $action, $gateway ) ) return $action;

            $next = self::fallback( $action );

            // Nothing to fall back to, and the gateway cannot do it. Flagging
            // is the honest floor: the order proceeds and someone is told.
            if( $next === '' ) return self::FLAG;

            $action = $next;

        }

        return self::FLAG;

    }

}
