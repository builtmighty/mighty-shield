<?php
/**
 * Initialize.
 *
 * Load all of our classes using a Singleton pattern.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield;
class Plugin {

    /**
     * Set instance(s).
     *
     * @since   1.0.0
     */
    private static $instance = null;
    private $instances = [];

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    private function __construct() {

        // Initiate classes.
        $this->init_classes();

    }

    /**
     * Get instance.
     *
     * @since   1.0.0
     */
    public static function get_instance() {

        // Set instance.
        if( self::$instance === null ) {

            // Set.
            self::$instance = new self();

        }

        // Return.
        return self::$instance;

    }

    /**
     * Initiate classes.
     *
     * @since   1.0.0
     */
    private function init_classes() {

        // Firewall.
        $this->load_class( \MightyShield\Firewall\api_firewall::class );
        $this->load_class( \MightyShield\Firewall\ip_blocklist::class );

        // Protection.
        $this->load_class( \MightyShield\Protection\rate_limiter::class );
        $this->load_class( \MightyShield\Protection\velocity_detector::class );
        $this->load_class( \MightyShield\Protection\failed_payment_tracker::class );
        $this->load_class( \MightyShield\Protection\email_domain_blocker::class );
        $this->load_class( \MightyShield\Protection\order_amount_validator::class );
        $this->load_class( \MightyShield\Protection\address_validator::class );
        $this->load_class( \MightyShield\Protection\zip_state_validator::class );
        $this->load_class( \MightyShield\Protection\smarty_address_verifier::class );
        $this->load_class( \MightyShield\Protection\honeypot::class );
        $this->load_class( \MightyShield\Protection\checkout_timing::class );
        $this->load_class( \MightyShield\Protection\device_fingerprint::class );
        $this->load_class( \MightyShield\Protection\cookie_check::class );
        $this->load_class( \MightyShield\Protection\captcha::class );

        // The same challenge on the surfaces that are not checkout: login,
        // registration, lost password, comments.
        $this->load_class( \MightyShield\Protection\challenge::class );
        $this->load_class( \MightyShield\Protection\store_api::class );

        // Whole-order checks: the ones that need the finished order to judge.
        // Ahead of the AI reviewer so its verdict is informed by them, and
        // ahead of the recorder so they count toward the level.
        $this->load_class( \MightyShield\Protection\order_signals::class );

        // Stage two. Reviews an order only after every deterministic check has
        // run, and only for the levels the merchant chose to spend calls on.
        $this->load_class( \MightyShield\Protection\ai_reviewer::class );

        // Phase 1 terminus. Records the scored verdict once every layer above
        // has emitted. Observation only — it takes no action on the order.
        $this->load_class( \MightyShield\Protection\risk_recorder::class );

        // Outcome learning. Records what actually happened to an order against
        // every identity on it, so the next decision has hindsight.
        $this->load_class( \MightyShield\Protection\outcomes::class );

        // Payment-instrument intelligence. Arrives post-payment via the
        // gateway's webhook stream, so it informs fulfilment and the next
        // order rather than this one's risk level.
        $this->load_class( \MightyShield\Protection\card_signals::class );

        // Each gateway adapter listens for whatever its processor exposes and
        // feeds card_signals in one normalised shape.
        \MightyShield\Includes\gateways::listen();

        // The doors either side of the checkout: the address someone used, and
        // what they were doing before they got here.
        $this->load_class( \MightyShield\Protection\email_intel::class );
        $this->load_class( \MightyShield\Protection\account_guard::class );

    }

    /**
     * Load class.
     *
     * @since   1.0.0
     *
     * @param   string  $class
     */
    private function load_class( $class ) {

        // Check if class exists.
        if( ! isset( $this->instances[$class] ) ) {

            // Set instance.
            $this->instances[$class] = new $class();

        }

    }

}
