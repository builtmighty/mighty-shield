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
        $this->load_class( \MightyShield\Protection\device_fingerprint::class );

        // Admin.
        if( is_admin() ) {
            $this->load_class( \MightyShield\Admin\admin_page::class );
        }

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
