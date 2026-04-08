<?php
/**
 * Device Fingerprint.
 *
 * Collects browser metadata at checkout to detect automated browsers
 * and geographic mismatches with billing address.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;

class device_fingerprint {

    /**
     * Country-to-timezone prefix mapping.
     *
     * @since   1.0.0
     */
    private const COUNTRY_TZ_PREFIXES = [
        'US' => [ 'America/', 'Pacific/Honolulu' ],
        'CA' => [ 'America/' ],
        'GB' => [ 'Europe/' ],
        'AU' => [ 'Australia/' ],
        'NZ' => [ 'Pacific/Auckland', 'Pacific/Chatham' ],
        'DE' => [ 'Europe/' ],
        'FR' => [ 'Europe/' ],
        'IT' => [ 'Europe/' ],
        'ES' => [ 'Europe/' ],
        'NL' => [ 'Europe/' ],
        'JP' => [ 'Asia/Tokyo' ],
        'BR' => [ 'America/' ],
        'MX' => [ 'America/' ],
    ];

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        if( settings::get( 'mshield_fingerprint_enabled' ) !== 'yes' ) return;

        add_action( 'woocommerce_after_checkout_billing_form', [ $this, 'render_field' ] );
        add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'validate_fingerprint' ], 5, 2 );

    }

    /**
     * Render hidden field for fingerprint data.
     *
     * @since   1.0.0
     */
    public function render_field() {

        echo '<input type="hidden" name="mshield_device_data" id="mshield_device_data" value="" />';

    }

    /**
     * Enqueue fingerprint collection script on checkout.
     *
     * @since   1.0.0
     */
    public function enqueue_scripts() {

        if( ! is_checkout() ) return;

        wp_enqueue_script(
            'mshield-fingerprint',
            MSHIELD_URI . 'assets/js/mshield-fingerprint.js',
            [],
            MSHIELD_VERSION,
            [ 'in_footer' => true ]
        );

    }

    /**
     * Validate fingerprint data.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function validate_fingerprint( $data, $errors ) {

        $raw = isset( $_POST['mshield_device_data'] ) ? sanitize_text_field( wp_unslash( $_POST['mshield_device_data'] ) ) : '';
        $ip  = ip_utils::get_client_ip();

        // Missing fingerprint — JS didn't execute. Flag but don't block (could be JS-disabled user).
        if( empty( $raw ) ) {
            db::log_event( $ip, 'classic_checkout', 'flagged', 'Device fingerprint missing (JS did not execute)' );
            return;
        }

        $device = json_decode( $raw, true );
        if( ! is_array( $device ) ) {
            db::log_event( $ip, 'classic_checkout', 'flagged', 'Device fingerprint data malformed' );
            return;
        }

        // Bot detection: navigator.webdriver is true for Selenium/Puppeteer.
        if( isset( $device['webdriver'] ) && $device['webdriver'] === true ) {

            db::log_event( $ip, 'classic_checkout', 'blocked', 'Automated browser detected (webdriver=true)' );

            $duration = (int) settings::get( 'mshield_temp_block_duration' );
            set_transient( 'mshield_tempblock_' . md5( $ip ), true, $duration );

            $errors->add( 'mighty_shield_fingerprint', __( 'This order could not be processed. Please contact support.', 'mighty-shield' ) );
            return;

        }

        // Timezone vs. billing country mismatch.
        $country  = isset( $data['billing_country'] ) ? $data['billing_country'] : '';
        $timezone = isset( $device['timezone'] ) ? $device['timezone'] : '';

        if( ! empty( $country ) && ! empty( $timezone ) && isset( self::COUNTRY_TZ_PREFIXES[ $country ] ) ) {

            $prefixes = self::COUNTRY_TZ_PREFIXES[ $country ];
            $matches  = false;

            foreach( $prefixes as $prefix ) {
                if( strpos( $timezone, $prefix ) === 0 || $timezone === $prefix ) {
                    $matches = true;
                    break;
                }
            }

            if( ! $matches ) {
                db::log_event(
                    $ip,
                    'classic_checkout',
                    'flagged',
                    sprintf( 'Timezone/country mismatch: browser timezone "%s" does not match billing country %s', $timezone, $country )
                );
            }

        }

    }

}
