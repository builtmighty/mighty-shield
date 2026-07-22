<?php
/**
 * Device Fingerprint.
 *
 * Collects browser metadata at checkout to detect automated browsers
 * and geographic mismatches with billing address. Also rate-limits by
 * device signature to catch VPN/IP-rotating attackers.
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
        add_action( 'woocommerce_checkout_process', [ $this, 'record_velocity' ], 0 );
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'block_fingerprint' ], 5, 2 );
        add_action( 'woocommerce_checkout_order_processed', [ $this, 'flag_fingerprint' ], 5, 3 );

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
     * Block checkout on a suspicious fingerprint.
     *
     * Runs before order creation. Only active when the configured action is
     * "block". A missing/malformed fingerprint is blockable only when
     * mshield_fingerprint_missing_action is "block"; otherwise it is logged as
     * flagged (protecting legitimate JS-disabled shoppers).
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function block_fingerprint( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        if( settings::get( 'mshield_fingerprint_action' ) !== 'block' ) return;

        $country = isset( $data['billing_country'] ) ? $data['billing_country'] : '';
        $result  = $this->evaluate( $country );
        $ip      = ip_utils::get_client_ip();

        if( empty( $result['reasons'] ) ) return;

        if( $result['blockable'] ) {

            db::log_event( $ip, 'classic_checkout', 'blocked', implode( '; ', $result['reasons'] ) );

            // Only escalate to an IP-wide temp-block for strong signals, so a
            // false positive on missing data does not lock a shopper out.
            if( ! empty( $result['temp_block'] ) ) {
                $duration = (int) settings::get( 'mshield_temp_block_duration' );
                set_transient( 'mshield_tempblock_' . md5( $ip ), true, $duration );
            }

            $errors->add( 'mighty_shield_fingerprint', __( 'This order could not be processed. Please contact support.', 'mighty-shield' ) );
            return;

        }

        // Non-blockable signals (e.g. missing/malformed) — record only.
        db::log_event( $ip, 'classic_checkout', 'flagged', implode( '; ', $result['reasons'] ) );

    }

    /**
     * Flag an order on a suspicious fingerprint.
     *
     * Runs after order creation. Active when the configured action is "flag"
     * or "notify".
     *
     * @since   1.0.0
     *
     * @param   int     $order_id   Order ID.
     * @param   array   $posted     Posted data.
     * @param   object  $order      WC_Order object.
     */
    public function flag_fingerprint( $order_id, $posted, $order ) {

        if( \MightyShield\Includes\exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $action = settings::get( 'mshield_fingerprint_action' );
        if( $action === 'block' ) return;

        $country = $order->get_billing_country();
        $result  = $this->evaluate( $country );

        if( empty( $result['reasons'] ) ) return;

        $ip     = ip_utils::get_client_ip();
        $reason = implode( '; ', $result['reasons'] );

        db::log_event( $ip, 'classic_checkout', 'flagged', $reason );
        $order->add_order_note( 'MightyShield: ' . $reason );
        $order->update_meta_data( '_mshield_flagged', 'device_fingerprint' );
        $order->save();

        if( $action === 'notify' ) {
            $this->send_admin_notification( $order, $reason );
        }

    }

    /**
     * Evaluate the submitted device fingerprint.
     *
     * @since   1.0.0
     *
     * @param   string  $country    Billing country code.
     * @return  array   [ 'blockable' => bool, 'reasons' => string[] ]
     */
    private function evaluate( $country ) {

        $reasons   = [];
        $blockable = false;

        $raw = isset( $_POST['mshield_device_data'] ) ? sanitize_text_field( wp_unslash( $_POST['mshield_device_data'] ) ) : '';

        // Missing/malformed fingerprint means the browser never ran our JS — the
        // signature of a non-interactive (scripted) checkout. Whether that is
        // blockable is governed by mshield_fingerprint_missing_action: "flag"
        // (default, accommodates rare no-JS shoppers) or "block" (recommended
        // when under active card-testing attack, since real payment already
        // requires JS via the gateway's tokenization script).
        $missing_blockable = ( settings::get( 'mshield_fingerprint_missing_action' ) === 'block' );

        // Missing fingerprint — JS didn't execute. Reject the order when
        // configured to block, but do NOT set an IP temp-block: this is a
        // weaker signal, and a false positive should not lock a real shopper
        // out for hours.
        if( empty( $raw ) ) {
            return [ 'blockable' => $missing_blockable, 'temp_block' => false, 'reasons' => [ 'Device fingerprint missing (JS did not execute)' ] ];
        }

        $device = json_decode( $raw, true );
        if( ! is_array( $device ) ) {
            return [ 'blockable' => $missing_blockable, 'temp_block' => false, 'reasons' => [ 'Device fingerprint data malformed' ] ];
        }

        // Bot detection: navigator.webdriver is true for Selenium/Puppeteer.
        if( isset( $device['webdriver'] ) && $device['webdriver'] === true ) {
            $reasons[]  = 'Automated browser detected (webdriver=true)';
            $blockable  = true;
        }

        // Timezone vs. billing country mismatch.
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
                $reasons[] = sprintf( 'Timezone/country mismatch: browser timezone "%s" does not match billing country %s', $timezone, $country );
                $blockable = true;
            }

        }

        // Device velocity — counts checkout attempts per device signature,
        // independent of IP, to catch VPN/IP-rotating attackers.
        $threshold = (int) settings::get( 'mshield_fingerprint_velocity_threshold' );
        if( $threshold > 0 ) {

            $signature = $this->get_signature( $device );
            if( $signature !== '' ) {

                $count = db::check_rate_limit( $signature, 'fp_velocity' );

                if( $count > $threshold ) {
                    $reasons[] = sprintf( 'Device velocity exceeded: %d/%d checkouts from the same device signature', $count, $threshold );
                    $blockable = true;
                }

            }

        }

        // Genuine detections (webdriver, timezone mismatch, device velocity)
        // are strong enough to justify an IP temp-block.
        return [ 'blockable' => $blockable, 'temp_block' => true, 'reasons' => $reasons ];

    }

    /**
     * Record a checkout attempt against the device velocity counter.
     *
     * Called once per checkout submission so the counter reflects real
     * attempts. Kept separate from evaluate() so the read-only evaluation can
     * run on both the block and flag hooks without double-counting.
     *
     * @since   1.0.0
     */
    public function record_velocity() {

        if( \MightyShield\Includes\exempt::is_exempt( isset( $_POST['billing_email'] ) ? sanitize_email( wp_unslash( $_POST['billing_email'] ) ) : '' ) ) return;

        $threshold = (int) settings::get( 'mshield_fingerprint_velocity_threshold' );
        if( $threshold <= 0 ) return;

        $raw = isset( $_POST['mshield_device_data'] ) ? sanitize_text_field( wp_unslash( $_POST['mshield_device_data'] ) ) : '';
        if( empty( $raw ) ) return;

        $device = json_decode( $raw, true );
        if( ! is_array( $device ) ) return;

        $signature = $this->get_signature( $device );
        if( $signature === '' ) return;

        $window = (int) settings::get( 'mshield_rate_checkout_window' );
        db::increment_rate_limit( $signature, 'fp_velocity', $window );

    }

    /**
     * Build a stable, IP-independent device signature.
     *
     * @since   1.0.0
     *
     * @param   array   $device     Decoded fingerprint data.
     * @return  string  MD5 signature, or '' if insufficient data.
     */
    private function get_signature( $device ) {

        $parts = [
            isset( $device['timezone'] ) ? $device['timezone'] : '',
            isset( $device['language'] ) ? $device['language'] : '',
            isset( $device['platform'] ) ? $device['platform'] : '',
            ( isset( $device['screen_width'] ) ? $device['screen_width'] : '' ) . 'x' . ( isset( $device['screen_height'] ) ? $device['screen_height'] : '' ),
        ];

        $joined = implode( '|', $parts );

        // Require at least some real data to avoid collapsing empty fingerprints
        // into one shared signature.
        if( trim( str_replace( [ '|', 'x' ], '', $joined ) ) === '' ) return '';

        return md5( $joined );

    }

    /**
     * Send admin notification email.
     *
     * @since   1.0.0
     *
     * @param   object  $order  WC_Order object.
     * @param   string  $reason Reason for flagging.
     */
    private function send_admin_notification( $order, $reason ) {

        $admin_email = get_option( 'admin_email' );
        $subject     = sprintf( '[MightyShield] Suspicious device on order #%d', $order->get_id() );
        $message     = sprintf(
            "A suspicious device fingerprint was detected by MightyShield.\n\nOrder: #%d\nReason: %s\nCustomer: %s (%s)\nIP: %s\n\nReview this order: %s",
            $order->get_id(),
            $reason,
            $order->get_formatted_billing_full_name(),
            $order->get_billing_email(),
            $order->get_customer_ip_address(),
            $order->get_edit_order_url()
        );

        wp_mail( $admin_email, $subject, $message );

    }

}
