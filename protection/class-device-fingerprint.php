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
use MightyShield\Includes\risk_context;
use MightyShield\Includes\response;

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

        // Render once per request even if the billing form is re-rendered (some
        // one-page-checkout plugins render it repeatedly), to avoid duplicate IDs.
        static $done = false;
        if( $done ) return;
        $done = true;

        // Enqueue here (not on wp_enqueue_scripts + is_checkout, which misses
        // shortcode / one-page checkouts) so the collector always loads wherever
        // the checkout billing form actually renders.
        $this->enqueue_scripts();

        echo '<input type="hidden" name="mshield_device_data" id="mshield_device_data" value="" />';

    }

    /**
     * Enqueue fingerprint collection script (idempotent by handle).
     *
     * @since   1.0.0
     */
    public function enqueue_scripts() {

        wp_enqueue_script(
            'mshield-collect',
            MSHIELD_URI . 'assets/js/mshield-collect.js',
            [],
            MSHIELD_VERSION,
            // Header, not footer: the collector has to start watching for
            // interaction before the customer starts filling the form, or the
            // fields they typed into first look untouched.
            [ 'in_footer' => false ]
        );

        wp_enqueue_script(
            'mshield-fingerprint',
            MSHIELD_URI . 'assets/js/mshield-fingerprint.js',
            [ 'mshield-collect' ],
            MSHIELD_VERSION,
            [ 'in_footer' => true ]
        );

    }

    /**
     * Whether this request is a WooCommerce order-review refresh (not a real
     * place-order). MightyShield must never interfere with that AJAX cycle,
     * which one-page-checkout plugins lean on heavily.
     *
     * @since   1.7.0
     *
     * @return  bool
     */
    private static function is_review_refresh() {

        return defined( 'DOING_AJAX' ) && DOING_AJAX
            && isset( $_GET['wc-ajax'] )
            && sanitize_text_field( wp_unslash( $_GET['wc-ajax'] ) ) === 'update_order_review';

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

        if( self::is_review_refresh() ) return;

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

            $errors->add( 'mighty_shield_fingerprint', response::with_note( __( 'This order could not be processed. Please contact support.', 'mighty-shield' ) ) );
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

        \MightyShield\Includes\response::flag( $order, 'device_fingerprint', $reason, false, 'classic_checkout' );

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
            risk_context::add( 'device_missing', 'Device fingerprint missing (JS did not execute)' );
            return [ 'blockable' => $missing_blockable, 'temp_block' => false, 'reasons' => [ 'Device fingerprint missing (JS did not execute)' ] ];
        }

        $device = json_decode( $raw, true );
        if( ! is_array( $device ) ) {
            risk_context::add( 'device_missing', 'Device fingerprint data malformed' );
            return [ 'blockable' => $missing_blockable, 'temp_block' => false, 'reasons' => [ 'Device fingerprint data malformed' ] ];
        }

        // Genuine detections (webdriver, timezone mismatch, device velocity)
        // are strong enough to justify an IP temp-block.
        $res = self::evaluate_device( $device, $country );
        return [ 'blockable' => $res['blockable'], 'temp_block' => true, 'reasons' => $res['reasons'] ];

    }

    /**
     * Evaluate a decoded device fingerprint against the billing country.
     *
     * Reusable by classic checkout and the Store API (block) checkout. Covers
     * automated-browser detection, timezone/country mismatch, and device
     * velocity. Missing/malformed handling stays with the caller.
     *
     * @since   1.8.0
     *
     * @param   array   $device     Decoded fingerprint data.
     * @param   string  $country    Billing country code.
     * @return  array   [ 'blockable' => bool, 'reasons' => string[] ]
     */
    public static function evaluate_device( $device, $country ) {

        $reasons   = [];
        $blockable = false;

        // Bot detection: navigator.webdriver is true for Selenium/Puppeteer.
        if( isset( $device['webdriver'] ) && $device['webdriver'] === true ) {
            $reasons[] = 'Automated browser detected (webdriver=true)';
            $blockable = true;
            risk_context::add( 'device_automated', 'Automated browser detected (webdriver=true)' );
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
                $reason    = sprintf( 'Timezone/country mismatch: browser timezone "%s" does not match billing country %s', $timezone, $country );
                $reasons[] = $reason;
                $blockable = true;
                risk_context::add( 'device_tz_mismatch', $reason );
            }

        }

        // Environment and interaction checks. Both paths run through here, so
        // neither checkout can be used to dodge them.
        $res = self::evaluate_behaviour( $device );
        foreach( $res as $reason ) $reasons[] = $reason;

        // Device velocity — counts checkout attempts per device signature,
        // independent of IP, to catch VPN/IP-rotating attackers.
        $threshold = (int) settings::get( 'mshield_fingerprint_velocity_threshold' );
        if( $threshold > 0 ) {

            $signature = self::get_signature( $device );
            if( $signature !== '' ) {

                $count = db::check_rate_limit( $signature, 'fp_velocity' );

                if( $count > $threshold ) {
                    $reason    = sprintf( 'Device velocity exceeded: %d/%d checkouts from the same device signature', $count, $threshold );
                    $reasons[] = $reason;
                    $blockable = true;
                    risk_context::add( 'device_velocity', $reason );
                }

            }

        }

        return [ 'blockable' => $blockable, 'reasons' => $reasons ];

    }

    /**
     * Environment consistency and interaction checks.
     *
     * These emit into the risk context rather than returning a blockable
     * verdict. That is deliberate: every one of them has a legitimate
     * explanation on some real customer's device, so they belong in a score
     * that weighs them against everything else, not in a hard block.
     *
     * @since   1.9.0
     *
     * @param   array   $device     Decoded fingerprint data.
     * @return  string[]            Human-readable reasons, for the log.
     */
    public static function evaluate_behaviour( $device ) {

        $reasons = [];

        // A collector that failed to load tells us nothing about the shopper.
        if( ! empty( $device['degraded'] ) ) return $reasons;

        // --- Environment consistency -------------------------------------
        //
        // Any single value here can be spoofed. What is hard is making them
        // agree with each other, so only contradictions count.

        $tells = [];

        // Software rasterisers are what a browser falls back to with no GPU.
        $renderer = strtolower( (string) ( $device['webgl_renderer'] ?? '' ) );

        foreach( [ 'swiftshader', 'llvmpipe', 'mesa offscreen' ] as $needle ) {
            if( $renderer !== '' && strpos( $renderer, $needle ) !== false ) {
                $tells[] = sprintf( 'graphics rendered in software (%s)', $renderer );
                break;
            }
        }

        // A browser claiming to be Chrome should have window.chrome. Only
        // checked when the collector actually reported the field, and never on
        // mobile, where the UA strings are far less predictable.
        $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

        if( array_key_exists( 'has_chrome', $device )
            && $device['has_chrome'] === false
            && stripos( $ua, 'Chrome/' ) !== false
            && stripos( $ua, 'Mobile' ) === false
            && empty( $device['has_touch'] ) ) {
            $tells[] = 'claims to be Chrome but is missing what Chrome provides';
        }

        // A desktop reporting no CPU cores and no screen is not a real device.
        if( isset( $device['hardware_concurrency'] ) && (int) $device['hardware_concurrency'] === 0
            && isset( $device['screen_width'] ) && (int) $device['screen_width'] === 0 ) {
            $tells[] = 'reports no processor or screen';
        }

        if( ! empty( $tells ) ) {
            $reason = 'Browser environment is inconsistent with a real device: ' . implode( '; ', $tells );
            risk_context::add( 'device_headless', $reason );
            $reasons[] = $reason;
        }

        // --- Interaction --------------------------------------------------

        // Fields that gained a value with no event of any kind. The collector
        // only reports fields it saw start empty, so a late-loading script
        // cannot produce a false positive here.
        $scripted = array_filter( array_map( 'sanitize_text_field', (array) ( $device['scripted_fields'] ?? [] ) ) );

        if( count( $scripted ) >= 2 ) {

            $reason = sprintf(
                '%d checkout fields were filled without any typing, pasting or autofill (%s)',
                count( $scripted ),
                implode( ', ', array_slice( $scripted, 0, 5 ) )
            );

            risk_context::add( 'input_scripted', $reason );
            $reasons[] = $reason;

        }

        // No interaction of any kind. Skipped on touch devices, where a short
        // tap-and-submit genuinely produces very little.
        if( isset( $device['moves'], $device['keys'], $device['scrolls'] )
            && (int) $device['moves'] === 0
            && (int) $device['keys'] === 0
            && (int) $device['scrolls'] === 0
            && (int) $device['pastes'] === 0
            && empty( $device['has_touch'] ) ) {

            $reason = 'No mouse, keyboard, scroll or touch activity during checkout';
            risk_context::add( 'interaction_none', $reason );
            $reasons[] = $reason;

        }

        return $reasons;

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

        if( self::is_review_refresh() ) return;

        if( \MightyShield\Includes\exempt::is_exempt( isset( $_POST['billing_email'] ) ? sanitize_email( wp_unslash( $_POST['billing_email'] ) ) : '' ) ) return;

        $raw = isset( $_POST['mshield_device_data'] ) ? sanitize_text_field( wp_unslash( $_POST['mshield_device_data'] ) ) : '';
        if( empty( $raw ) ) return;

        $device = json_decode( $raw, true );
        if( ! is_array( $device ) ) return;

        self::record_device( $device );

    }

    /**
     * Increment the velocity counter for one decoded fingerprint.
     *
     * The read side of this counter lives in evaluate_device(), which both
     * checkouts already share. The write side was hooked to a classic-only
     * action, so on the block checkout device_velocity compared against a
     * number that never grew and could not fire. This is the shared write.
     *
     * @since   2.0.0
     *
     * @param   array   $device     Decoded fingerprint data.
     */
    public static function record_device( $device ) {

        if( ! is_array( $device ) ) return;

        // Zero switches the check off, so there is nothing worth counting.
        $threshold = (int) settings::get( 'mshield_fingerprint_velocity_threshold' );
        if( $threshold <= 0 ) return;

        $signature = self::get_signature( $device );
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
    private static function get_signature( $device ) {

        // Prefer the high-entropy signature the collector computes.
        //
        // The old signature was timezone + language + platform + screen size.
        // Thousands of ordinary customers share
        // "America/New_York|en-US|MacIntel|1920x1080", so counting checkouts
        // per signature both flagged real shoppers who happened to collide and
        // could be sidestepped by resizing a window. It identified a
        // demographic, not a device.
        if( ! empty( $device['signature'] ) ) {
            return md5( 'v2|' . sanitize_text_field( (string) $device['signature'] ) );
        }

        // Fallback for a degraded collector. Kept coarse on purpose — it is
        // better to under-identify than to invent precision that is not there.
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
