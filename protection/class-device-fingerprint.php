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
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'assess_checkout' ], 5, 2 );

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
     * Score the device fingerprint. Runs before any order exists.
     *
     * The strongest thing this layer finds — navigator.webdriver — carries a
     * `rejected` floor of its own, so an openly automated browser is still
     * refused, by risk_recorder rather than here. Everything else is a cost:
     * a missing fingerprint is worth a little, because the JS-disabled shopper
     * and the scripted one look identical from the server.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object, unused — this layer does not refuse.
     */
    public function assess_checkout( $data, $errors ) {

        if( self::is_review_refresh() ) return;

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        $country = isset( $data['billing_country'] ) ? $data['billing_country'] : '';
        $result  = $this->evaluate( $country );
        $ip      = ip_utils::get_client_ip();

        if( empty( $result['reasons'] ) ) return;

        db::log_event( $ip, 'classic_checkout', 'flagged', implode( '; ', $result['reasons'] ) );

        // Only a genuine detection escalates to an IP-wide temp-block. Missing
        // data never does, so a shopper with JS off is not locked out for hours.
        if( ! empty( $result['temp_block'] ) ) {
            // Through rate_limiter, not by hand. The hand-rolled version
            // stored a bare true with no reason and wrote no log entry, so
            // three of the four ways a shopper gets temporarily blocked left
            // nothing in the Logs at all -- and "why can this customer not
            // check out" is the first question a merchant asks.
            rate_limiter::temp_block_ip( $ip, __( 'Browser reported itself as automated', 'mighty-shield' ) );
        }

    }

    /**
     * Evaluate the submitted device fingerprint.
     *
     * @since   1.0.0
     *
     * @param   string  $country    Billing country code.
     * @return  array   [ 'temp_block' => bool, 'reasons' => string[] ]
     */
    private function evaluate( $country ) {

        $raw = isset( $_POST['mshield_device_data'] ) ? sanitize_text_field( wp_unslash( $_POST['mshield_device_data'] ) ) : '';

        // Missing/malformed fingerprint means the browser never ran our JS — the
        // signature of a non-interactive checkout, and also of the rare shopper
        // with JS off or an extension that ate the field. It costs trust and it
        // never blocks an address, because those two are indistinguishable from
        // here.
        if( empty( $raw ) ) {
            risk_context::add( 'device_missing', 'Device fingerprint missing (JS did not execute)' );
            return [ 'temp_block' => false, 'reasons' => [ 'Device fingerprint missing (JS did not execute)' ] ];
        }

        $device = json_decode( $raw, true );
        if( ! is_array( $device ) ) {
            risk_context::add( 'device_missing', 'Device fingerprint data malformed' );
            return [ 'temp_block' => false, 'reasons' => [ 'Device fingerprint data malformed' ] ];
        }

        return self::evaluate_device( $device, $country );

    }

    /**
     * Evaluate a decoded device fingerprint against the billing country.
     *
     * Reusable by classic checkout and the Store API (block) checkout. Covers
     * automated-browser detection, timezone/country mismatch, and device
     * velocity. Missing/malformed handling stays with the caller.
     *
     * temp_block says whether what was found is unambiguous enough to bar the
     * address for everyone behind it, which on a carrier NAT, an office or a
     * campus is hundreds of unrelated people. Only two things qualify: a
     * browser that declares itself automated, and a device signature seen more
     * times than the merchant allows. A timezone that disagrees with the
     * billing country does NOT -- that is a VPN, a traveller or an expat far
     * more often than a bot, and it used to lock all of them out, because the
     * default for this layer shipped set to refuse.
     *
     * @since   1.8.0
     *
     * @param   array   $device     Decoded fingerprint data.
     * @param   string  $country    Billing country code.
     * @return  array   [ 'temp_block' => bool, 'reasons' => string[] ]
     */
    public static function evaluate_device( $device, $country ) {

        $reasons    = [];
        $temp_block = false;

        // Bot detection: navigator.webdriver is true for Selenium/Puppeteer.
        if( isset( $device['webdriver'] ) && $device['webdriver'] === true ) {
            $reasons[]  = 'Automated browser detected (webdriver=true)';
            $temp_block = true;
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
                    $reason     = sprintf( 'Device velocity exceeded: %d/%d checkouts from the same device signature', $count, $threshold );
                    $reasons[]  = $reason;
                    $temp_block = true;
                    risk_context::add( 'device_velocity', $reason );
                }

            }

        }

        return [ 'temp_block' => $temp_block, 'reasons' => $reasons ];

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

}
