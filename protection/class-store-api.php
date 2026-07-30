<?php
/**
 * Store API checkout protection (block-based checkout).
 *
 * The WooCommerce Checkout block submits through the Store API, which does not
 * fire the classic checkout hooks the other layers rely on. This adapter runs
 * the server-side, order-data-driven fraud checks on the Store API checkout,
 * blocking (via RouteException) or flagging (order note/meta) per each layer's
 * existing settings.
 *
 * Front-end token layers (honeypot, checkout timing, device fingerprint,
 * CAPTCHA) require a Blocks front-end integration and are handled separately.
 *
 * @package MightyShield
 * @since   1.8.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\exempt;

class store_api {

    /**
     * Construct.
     *
     * @since   1.8.0
     */
    public function __construct() {

        if( settings::get( 'mshield_store_api_checks' ) !== 'yes' ) return;

        // The Store API extension hooks and RouteException must exist.
        if( ! class_exists( '\Automattic\WooCommerce\StoreApi\Exceptions\RouteException' ) ) return;

        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'validate' ], 20, 2 );
        add_action( 'woocommerce_store_api_checkout_order_processed', [ $this, 'flag' ], 20, 1 );

        // Front-end token layers on the block Checkout (honeypot/timing/
        // fingerprint/reCAPTCHA v3) are carried in the Store API request as
        // extension data. Register the schema and enqueue the collector.
        if( did_action( 'woocommerce_blocks_loaded' ) ) {
            $this->register_extension();
        } else {
            add_action( 'woocommerce_blocks_loaded', [ $this, 'register_extension' ] );
        }
        add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_blocks' ] );

    }

    /**
     * Trips carried over from validate() to flag() within one request (the
     * Store API order-processed action does not receive the request object).
     *
     * @since   1.8.0
     */
    private $token_trips = [];

    /**
     * Register the "mightyshield" checkout extension so our token data on the
     * Store API request is accepted and readable server-side.
     *
     * @since   1.8.0
     */
    public function register_extension() {

        if( ! function_exists( 'woocommerce_store_api_register_endpoint_data' ) ) return;

        $string = [ 'type' => 'string', 'context' => [], 'readonly' => false, 'optional' => true ];

        woocommerce_store_api_register_endpoint_data( [
            'endpoint'        => 'checkout',
            'namespace'       => 'mightyshield',
            'data_callback'   => function() { return []; },
            'schema_callback' => function() use ( $string ) {
                return [ 'hp' => $string, 'ct' => $string, 'dev' => $string, 'cap' => $string ];
            },
            'schema_type'     => ARRAY_A,
        ] );

    }

    /**
     * Enqueue the block-checkout collector script on the checkout page.
     *
     * @since   1.8.0
     */
    public function enqueue_blocks() {

        if( ! function_exists( 'is_checkout' ) || ! is_checkout() ) return;

        $provider = settings::get( 'mshield_captcha_provider' );
        $site_key = settings::get( 'mshield_captcha_site_key' );

        // reCAPTCHA v3 is the only script-based challenge that works without a
        // rendered widget; Turnstile needs a React block (not supported here).
        if( $provider === 'recaptcha_v3' && $site_key !== '' ) {
            wp_enqueue_script( 'mshield-recaptcha', 'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $site_key ), [], null, [ 'in_footer' => true ] );
        }

        wp_enqueue_script( 'mshield-blocks', MSHIELD_URI . 'assets/js/mshield-blocks.js', [ 'wp-data' ], MSHIELD_VERSION, [ 'in_footer' => true ] );
        wp_localize_script( 'mshield-blocks', 'mshieldBlocks', [
            'timing'      => settings::get( 'mshield_timing_enabled' ) === 'yes',
            'timingToken' => checkout_timing::generate_token(),
            'fingerprint' => settings::get( 'mshield_fingerprint_enabled' ) === 'yes',
            'recaptcha'   => ( $provider === 'recaptcha_v3' && $site_key !== '' ),
            'siteKey'     => $site_key,
        ] );

    }

    /**
     * Pre-payment validation — blocks the order via RouteException on failure.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order          $order   Draft order.
     * @param   \WP_REST_Request   $request Store API request.
     */
    public function validate( $order, $request ) {

        $email = $order->get_billing_email();

        if( exempt::is_exempt( $email, $order->get_user_id() ) ) return;

        $ip = ip_utils::get_client_ip();

        // Temporary block (set by velocity / failed-payment / other layers).
        if( rate_limiter::is_temp_blocked( $ip ) ) {
            db::log_event( $ip, 'store_api', 'blocked', 'Temporarily blocked IP' );
            $this->block( __( 'Your access has been temporarily restricted. Please try again later.', 'mighty-shield' ) );
        }

        // Rate limit checkout attempts per IP.
        $limit  = (int) settings::get( 'mshield_rate_checkout_limit' );
        $window = (int) settings::get( 'mshield_rate_checkout_window' );
        $count  = db::increment_rate_limit( md5( $ip . '|checkout' ), 'checkout', $window );
        if( $count > $limit ) {
            db::log_event( $ip, 'store_api', 'rate_limited', "Checkout rate limit exceeded: {$count}/{$limit}" );
            $this->block( __( 'Too many checkout attempts. Please wait and try again later.', 'mighty-shield' ) );
        }

        // Disposable email domain (always blocks, like classic).
        if( ! empty( $email ) && email_domain_blocker::is_disposable_email( $email ) ) {
            db::log_event( $ip, 'store_api', 'blocked', 'Disposable email domain' );
            $this->block( __( 'Please use a valid, non-disposable email address.', 'mighty-shield' ) );
        }

        $data = $this->order_to_data( $order );

        // Score-based address validation (always blocks, like classic).
        $result = address_validator::score_address( $data );
        if( $result['score'] >= address_validator::block_threshold() ) {
            db::log_event( $ip, 'store_api', 'blocked', 'Address validation failed (score: ' . $result['score'] . '): ' . implode( ', ', $result['signals'] ) );
            $this->block( __( 'Please verify your billing information and try again.', 'mighty-shield' ) );
        }

        // Suspicious order amount (block mode only; flag handled post-order).
        $min = (float) settings::get( 'mshield_min_order_amount' );
        if( $min > 0 && (float) $order->get_total() < $min && settings::get( 'mshield_suspicious_amount_action' ) === 'block' ) {
            db::log_event( $ip, 'store_api', 'blocked', 'Suspicious order amount below minimum' );
            $this->block( __( 'This order could not be processed. Please contact support.', 'mighty-shield' ) );
        }

        // ZIP/State mismatch (block mode only; flag handled post-order).
        if( settings::get( 'mshield_zip_state_enabled' ) === 'yes' && settings::get( 'mshield_zip_state_action' ) === 'block' && $order->get_billing_country() === 'US' ) {
            $zres = zip_state_validator::verify_zip_state( $order->get_billing_state(), $order->get_billing_postcode() );
            if( $zres !== true && $zres !== null ) {
                db::log_event( $ip, 'store_api', 'blocked', $zres );
                $this->block( __( 'Please verify your billing ZIP code and state.', 'mighty-shield' ) );
            }
        }

        // Front-end token layers (timing / fingerprint / CAPTCHA). Computed
        // once here — the request object is not available in flag() — and
        // stashed so the flag-action trips can be applied post-order.
        $this->token_trips = $this->evaluate_token_layers( $order, $request );
        foreach( $this->token_trips as $trip ) {
            if( $trip['action'] === 'block' ) {
                db::log_event( $ip, 'store_api', 'blocked', $trip['reason'] );
                if( ! empty( $trip['temp_block'] ) ) {
                    rate_limiter::temp_block_ip( $ip, $trip['reason'] );
                }
                $this->block( __( 'This order could not be processed. Please try again.', 'mighty-shield' ) );
            }
        }

    }

    /**
     * Evaluate the front-end token layers carried in the Store API request's
     * "mightyshield" extension data (timing, device fingerprint, reCAPTCHA v3).
     *
     * Honeypot is intentionally not enforced here: the React Checkout block
     * never renders our decoy field, so its absence carries no signal. Turnstile
     * likewise requires a rendered widget and is not supported on block checkout.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order          $order   Draft order.
     * @param   \WP_REST_Request   $request Store API request.
     * @return  array   List of [ 'layer','reason','action','temp_block' ] trips.
     */
    private function evaluate_token_layers( $order, $request ) {

        $ext   = ( isset( $request['extensions'] ) && is_array( $request['extensions'] ) && isset( $request['extensions']['mightyshield'] ) )
            ? (array) $request['extensions']['mightyshield'] : [];
        $trips = [];

        // Checkout timing.
        if( settings::get( 'mshield_timing_enabled' ) === 'yes' ) {
            $token   = isset( $ext['ct'] ) ? (string) $ext['ct'] : '';
            $elapsed = checkout_timing::verify_token( $token );
            $reason  = null;
            $temp    = false;

            if( $elapsed === null ) {
                // Missing/invalid token — governed by the same missing-action
                // setting as classic; default flag to avoid caching lockouts.
                if( settings::get( 'mshield_timing_missing_action' ) === 'block' ) {
                    $reason = 'Checkout timing token missing or invalid';
                }
            } else {
                $mins = (int) settings::get( 'mshield_timing_min_seconds' );
                if( $elapsed < $mins ) {
                    $reason = sprintf( 'Checkout submitted too fast: %ds (minimum %ds) — likely automated', $elapsed, $mins );
                    $temp   = true;
                }
            }

            if( $reason !== null ) {
                $trips[] = [ 'layer' => 'timing', 'reason' => $reason, 'action' => settings::get( 'mshield_timing_action' ), 'temp_block' => $temp ];
            }
        }

        // Device fingerprint.
        if( settings::get( 'mshield_fingerprint_enabled' ) === 'yes' && ! empty( $ext['dev'] ) ) {
            $device = json_decode( (string) $ext['dev'], true );
            if( is_array( $device ) ) {
                $res = device_fingerprint::evaluate_device( $device, $order->get_billing_country() );
                if( ! empty( $res['blockable'] ) && ! empty( $res['reasons'] ) ) {
                    $trips[] = [
                        'layer'      => 'fingerprint',
                        'reason'     => 'Device fingerprint: ' . implode( ', ', $res['reasons'] ),
                        'action'     => settings::get( 'mshield_fingerprint_action' ),
                        'temp_block' => true,
                    ];
                }
            }
        }

        // reCAPTCHA v3 (Turnstile is not supported on block checkout). An empty
        // token is treated as a skip so a script/enqueue failure never locks out
        // every block-checkout shopper.
        if( settings::get( 'mshield_captcha_provider' ) === 'recaptcha_v3' ) {
            $token = isset( $ext['cap'] ) ? (string) $ext['cap'] : '';
            if( $token !== '' ) {
                $ok = captcha::verify( 'recaptcha_v3', settings::get( 'mshield_captcha_secret_key' ), $token );
                if( ! $ok ) {
                    $trips[] = [ 'layer' => 'captcha', 'reason' => 'CAPTCHA verification failed (recaptcha_v3)', 'action' => settings::get( 'mshield_captcha_action' ), 'temp_block' => false ];
                }
            }
        }

        return $trips;

    }

    /**
     * Post-order flagging + velocity tracking for the Store API checkout.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order  The created order.
     */
    public function flag( $order ) {

        $email = $order->get_billing_email();

        if( exempt::is_exempt( $email, $order->get_user_id() ) ) return;

        $ip = ip_utils::get_client_ip();

        // Suspicious order amount (flag / notify).
        $min    = (float) settings::get( 'mshield_min_order_amount' );
        $action = settings::get( 'mshield_suspicious_amount_action' );
        if( $min > 0 && (float) $order->get_total() < $min && $action !== 'block' ) {
            $this->flag_order( $order, 'suspicious_amount', 'Suspicious order amount below minimum', $action );
        }

        // ZIP/State mismatch (flag / notify).
        if( settings::get( 'mshield_zip_state_enabled' ) === 'yes' && $order->get_billing_country() === 'US' ) {
            $zaction = settings::get( 'mshield_zip_state_action' );
            if( $zaction !== 'block' ) {
                $zres = zip_state_validator::verify_zip_state( $order->get_billing_state(), $order->get_billing_postcode() );
                if( $zres !== true && $zres !== null ) {
                    $this->flag_order( $order, 'zip_state_mismatch', $zres, $zaction );
                }
            }
        }

        // Front-end token layers set to flag / notify (block trips already
        // aborted the request inside validate()).
        foreach( $this->token_trips as $trip ) {
            if( $trip['action'] !== 'block' ) {
                $this->flag_order( $order, 'token_' . $trip['layer'], $trip['reason'], $trip['action'] );
            }
        }

        // Velocity tracking (unique emails + order count per IP).
        $this->track_velocity( $ip, $email );

    }

    /**
     * Add a flag note/meta to an order, optionally emailing the admin.
     *
     * @since   1.8.0
     */
    private function flag_order( $order, $slug, $reason, $action ) {

        db::log_event( ip_utils::get_client_ip(), 'store_api', 'flagged', $reason );
        $order->add_order_note( 'MightyShield: ' . $reason );
        $order->update_meta_data( '_mshield_flagged', $slug );
        $order->save();

        if( $action === 'notify' ) {
            $admin_email = get_option( 'admin_email' );
            $subject     = sprintf( '[MightyShield] %s on order #%d', $reason, $order->get_id() );
            $message     = sprintf(
                "MightyShield flagged a block-checkout order.\n\nOrder: #%d\nReason: %s\nCustomer: %s (%s)\nIP: %s\n\nReview this order: %s",
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

    /**
     * Track unique-emails-per-IP and orders-per-IP velocity, temp-blocking the
     * IP when a threshold is exceeded (mirrors the classic velocity detector).
     *
     * @since   1.8.0
     */
    private function track_velocity( $ip, $email ) {

        if( ! empty( $email ) ) {
            $key    = 'mshield_emails_' . md5( $ip );
            $emails = get_transient( $key );
            if( ! is_array( $emails ) ) $emails = [];
            $hash = md5( strtolower( trim( $email ) ) );
            if( ! in_array( $hash, $emails, true ) ) $emails[] = $hash;
            set_transient( $key, $emails, HOUR_IN_SECONDS );

            $email_threshold = (int) settings::get( 'mshield_velocity_email_threshold' );
            if( count( $emails ) > $email_threshold ) {
                rate_limiter::temp_block_ip( $ip, "Velocity: {$email_threshold}+ unique emails in 1 hour" );
                return;
            }
        }

        $okey  = 'mshield_orders_' . md5( $ip );
        $count = (int) get_transient( $okey ) + 1;
        set_transient( $okey, $count, 15 * MINUTE_IN_SECONDS );

        $order_threshold = (int) settings::get( 'mshield_velocity_order_threshold' );
        if( $count > $order_threshold ) {
            rate_limiter::temp_block_ip( $ip, "Velocity: {$order_threshold}+ orders in 15 minutes" );
        }

    }

    /**
     * Map a WC_Order's billing fields to the array the checks expect.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @return  array
     */
    private function order_to_data( $order ) {

        return [
            'billing_email'      => $order->get_billing_email(),
            'billing_first_name' => $order->get_billing_first_name(),
            'billing_last_name'  => $order->get_billing_last_name(),
            'billing_address_1'  => $order->get_billing_address_1(),
            'billing_city'       => $order->get_billing_city(),
            'billing_state'      => $order->get_billing_state(),
            'billing_postcode'   => $order->get_billing_postcode(),
            'billing_country'    => $order->get_billing_country(),
            'billing_phone'      => $order->get_billing_phone(),
        ];

    }

    /**
     * Abort the Store API checkout with a customer-facing message.
     *
     * @since   1.8.0
     *
     * @param   string  $message
     */
    private function block( $message ) {

        throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
            'mighty_shield_blocked',
            $message,
            400
        );

    }

}
