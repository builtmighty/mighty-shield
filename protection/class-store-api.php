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
 * Front-end layers (honeypot, checkout timing, device fingerprint, CAPTCHA)
 * ride along in the Store API request as extension data. Turnstile's widget is
 * rendered into the page by the collector script rather than by a Blocks
 * component, which would require a build step this plugin does not have.
 *
 * @package MightyShield
 * @since   1.8.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\exempt;
use MightyShield\Includes\risk_context;
use MightyShield\Includes\ip_data;

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

        // Priority 0: the classic path warms the IP cache and counts the
        // device on woocommerce_checkout_process, which is a hook the Store API
        // never fires. Both have to happen before anything reads them, and
        // validate() below is the first thing that does.
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'prepare' ], 0, 2 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'validate' ], 20, 2 );
        add_action( 'woocommerce_store_api_checkout_order_processed', [ $this, 'flag' ], 20, 1 );

        // Front-end token layers on the block Checkout (honeypot/timing/
        // fingerprint/bot challenge) are carried in the Store API request as
        // extension data. Register the schema and enqueue the collector.
        if( did_action( 'woocommerce_blocks_loaded' ) ) {
            $this->register_extension();
        } else {
            add_action( 'woocommerce_blocks_loaded', [ $this, 'register_extension' ] );
        }
        add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_blocks' ] );

    }

    /**
     * Order-data trips carried from validate() to flag(). The checks run in
     * validate() so their signals land before the order is scored; the order
     * they annotate does not exist until flag().
     *
     * @since   2.0.0
     *
     * @var     array
     */
    private $post_trips = [];

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

        // Every key must be nullable: WooCommerce's request validator coerces
        // any key the client did not send to null and validates it against the
        // declared type, only skipping when 'null' is among the types. The
        // front-end sends only the keys for enabled layers (ct/dev/cap), so
        // without 'null' an omitted key throws "... is not of type string".
        $string = [ 'type' => [ 'string', 'null' ], 'context' => [ 'view', 'edit' ], 'readonly' => false ];

        woocommerce_store_api_register_endpoint_data( [
            'endpoint'        => 'checkout',
            'namespace'       => 'mightyshield',
            'data_callback'   => function() { return []; },
            'schema_callback' => function() use ( $string ) {
                // ct = checkout timing, dev = device fingerprint,
                // cap = CAPTCHA, hp = honeypot. Added in 1.9.0; the block checkout had no
                // honeypot before, because there is no server-rendered form to
                // put a decoy field into. The shared collector plants one.
                return [ 'ct' => $string, 'dev' => $string, 'cap' => $string, 'hp' => $string ];
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

        if( $provider === 'recaptcha_v3' && $site_key !== '' ) {
            wp_enqueue_script( 'mshield-recaptcha', 'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $site_key ), [], null, [ 'in_footer' => true ] );
        }

        // Turnstile needs a visible widget, which is why it used to be
        // classic-only. The collector renders one into the checkout rather than
        // a Blocks component, which would need a build step this plugin does
        // not have.
        if( $provider === 'turnstile' && $site_key !== '' ) {
            wp_enqueue_script( 'mshield-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit', [], null, [ 'in_footer' => true ] );
        }

        // Header so it starts watching before the form is filled in.
        wp_enqueue_script( 'mshield-collect', MSHIELD_URI . 'assets/js/mshield-collect.js', [], MSHIELD_VERSION, [ 'in_footer' => false ] );
        wp_enqueue_script( 'mshield-blocks', MSHIELD_URI . 'assets/js/mshield-blocks.js', [ 'wp-data', 'mshield-collect' ], MSHIELD_VERSION, [ 'in_footer' => true ] );
        wp_localize_script( 'mshield-blocks', 'mshieldBlocks', [
            'timing'      => settings::get( 'mshield_timing_enabled' ) === 'yes',
            'timingToken' => checkout_timing::generate_token(),
            'fingerprint' => settings::get( 'mshield_fingerprint_enabled' ) === 'yes',
            'recaptcha'   => ( $provider === 'recaptcha_v3' && $site_key !== '' ),
            'turnstile'   => ( $provider === 'turnstile' && $site_key !== '' ),
            'siteKey'     => $site_key,
            // The action string reCAPTCHA v3 signs the token with. It MUST come
            // from the same place the server verifies against, and that is
            // captcha::action_for(). This was the literal 'checkout' in the JS
            // while the server checked 'mshield_checkout', so verification could
            // never succeed -- and captcha_failed carries a Rejected floor, so
            // every block-checkout order would have been refused the moment
            // reCAPTCHA was switched on.
            'action'      => captcha::action_for( 'checkout' ),
        ] );

    }

    /**
     * Everything that has to happen before the order is scored.
     *
     * The classic checkout does this work on woocommerce_checkout_process,
     * which the Store API never fires. Runs at priority 0 so it lands ahead of
     * validate(), which is the first thing that reads what it writes.
     *
     * @since   2.0.0
     *
     * @param   \WC_Order          $order   Draft order.
     * @param   \WP_REST_Request   $request Store API request.
     */
    public function prepare( $order, $request ) {

        if( exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        $this->warm_ip_cache();
        $this->record_device( $request );

    }

    /**
     * Fetch and cache IP intelligence before anything scores the order.
     *
     * ip_proxy, ip_datacenter and ip_geo_mismatch all read the cache and skip
     * on a miss, which is deliberate: they must never make a network call from
     * inside the scoring pass. The classic path warms the cache for them on
     * woocommerce_checkout_process. Nothing warmed it here, so on the block
     * checkout those three signals could only fire for an address that some
     * earlier order had already paid to look up. In practice that meant never,
     * because a first-time attacker is exactly the case they exist for.
     *
     * Best effort. A miss leaves the three signals unevaluated, which is
     * precisely today's behaviour, so a slow provider costs evidence rather
     * than the sale.
     *
     * @since   2.0.0
     */
    private function warm_ip_cache() {

        $ip = ip_utils::get_client_ip();
        if( empty( $ip ) ) return;

        // Already cached — no network call. This also makes the repeat fires
        // of this hook (the block checkout PATCHes the draft order as the
        // shopper edits it) cost one indexed lookup rather than a request.
        if( db::get_ip_data( $ip ) ) return;

        ip_data::get_or_fetch( $ip );

    }

    /**
     * Count this checkout attempt against the device velocity counter.
     *
     * device_velocity compares a per-device-signature counter against a
     * threshold. Both checkouts share the read, inside evaluate_device(), but
     * the write was hooked to woocommerce_checkout_process and so ran on the
     * classic path only. On the block checkout the signal was reading a number
     * that never moved.
     *
     * @since   2.0.0
     *
     * @param   \WP_REST_Request   $request Store API request.
     */
    private function record_device( $request ) {

        if( settings::get( 'mshield_fingerprint_enabled' ) !== 'yes' ) return;

        // Count submissions, not edits. This hook fires again on every PATCH
        // the block checkout makes as the shopper changes their address or
        // shipping method, and counting those would walk a real customer into
        // their own velocity threshold. Classic guards the same way against
        // the order-review refresh.
        if( ! is_object( $request ) || ! method_exists( $request, 'get_method' ) ) return;
        if( strtoupper( (string) $request->get_method() ) !== 'POST' ) return;

        $ext = $this->extensions( $request );
        if( empty( $ext['dev'] ) ) return;

        $device = json_decode( (string) $ext['dev'], true );
        if( ! is_array( $device ) ) return;

        device_fingerprint::record_device( $device );

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

        // The order-data checks below all run through each layer's own
        // assess(), which is where the signal is emitted. This used to be a
        // second, hand-written copy of each check that acted on the answer
        // without ever recording it, so an order that was merely suspicious
        // scored nothing here and the same order scored against it on the
        // classic checkout. Emission is unconditional; the action settings
        // decide only whether the order is also refused.
        $this->post_trips = [];

        // Score-based address validation (always blocks, like classic).
        $addr = address_validator::assess( $data );
        if( $addr['blockable'] ) {
            db::log_event( $ip, 'store_api', 'blocked', $addr['reason'] );
            $this->block( __( 'Please verify your billing information and try again.', 'mighty-shield' ) );
        }

        // Suspicious order amount.
        $amount = order_amount_validator::assess( (float) $order->get_total() );
        if( $amount !== null ) {
            $action = settings::get( 'mshield_suspicious_amount_action' );
            if( $action === 'block' ) {
                db::log_event( $ip, 'store_api', 'blocked', $amount );
                $this->block( __( 'This order could not be processed. Please contact support.', 'mighty-shield' ) );
            }
            $this->post_trips[] = [ 'slug' => 'suspicious_amount', 'reason' => $amount, 'action' => $action ];
        }

        // ZIP/State mismatch.
        if( settings::get( 'mshield_zip_state_enabled' ) === 'yes' ) {

            $zres = zip_state_validator::assess( $order->get_billing_country(), $order->get_billing_state(), $order->get_billing_postcode() );

            if( $zres !== null ) {
                $action = settings::get( 'mshield_zip_state_action' );
                if( $action === 'block' ) {
                    db::log_event( $ip, 'store_api', 'blocked', $zres );
                    $this->block( __( 'Please verify your billing ZIP code and state.', 'mighty-shield' ) );
                }
                $this->post_trips[] = [ 'slug' => 'zip_state_mismatch', 'reason' => $zres, 'action' => $action ];
            }

        }

        // USPS address verification. This check did not run on the block
        // checkout at all, so a store paying for Smarty was verifying only the
        // orders that came through the classic checkout, which on a Blocks
        // store is none of them.
        $smarty = smarty_address_verifier::assess( $data );
        if( $smarty !== null ) {
            $action = settings::get( 'mshield_smarty_action' );
            if( $action === 'block' ) {
                db::log_event( $ip, 'store_api', 'blocked', $smarty );
                $this->block( __( 'Please verify your billing address and try again.', 'mighty-shield' ) );
            }
            $this->post_trips[] = [ 'slug' => 'smarty_address_invalid', 'reason' => $smarty, 'action' => $action ];
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
     * Honeypot and Turnstile both run here: the collector script plants the
     * decoy field and renders the Turnstile widget into the page, so neither
     * needs a Blocks component.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order          $order   Draft order.
     * @param   \WP_REST_Request   $request Store API request.
     * @return  array   List of [ 'layer','reason','action','temp_block' ] trips.
     */
    private function evaluate_token_layers( $order, $request ) {

        $ext   = $this->extensions( $request );
        $trips = [];

        // Honeypot. A value here means something filled a field that is
        // off-screen, aria-hidden and out of tab order — which a person using
        // the site cannot do.
        if( settings::get( 'mshield_honeypot_enabled' ) === 'yes' ) {

            $hp = isset( $ext['hp'] ) ? trim( (string) $ext['hp'] ) : '';

            if( $hp !== '' ) {

                $reason = 'Honeypot field filled (bot detected): "' . substr( sanitize_text_field( $hp ), 0, 100 ) . '"';

                risk_context::add( 'honeypot', 'Honeypot field filled (bot detected)' );

                $trips[] = [
                    'layer'      => 'honeypot',
                    'reason'     => $reason,
                    'action'     => settings::get( 'mshield_honeypot_action' ),
                    'temp_block' => true,
                ];

            }

        }

        // Checkout timing. The judgement, and the signals, live in the timing
        // class; only the read differs between the two checkouts. This used to
        // be a second copy that recorded nothing unless the missing-token
        // action was set to block, so on the default setting a scripted
        // checkout that never carried a token cost itself nothing at all.
        if( settings::get( 'mshield_timing_enabled' ) === 'yes' ) {

            $timing = checkout_timing::assess( isset( $ext['ct'] ) ? (string) $ext['ct'] : '' );

            if( $timing['reason'] !== null ) {

                // Two settings, two jobs, same as classic. mshield_timing_action
                // says what a trip does; mshield_timing_missing_action says
                // whether a missing token is strong enough to be one. A missing
                // token under the default setting is still recorded, it simply
                // does not refuse the order.
                $action = settings::get( 'mshield_timing_action' );
                if( $action === 'block' && ! $timing['blockable'] ) $action = 'flag';

                $trips[] = [
                    'layer'      => 'timing',
                    'reason'     => $timing['reason'],
                    'action'     => $action,
                    'temp_block' => ! empty( $timing['temp_block'] ),
                ];

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

        // Bot challenge. Both providers work here now: reCAPTCHA v3 needs no
        // widget, and Turnstile's is rendered into the page by the block
        // collector rather than by a Blocks component.
        //
        // An empty token is treated as a skip, so a blocked third-party script,
        // a failed enqueue or an ad blocker never locks out every
        // block-checkout shopper. That is the same fail-open every other
        // external dependency in this plugin uses.
        $provider = settings::get( 'mshield_captcha_provider' );

        if( \in_array( $provider, [ 'recaptcha_v3', 'turnstile' ], true ) ) {

            $token = isset( $ext['cap'] ) ? (string) $ext['cap'] : '';

            if( $token !== '' ) {

                $ok = captcha::verify( $provider, settings::get( 'mshield_captcha_secret_key' ), $token, captcha::action_for( 'checkout' ) );

                if( ! $ok ) {

                    $reason = sprintf( 'Bot challenge failed (%s)', $provider );

                    // The signal is the whole outcome. No trip: captcha_failed
                    // floors to Rejected, so adding a per-layer block action on
                    // top was a second route to the same refusal -- and one that
                    // ignored the enforcement mode the rest of the ladder obeys.
                    \MightyShield\Includes\risk_context::add( 'captcha_failed', $reason );

                    db::log_event( ip_utils::get_client_ip(), 'store_api', 'flagged', $reason );

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

        // Order-data trips (amount, ZIP/state, address verification). These
        // were judged in validate(), where their signals could still reach the
        // score. Re-running them here would be a second call into a paid API
        // for Smarty and, because risk_context is first-write-wins, would
        // record nothing new anyway.
        foreach( $this->post_trips as $trip ) {
            if( $trip['action'] !== 'block' ) {
                $this->flag_order( $order, $trip['slug'], $trip['reason'], $trip['action'] );
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

        \MightyShield\Includes\response::flag( $order, $slug, $reason, false, 'store_api' );

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
     * Read this plugin's slice of the Store API request extension data.
     *
     * @since   2.0.0
     *
     * @param   \WP_REST_Request   $request Store API request.
     * @return  array
     */
    private function extensions( $request ) {

        if( ! isset( $request['extensions'] ) || ! is_array( $request['extensions'] ) ) return [];
        if( ! isset( $request['extensions']['mightyshield'] ) ) return [];

        return (array) $request['extensions']['mightyshield'];

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
     * The merchant's contact note is appended here rather than at each caller.
     * On the classic checkout each layer wraps its own message at the
     * $errors->add() site; this is the one place every block-checkout refusal
     * passes through, so wrapping here is the same guarantee in one line.
     *
     * @since   1.8.0
     *
     * @param   string  $message
     */
    private function block( $message ) {

        throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
            'mighty_shield_blocked',
            \MightyShield\Includes\response::with_note( $message ),
            400
        );

    }

}
