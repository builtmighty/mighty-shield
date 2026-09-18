<?php
/**
 * Store API checkout protection (block-based checkout).
 *
 * The WooCommerce Checkout block submits through the Store API, which does not
 * fire the classic checkout hooks the other layers rely on. This adapter runs
 * the same server-side checks on that path, and like every other layer it only
 * scores: it emits signals and writes log rows, and refuses nothing. The one
 * thing that refuses is risk_recorder, at the end of the same hook.
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

        // Nothing on woocommerce_store_api_checkout_order_processed any more.
        // This class used to carry half its work over to that hook -- the flag
        // side of each layer's action setting, plus its own copy of velocity
        // tracking -- which put part of the score after the order existed.
        // Velocity now lives in velocity_detector for both checkouts, and
        // nothing here has anything left to say once an order has been created.

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

        // Both keys, not just the site key. Enqueueing on the site key alone
        // mints tokens that can never be checked, because there is no secret to
        // check them with. That no longer refuses anybody -- a blank secret now
        // reads as MISCONFIGURED, which costs an order nothing -- but it is
        // still a challenge doing no work while looking like it is, so the
        // widget stays away until both keys are in place. Everything else in
        // the plugin gates on is_ready(); this was the one place that did not.
        $ready = captcha::is_ready();

        if( $ready && $provider === 'recaptcha_v3' && $site_key !== '' ) {
            wp_enqueue_script( 'mshield-recaptcha', 'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $site_key ), [], null, [ 'in_footer' => true ] );
        }

        // Turnstile needs a visible widget, which is why it used to be
        // classic-only. The collector renders one into the checkout rather than
        // a Blocks component, which would need a build step this plugin does
        // not have.
        if( $ready && $provider === 'turnstile' && $site_key !== '' ) {
            wp_enqueue_script( 'mshield-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit', [], null, [ 'in_footer' => true ] );
        }

        // Header so it starts watching before the form is filled in.
        wp_enqueue_script( 'mshield-collect', MSHIELD_URI . 'assets/js/mshield-collect.js', [], \MightyShield\asset_version( 'assets/js/mshield-collect.js' ), [ 'in_footer' => false ] );
        wp_enqueue_script( 'mshield-blocks', MSHIELD_URI . 'assets/js/mshield-blocks.js', [ 'wp-data', 'mshield-collect' ], \MightyShield\asset_version( 'assets/js/mshield-blocks.js' ), [ 'in_footer' => true ] );
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
     * Pre-payment scoring for the block checkout.
     *
     * Named validate() because it runs on the Store API's validation hook, not
     * because it validates anything away -- it emits and returns.
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
        // Scored, not refused. A temp block is MightyShield's own inference and
        // it is keyed on an IP, which behind a carrier NAT, an office or a
        // campus is hundreds of unrelated people -- so it costs 60 trust, which
        // holds a first-time order on its own, and decides nothing by itself.
        if( rate_limiter::is_temp_blocked( $ip ) ) {
            risk_context::add( 'ip_temp_blocked', 'IP is under a temporary block' );
            db::log_event( $ip, 'store_api', 'flagged', 'Temporarily blocked IP' );
        }

        // Rate limit checkout attempts per IP. The count is what matters here;
        // the signal is worth 80 and the engine does the rest.
        $limit  = (int) settings::get( 'mshield_rate_checkout_limit' );
        $window = (int) settings::get( 'mshield_rate_checkout_window' );
        $count  = db::increment_rate_limit( md5( $ip . '|checkout' ), 'checkout', $window );
        if( $count > $limit ) {
            risk_context::add( 'rate_limited', "Checkout rate limit exceeded: {$count}/{$limit}" );
            db::log_event( $ip, 'store_api', 'rate_limited', "Checkout rate limit exceeded: {$count}/{$limit}" );
        }

        // Disposable email domain.
        if( ! empty( $email ) && email_domain_blocker::is_disposable_email( $email ) ) {
            $domain = strtolower( substr( strrchr( $email, '@' ), 1 ) );
            risk_context::add( 'email_disposable', "Disposable or blocked email domain: {$domain}" );
            db::log_event( $ip, 'store_api', 'flagged', "Disposable email domain: {$domain}" );
        }

        $data = $this->order_to_data( $order );

        // Everything here runs through each layer's own assess(), which is
        // where the signal is emitted, and does nothing else. What a signal is
        // worth is set on the Scoring tab; whether it stops the order is
        // risk_recorder's decision, made once, after all of this has run.
        //
        // These used to consult per-layer action settings and refuse here, and
        // the flag half of each ran after the order existed -- so the score
        // arrived in two pieces either side of the order, and the refusal
        // happened before half of it had been counted.

        // Score-based address validation.
        $addr = address_validator::assess( $data );
        if( (int) $addr['score'] > 0 ) db::log_event( $ip, 'store_api', 'flagged', $addr['reason'] );

        // Suspicious order amount.
        $amount = order_amount_validator::assess( (float) $order->get_total() );
        if( $amount !== null ) db::log_event( $ip, 'store_api', 'flagged', $amount );

        // ZIP/State mismatch.
        if( settings::get( 'mshield_zip_state_enabled' ) === 'yes' ) {

            $zres = zip_state_validator::assess( $order->get_billing_country(), $order->get_billing_state(), $order->get_billing_postcode() );

            if( $zres !== null ) db::log_event( $ip, 'store_api', 'flagged', $zres );

        }

        // USPS address verification. This check did not run on the block
        // checkout at all, so a store paying for Smarty was verifying only the
        // orders that came through the classic checkout, which on a Blocks
        // store is none of them.
        $smarty = smarty_address_verifier::assess( $data );
        if( $smarty !== null ) db::log_event( $ip, 'store_api', 'flagged', $smarty );

        // Front-end token layers (honeypot / timing / fingerprint / CAPTCHA).
        // They emit their own signals; what comes back is only the handful that
        // justify barring the address, which is a fact recorded about the
        // network rather than a decision about this order.
        foreach( $this->evaluate_token_layers( $order, $request ) as $trip ) {

            db::log_event( $ip, 'store_api', 'flagged', $trip['reason'] );

            if( ! empty( $trip['temp_block'] ) ) rate_limiter::temp_block_ip( $ip, $trip['reason'] );

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
     * Every layer emits its signal here. What comes back is only the subset
     * that warrants temp-blocking the address, for the caller to log and act
     * on — nothing in this method refuses anything.
     *
     * @param   \WC_Order          $order   Draft order.
     * @param   \WP_REST_Request   $request Store API request.
     * @return  array   List of [ 'layer','reason','temp_block' ] trips.
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

                $trips[] = [
                    'layer'      => 'timing',
                    'reason'     => $timing['reason'],
                    'temp_block' => ! empty( $timing['temp_block'] ),
                ];

            }

        }

        // Device fingerprint.
        if( settings::get( 'mshield_fingerprint_enabled' ) === 'yes' ) {

            $device = ! empty( $ext['dev'] ) ? json_decode( (string) $ext['dev'], true ) : null;

            // Absent or unreadable costs what it costs on the classic checkout.
            // Gating the whole branch on the payload being present made omitting
            // it free here and worth 20 there, so the same scripted order was
            // judged differently depending on which checkout it was pointed at
            // -- and the block one was always the softer target.
            if( ! is_array( $device ) ) {
                risk_context::add( 'device_missing', empty( $ext['dev'] )
                    ? 'Device fingerprint missing (JS did not execute)'
                    : 'Device fingerprint data malformed' );
            }

            if( is_array( $device ) ) {
                $res = device_fingerprint::evaluate_device( $device, $order->get_billing_country() );
                if( ! empty( $res['reasons'] ) ) {
                    $trips[] = [
                        'layer'      => 'fingerprint',
                        'reason'     => 'Device fingerprint: ' . implode( ', ', $res['reasons'] ),
                        'temp_block' => ! empty( $res['temp_block'] ),
                    ];
                }
            }
        }

        // Bot challenge. Both providers work here now: reCAPTCHA v3 needs no
        // widget, and Turnstile's is rendered into the page by the block
        // collector rather than by a Blocks component.
        //
        // An absent token no longer refuses anybody, but it is no longer free
        // either: it records the same "could not confirm" signal the classic
        // checkout records, so a blocked script or an ad blocker costs an order
        // a little trust while a scripted request that simply omits the field
        // stops being the cheapest way through.
        $provider = settings::get( 'mshield_captcha_provider' );

        if( \in_array( $provider, [ 'recaptcha_v3', 'turnstile' ], true ) ) {

            // The same call the classic checkout makes, rather than a second
            // implementation beside it. Going straight to judge() meant four
            // things the classic path does never happened here: the breaker was
            // read but never fed, a recovered configuration never cleared its own
            // warning, a challenge that was switched on but never rendered was
            // never reported, and an ABSENT token was skipped in silence -- so
            // the cheapest possible request produced no evidence at all, on the
            // one checkout where the payload is entirely attacker-chosen.
            //
            // The widget here is drawn by script whenever the keys are set, so
            // "was it shown" is answered by is_ready() rather than by a signed
            // marker, which the Store API has no way to carry.
            $verdict = captcha::assess_surface( 'checkout', isset( $ext['cap'] ) ? (string) $ext['cap'] : '', true );

            if( $verdict !== captcha::PASSED ) {

                $reason = sprintf(
                    /* translators: 1: provider, 2: plain explanation of the verdict. */
                    __( 'Bot challenge (%1$s): %2$s', 'mighty-shield' ),
                    $provider,
                    captcha::explain( $verdict )
                );

                // captcha_failed floors to Rejected and is only for the provider
                // positively saying "not a person" while the challenge is
                // demonstrably working. Everything else -- a spent token from a
                // shopper who pressed Place order twice, a blocked script, a
                // breaker that has given up on these keys -- costs trust and
                // refuses nobody.
                $signal = ( captcha::is_automation( $verdict ) && ! captcha::breaker_tripped( 'checkout' ) )
                    ? 'captcha_failed'
                    : 'captcha_unverified';

                if( captcha::is_automation( $verdict ) || captcha::is_unconfirmed( $verdict ) ) {
                    \MightyShield\Includes\risk_context::add( $signal, $reason );
                }

                db::log_event( ip_utils::get_client_ip(), 'store_api', 'flagged', $reason );

            }

        }

        return $trips;

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

}
