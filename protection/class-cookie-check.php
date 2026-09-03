<?php
/**
 * Cookie Check.
 *
 * Scores a checkout that arrives carrying no cookies at all.
 *
 * A shopper cannot reach checkout without a cookie jar. WooCommerce sets a
 * session cookie the moment anything goes in the cart, and that session is what
 * the cart itself is stored against, so a browser that sends nothing either
 * threw the jar away between the cart and the checkout or never had one. The
 * second is what a scripted checkout looks like: it posts the form fields and
 * skips everything a browser would have kept.
 *
 * Read server-side rather than from the collector, because the cookie that
 * matters most is the one JavaScript cannot see. WooCommerce sets
 * wp_woocommerce_session_* HttpOnly, so document.cookie never reports it.
 *
 * Deliberately its own layer rather than part of the device fingerprint: that
 * one is switched off by default, and this check costs nothing to run and needs
 * no script on the page.
 *
 * @package MightyShield
 * @since   2.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\exempt;
use MightyShield\Includes\risk_context;

class cookie_check {

    /**
     * Construct.
     *
     * Priority 0 on both checkouts, alongside the other work that has to land
     * before anything scores the order. Two thin adapters over one shared
     * assess(), which is the shape every dual-path check in this plugin uses.
     *
     * @since   2.0.0
     */
    public function __construct() {

        add_action( 'woocommerce_checkout_process', [ $this, 'assess_classic' ], 0 );
        add_action( 'woocommerce_store_api_checkout_update_order_from_request', [ $this, 'assess_store_api' ], 0, 2 );

    }

    /**
     * Classic checkout adapter.
     *
     * @since   2.0.0
     */
    public function assess_classic() {

        $email = isset( $_POST['billing_email'] ) ? sanitize_email( wp_unslash( $_POST['billing_email'] ) ) : '';

        if( exempt::is_exempt( $email ) ) return;

        self::assess();

    }

    /**
     * Block (Store API) checkout adapter.
     *
     * @since   2.0.0
     *
     * @param   \WC_Order          $order   Draft order.
     * @param   \WP_REST_Request   $request Store API request.
     */
    public function assess_store_api( $order, $request ) {

        if( ! is_object( $order ) || ! method_exists( $order, 'get_billing_email' ) ) return;

        if( exempt::is_exempt( $order->get_billing_email(), $order->get_user_id() ) ) return;

        self::assess();

    }

    /**
     * Record a checkout that carried no cookies.
     *
     * Only a completely empty jar counts. Judging the *contents* would mean
     * guessing at which cookies a given store happens to set, which varies with
     * every plugin, theme and consent banner in play. Nothing at all is the one
     * state that means the same thing everywhere.
     *
     * @since   2.0.0
     *
     * @return  bool    Whether the signal was recorded.
     */
    public static function assess() {

        if( ! empty( $_COOKIE ) ) return false;

        return risk_context::add(
            'cookies_none',
            'Checkout submitted with no cookies at all'
        );

    }

}
