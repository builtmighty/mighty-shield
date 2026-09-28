/**
 * MightyShield Device Fingerprint Collector.
 *
 * Collects browser metadata and writes it to a hidden form field
 * for server-side validation at checkout.
 *
 * @package MightyShield
 * @since   1.0.0
 */
( function() {

    'use strict';

    // The collector itself lives in mshield-collect.js, shared with the block
    // checkout so the two paths cannot report different things.
    function collectFingerprint() {

        if ( typeof window.mshieldCollect === 'function' ) return window.mshieldCollect();

        // The shared collector failed to load. Send what can be read inline
        // rather than nothing: an empty field reads as "JS did not run", which
        // would penalise a shopper for our own asset failing.
        return {
            timezone_offset: new Date().getTimezoneOffset(),
            language: navigator.language || '',
            platform: navigator.platform || '',
            webdriver: !!navigator.webdriver,
            degraded: true
        };

    }

    function writeToField() {

        var field = document.getElementById( 'mshield_device_data' );
        if( ! field ) return;

        var data = collectFingerprint();
        field.value = JSON.stringify( data );

    }

    // Collect on page load.
    if( document.readyState === 'loading' ) {
        document.addEventListener( 'DOMContentLoaded', writeToField );
    } else {
        writeToField();
    }

    // Re-collect at the moment of placing the order. WooCommerce's own submit
    // handler returns false, which stops the native submit event before any
    // document-level listener sees it -- so a plain 'submit' listener here
    // never ran, and the field held whatever the last order-review refresh
    // left in it. checkout_place_order is the event WooCommerce fires itself,
    // synchronously, just before it serialises the form. Delegated from body
    // because the form can be re-rendered; the handler must return true or
    // WooCommerce treats it as a veto.
    if( window.jQuery ) {
        window.jQuery( document.body ).on( 'checkout_place_order', 'form.checkout, form.woocommerce-checkout', function() {
            writeToField();
            return true;
        } );

        // And after WooCommerce refreshes the order review: one-page and AJAX
        // checkouts re-render the form, which would otherwise blank the field.
        window.jQuery( document.body ).on( 'updated_checkout', writeToField );
    }

    // Belt and braces for a theme that submits the form natively. Capture
    // phase, so it runs before any handler that might stop propagation.
    document.addEventListener( 'submit', function( e ) {
        if( e.target && e.target.matches && e.target.matches( 'form.checkout, form.woocommerce-checkout' ) ) {
            writeToField();
        }
    }, true );

} )();
