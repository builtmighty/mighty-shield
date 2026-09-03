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

    // Re-collect before form submit (in case checkout updates the DOM).
    document.addEventListener( 'submit', function( e ) {
        if( e.target && e.target.matches && e.target.matches( 'form.checkout, form.woocommerce-checkout' ) ) {
            writeToField();
        }
    } );

    // Re-collect after WooCommerce refreshes the order review (one-page and
    // AJAX checkouts re-render the form, which would otherwise blank the field).
    if( window.jQuery ) {
        window.jQuery( document.body ).on( 'updated_checkout', writeToField );
    }

} )();
