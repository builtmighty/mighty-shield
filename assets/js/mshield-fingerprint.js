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

    function collectFingerprint() {

        var data = {
            timezone: '',
            timezone_offset: new Date().getTimezoneOffset(),
            language: navigator.language || '',
            languages: navigator.languages ? Array.prototype.slice.call( navigator.languages ) : [],
            screen_width: screen.width || 0,
            screen_height: screen.height || 0,
            platform: navigator.platform || '',
            webdriver: !!navigator.webdriver
        };

        // Timezone name (modern browsers).
        try {
            data.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
        } catch( e ) {
            data.timezone = '';
        }

        return data;

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
