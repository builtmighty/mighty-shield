/**
 * MightyShield Block Checkout Collector.
 *
 * The WooCommerce Checkout block submits through the Store API, which does not
 * render our classic hidden fields. This script collects the same front-end
 * signals (checkout-timing token, device fingerprint, reCAPTCHA v3 token) and
 * attaches them to the Store API checkout request as "mightyshield" extension
 * data, where class-store-api.php reads and evaluates them server-side.
 *
 * Fully defensive: any missing dependency (wp.data store, grecaptcha) simply
 * omits that signal rather than throwing — it must never break checkout.
 *
 * @package MightyShield
 * @since   1.8.0
 */
( function() {

    'use strict';

    var cfg = window.mshieldBlocks || {};

    /**
     * The Store API checkout data store may not be registered yet (script
     * order). Resolve the dispatcher lazily and defensively.
     */
    function checkoutDispatch() {
        if( ! window.wp || ! window.wp.data || typeof window.wp.data.dispatch !== 'function' ) return null;
        try {
            var store = window.wp.data.dispatch( 'wc/store/checkout' );
            return ( store && typeof store.setExtensionData === 'function' ) ? store : null;
        } catch( e ) {
            return null;
        }
    }

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

        try {
            data.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
        } catch( e ) {
            data.timezone = '';
        }

        return data;

    }

    /**
     * Resolve a fresh reCAPTCHA v3 token. Returns a Promise<string> that never
     * rejects — on any failure it resolves to '' so the server treats CAPTCHA as
     * skipped rather than failed (avoids locking out shoppers on a script hiccup).
     */
    function getRecaptchaToken() {
        return new Promise( function( resolve ) {
            if( ! cfg.recaptcha || ! cfg.siteKey || ! window.grecaptcha || typeof window.grecaptcha.execute !== 'function' ) {
                resolve( '' );
                return;
            }
            try {
                window.grecaptcha.ready( function() {
                    window.grecaptcha.execute( cfg.siteKey, { action: 'checkout' } ).then(
                        function( token ) { resolve( token || '' ); },
                        function() { resolve( '' ); }
                    );
                } );
            } catch( e ) {
                resolve( '' );
            }
        } );
    }

    /**
     * Collect all enabled signals and push them into the checkout extension data.
     */
    function push() {

        var dispatch = checkoutDispatch();
        if( ! dispatch ) return;

        getRecaptchaToken().then( function( capToken ) {

            var data = {};

            if( cfg.timing && cfg.timingToken ) {
                data.ct = String( cfg.timingToken );
            }

            if( cfg.fingerprint ) {
                try {
                    data.dev = JSON.stringify( collectFingerprint() );
                } catch( e ) {}
            }

            if( capToken ) {
                data.cap = capToken;
            }

            try {
                dispatch.setExtensionData( 'mightyshield', data );
            } catch( e ) {}

        } );

    }

    // Initial push once the DOM is ready.
    if( document.readyState === 'loading' ) {
        document.addEventListener( 'DOMContentLoaded', push );
    } else {
        push();
    }

    // Refresh periodically so the reCAPTCHA v3 token (120s TTL) is never stale
    // when the shopper finally submits.
    if( cfg.recaptcha ) {
        window.setInterval( push, 90000 );
    }

} )();
