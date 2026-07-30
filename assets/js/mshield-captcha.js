/**
 * MightyShield CAPTCHA helper.
 *
 * reCAPTCHA v3: keeps a fresh token in the hidden checkout field (refreshed on
 * load, on an interval well under the 2-minute TTL, and after every order-review
 * refresh or checkout error so a resubmit never reuses a stale/consumed token).
 *
 * Turnstile: the widget manages its own token; we reset it after a checkout
 * error (tokens are single-use) and re-render it if a form refresh removed it.
 *
 * @package MightyShield
 * @since   1.2.0
 */
( function() {

    'use strict';

    if ( typeof window.mshieldCaptcha === 'undefined' ) return;

    var cfg = window.mshieldCaptcha;
    var $   = window.jQuery;

    /* ---------- reCAPTCHA v3 ---------- */
    if ( cfg.provider === 'recaptcha_v3' ) {

        var siteKey = cfg.siteKey;

        function refreshToken() {
            if ( typeof grecaptcha === 'undefined' || ! grecaptcha.execute ) return;
            try {
                grecaptcha.execute( siteKey, { action: 'checkout' } ).then( function( token ) {
                    var field = document.getElementById( 'mshield_captcha_token' );
                    if ( field ) field.value = token;
                } ).catch( function() {} );
            } catch ( e ) {}
        }

        function init() {
            if ( typeof grecaptcha === 'undefined' || ! grecaptcha.ready ) { window.setTimeout( init, 300 ); return; }
            grecaptcha.ready( function() {
                refreshToken();
                // v3 tokens live ~120s; refresh comfortably inside that window.
                window.setInterval( refreshToken, 90000 );
            } );
        }
        init();

        if ( $ ) {
            // Re-issue after the order review re-renders or a checkout error, so
            // the next submit always carries a fresh, single-use token.
            $( document.body ).on( 'updated_checkout checkout_error', refreshToken );
        }

    }

    /* ---------- Cloudflare Turnstile ---------- */
    if ( cfg.provider === 'turnstile' && $ ) {

        // Tokens are single-use: after any checkout error, reset so a retry gets
        // a new token instead of resubmitting the consumed one.
        $( document.body ).on( 'checkout_error', function() {
            if ( typeof turnstile !== 'undefined' && turnstile.reset ) {
                try { turnstile.reset(); } catch ( e ) {}
            }
        } );

        // Re-render the widget if a form refresh removed it.
        $( document.body ).on( 'updated_checkout', function() {
            var el = document.querySelector( '.cf-turnstile' );
            if ( el && ! el.querySelector( 'iframe' ) && typeof turnstile !== 'undefined' && turnstile.render ) {
                try { turnstile.render( el ); } catch ( e ) {}
            }
        } );

    }

} )();
