/**
 * MightyShield CAPTCHA helper.
 *
 * For reCAPTCHA v3, generates a token and writes it to the hidden checkout
 * field (refreshing before submit and periodically, since v3 tokens expire).
 * Turnstile manages its own widget + hidden field, so no work is needed here.
 *
 * @package MightyShield
 * @since   1.2.0
 */
( function() {

    'use strict';

    if ( typeof mshieldCaptcha === 'undefined' ) return;
    if ( mshieldCaptcha.provider !== 'recaptcha_v3' ) return;

    var siteKey = mshieldCaptcha.siteKey;

    function refreshToken() {

        if ( typeof grecaptcha === 'undefined' || ! grecaptcha.execute ) return;

        grecaptcha.execute( siteKey, { action: 'checkout' } ).then( function( token ) {
            var field = document.getElementById( 'mshield_captcha_token' );
            if ( field ) field.value = token;
        } );

    }

    function init() {

        if ( typeof grecaptcha === 'undefined' || ! grecaptcha.ready ) {
            window.setTimeout( init, 300 );
            return;
        }

        grecaptcha.ready( function() {
            refreshToken();
            // v3 tokens expire after ~2 minutes; keep it fresh.
            window.setInterval( refreshToken, 90000 );
        } );

    }

    // Refresh right before the checkout form submits.
    document.addEventListener( 'submit', function( e ) {
        if ( e.target && e.target.matches && e.target.matches( 'form.checkout, form.woocommerce-checkout' ) ) {
            refreshToken();
        }
    } );

    init();

} )();
