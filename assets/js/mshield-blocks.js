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

    // Shared with the classic checkout via mshield-collect.js.
    function collectFingerprint() {

        if ( typeof window.mshieldCollect === 'function' ) return window.mshieldCollect();

        return {
            timezone_offset: new Date().getTimezoneOffset(),
            language: navigator.language || '',
            platform: navigator.platform || '',
            webdriver: !!navigator.webdriver,
            degraded: true
        };

    }

    /**
     * Turnstile on the block checkout.
     *
     * Unlike reCAPTCHA v3, Turnstile renders a widget — and in its managed mode
     * that widget can ask the customer to do something. So it is placed
     * visibly, next to the place-order button, rather than hidden off-screen
     * the way the honeypot is. A challenge nobody can see is one nobody can
     * complete, which would mean every order failing it.
     *
     * The token is single-use and expires, so it is reset after a failed
     * attempt and re-issued when the checkout re-renders.
     */
    var tsToken  = '';
    var tsWidget = null;

    function turnstileHost() {

        // Sit just above the place-order button where the customer is already
        // looking. Each fallback is a step further out; the last resort is the
        // checkout block itself, so the widget is always somewhere visible.
        var anchors = [
            '.wc-block-checkout__actions_row',
            '.wc-block-checkout__actions',
            '.wp-block-woocommerce-checkout-actions-block',
            '.wc-block-checkout__form',
            '.wp-block-woocommerce-checkout'
        ];

        for ( var i = 0; i < anchors.length; i++ ) {
            var el = document.querySelector( anchors[ i ] );
            if ( el ) return el;
        }

        return null;

    }

    function renderTurnstile() {

        if ( ! cfg.turnstile || ! cfg.siteKey ) return;
        if ( typeof window.turnstile === 'undefined' ) return;
        if ( document.getElementById( 'mshield-turnstile-block' ) ) return;

        var host = turnstileHost();
        if ( ! host ) return;

        var box = document.createElement( 'div' );
        box.id = 'mshield-turnstile-block';
        box.style.cssText = 'margin:0 0 16px 0;';

        if ( host.parentNode ) {
            host.parentNode.insertBefore( box, host );
        } else {
            host.appendChild( box );
        }

        try {
            tsWidget = window.turnstile.render( box, {
                sitekey: cfg.siteKey,
                callback: function( token ) { tsToken = token || ''; },
                'expired-callback': function() { tsToken = ''; },
                'error-callback': function() { tsToken = ''; }
            } );
        } catch ( e ) {
            // A widget that will not render must not stop the sale. The server
            // treats an absent token as a skip.
            tsToken = '';
        }

    }

    function resetTurnstile() {
        tsToken = '';
        try {
            if ( tsWidget !== null && typeof window.turnstile !== 'undefined' ) {
                window.turnstile.reset( tsWidget );
            }
        } catch ( e ) {}
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
                    window.grecaptcha.execute( cfg.siteKey, { action: cfg.action || 'checkout' } ).then(
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

            // Collected once and reused: two calls would re-read the DOM and
            // could disagree with each other.
            var fp = null;
            try { fp = collectFingerprint(); } catch( e ) {}

            if( cfg.fingerprint && fp ) {
                try {
                    data.dev = JSON.stringify( fp );
                } catch( e ) {}
            }

            // Honeypot. The classic checkout renders a decoy server-side; here
            // the shared collector plants one and this carries what landed in
            // it. Sent independently of the fingerprint setting — they are
            // separate protections that happen to share a collector.
            if( fp && typeof fp.honeypot === 'string' && fp.honeypot !== '' ) {
                data.hp = fp.honeypot;
            }

            // Whichever challenge is configured fills the same field; the
            // server knows which provider to verify against.
            if( cfg.turnstile ) {
                if( tsToken ) data.cap = tsToken;
            } else if( capToken ) {
                data.cap = capToken;
            }

            try {
                dispatch.setExtensionData( 'mightyshield', data );
            } catch( e ) {}

        } );

    }

    function start() {
        renderTurnstile();
        push();
    }

    // Initial push once the DOM is ready.
    if( document.readyState === 'loading' ) {
        document.addEventListener( 'DOMContentLoaded', start );
    } else {
        start();
    }

    // Refresh periodically so the reCAPTCHA v3 token (120s TTL) is never stale
    // when the shopper finally submits.
    if( cfg.recaptcha ) {
        window.setInterval( push, 90000 );
    }

    if( cfg.turnstile ) {

        // The block checkout is a React tree that re-renders as the shopper
        // fills it in, and can replace the region the widget lives in. Watch
        // for the widget disappearing and put it back, rather than assuming
        // one render at load is enough.
        try {
            var observer = new MutationObserver( function() {
                if( ! document.getElementById( 'mshield-turnstile-block' ) ) {
                    tsWidget = null;
                    renderTurnstile();
                }
                push();
            } );
            observer.observe( document.body, { childList: true, subtree: true } );
        } catch( e ) {}

        // A token is single-use. Once an attempt fails, the old one is spent,
        // so it is cleared and a fresh one requested — otherwise a shopper who
        // mistypes their card can never complete the order.
        try {
            if( window.wp && window.wp.data && window.wp.data.subscribe ) {
                var wasProcessing = false;
                window.wp.data.subscribe( function() {
                    try {
                        var store = window.wp.data.select( 'wc/store/checkout' );
                        if( ! store ) return;
                        var failed = store.hasError && store.hasError();
                        var busy   = store.isProcessing && store.isProcessing();
                        if( wasProcessing && ! busy && failed ) {
                            resetTurnstile();
                            push();
                        }
                        wasProcessing = busy;
                    } catch( e ) {}
                } );
            }
        } catch( e ) {}

    }

} )();
