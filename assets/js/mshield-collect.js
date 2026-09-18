/**
 * MightyShield shared checkout collector.
 *
 * One implementation for both checkouts. The classic and block collectors used
 * to each carry their own copy, which meant any signal added to one could be
 * sidestepped by using the other — so they share this instead.
 *
 * Two kinds of thing are gathered:
 *
 *   Environment — what the browser claims to be, and whether those claims are
 *   consistent with each other. A headless browser can lie about any single
 *   value; making all of them agree is harder.
 *
 *   Interaction — what actually happened on the page. This is the more useful
 *   half: a script can spoof a user agent, but filling a form without ever
 *   producing an input event is very hard to avoid.
 *
 * Everything here is best-effort and wrapped. A browser that blocks one of
 * these APIs must still be able to check out — a collector that throws would
 * cost a real sale, which is worse than any fraud it might catch.
 *
 * Deliberately NOT collected: canvas and audio fingerprints. They are strong
 * identifiers but carry real privacy and consent implications, and are gated
 * behind a store setting elsewhere rather than gathered by default.
 *
 * @package MightyShield
 * @since   1.9.0
 */
( function() {

    'use strict';

    if ( window.mshieldCollect ) return;

    var moves    = 0;
    var keys     = 0;
    var pastes   = 0;
    var scrolls  = 0;
    var firstAt  = 0;
    var startedAt = Date.now();

    // Fields that were empty when we started watching, so a value appearing
    // later without any matching event means it was set programmatically.
    var watched = {};
    var touched = {};

    function note() {
        if ( ! firstAt ) firstAt = Date.now();
    }

    function on( target, type, fn, opts ) {
        try { target.addEventListener( type, fn, opts || { passive: true, capture: true } ); } catch ( e ) {}
    }

    on( document, 'pointermove', function() { moves++; note(); } );
    on( document, 'mousemove',   function() { moves++; note(); } );
    on( document, 'touchstart',  function() { moves++; note(); } );
    on( document, 'scroll',      function() { scrolls++; note(); } );
    on( document, 'keydown',     function( e ) {
        keys++; note();
        if ( e && e.target && e.target.name ) touched[ e.target.name ] = 1;
    } );
    on( document, 'paste', function( e ) {
        pastes++; note();
        if ( e && e.target && e.target.name ) touched[ e.target.name ] = 1;
    } );
    // Autofill and password managers fire input without keydown, which is
    // perfectly legitimate — so an input event counts as the field having been
    // touched by something real.
    on( document, 'input', function( e ) {
        note();
        if ( e && e.target && e.target.name ) touched[ e.target.name ] = 1;
    } );

    /**
     * Plant a decoy field.
     *
     * The classic checkout gets its honeypot rendered server-side into the
     * form. The block checkout has no server-rendered form to hook, which is
     * why it had no honeypot at all — so one is planted here instead.
     *
     * Appended to <body> rather than into the checkout markup on purpose: the
     * block checkout is a React tree, and anything injected inside it can be
     * reconciled away without warning. A script that fills every input it can
     * find does not care where on the page the input lives.
     *
     * Hidden from sight, from screen readers, and from tab order — a real
     * customer can neither see it nor reach it.
     */
    function plantDecoy() {
        try {
            if ( document.getElementById( 'mshield_hp_field' ) ) return;

            var wrap = document.createElement( 'div' );
            wrap.setAttribute( 'aria-hidden', 'true' );
            wrap.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;';

            var input = document.createElement( 'input' );
            input.type = 'text';
            input.id = 'mshield_hp_field';
            input.name = 'mshield_hp_field';
            input.value = '';
            input.tabIndex = -1;
            input.setAttribute( 'autocomplete', 'off' );

            wrap.appendChild( input );
            document.body.appendChild( wrap );
        } catch ( e ) {}
    }

    /**
     * Whatever ended up in the decoy.
     */
    function decoyValue() {
        try {
            var el = document.getElementById( 'mshield_hp_field' );
            return el && el.value ? String( el.value ).slice( 0, 100 ) : '';
        } catch ( e ) {
            return '';
        }
    }

    /**
     * Snapshot which relevant fields are currently empty.
     *
     * Called as early as possible. A field already filled when we start cannot
     * be judged — the script may simply have loaded after the customer typed —
     * so those are never reported as scripted.
     */
    function snapshot() {
        try {
            var inputs = document.querySelectorAll( 'input[name], textarea[name]' );
            for ( var i = 0; i < inputs.length; i++ ) {
                var el = inputs[ i ];
                if ( ! el.name || el.type === 'hidden' || el.type === 'submit' ) continue;
                if ( el.id === 'mshield_hp_field' ) continue;
                if ( ! el.value ) watched[ el.name ] = 1;
            }
        } catch ( e ) {}
    }

    /**
     * Fields that gained a value without any event ever firing for them.
     *
     * This is the strongest interaction signal available: a real customer
     * cannot fill a field without the browser emitting something, whether they
     * typed, pasted, or let a password manager do it.
     */
    function scriptedFields() {
        var out = [];
        try {
            for ( var name in watched ) {
                if ( ! Object.prototype.hasOwnProperty.call( watched, name ) ) continue;
                if ( touched[ name ] ) continue;
                var el = document.querySelector( '[name="' + name.replace( /"/g, '\\"' ) + '"]' );
                if ( el && el.value ) out.push( name );
            }
        } catch ( e ) {}
        return out.slice( 0, 20 );
    }

    /**
     * The GPU renderer string.
     *
     * Software rasterisers (SwiftShader, llvmpipe, Mesa OffScreen) are what a
     * headless browser falls back to when there is no real GPU. Real devices
     * report actual hardware.
     */
    function renderer() {
        try {
            var c  = document.createElement( 'canvas' );
            var gl = c.getContext( 'webgl' ) || c.getContext( 'experimental-webgl' );
            if ( ! gl ) return '';
            var ext = gl.getExtension( 'WEBGL_debug_renderer_info' );
            if ( ! ext ) return '';
            return String( gl.getParameter( ext.UNMASKED_RENDERER_WEBGL ) || '' ).slice( 0, 120 );
        } catch ( e ) {
            return '';
        }
    }

    /**
     * A high-entropy device signature.
     *
     * The old signature was timezone + language + platform + screen size, which
     * thousands of ordinary customers share — so counting checkouts per
     * signature both flagged real shoppers and could be sidestepped by resizing
     * a window. This mixes in far more, so it identifies a device rather than a
     * demographic.
     */
    function signature( d ) {
        var parts = [
            d.timezone, d.timezone_offset, d.language, ( d.languages || [] ).join( ',' ),
            d.platform, d.screen_width, d.screen_height, d.color_depth,
            d.hardware_concurrency, d.device_memory, d.pixel_ratio,
            d.touch_points, d.webgl_renderer
        ].join( '|' );

        // FNV-1a. Not cryptographic, and does not need to be: this only has to
        // spread similar inputs apart, and the server re-hashes it anyway.
        var h = 2166136261;
        for ( var i = 0; i < parts.length; i++ ) {
            h ^= parts.charCodeAt( i );
            h = ( h + ( ( h << 1 ) + ( h << 4 ) + ( h << 7 ) + ( h << 8 ) + ( h << 24 ) ) ) >>> 0;
        }
        return ( '00000000' + h.toString( 16 ) ).slice( -8 );
    }

    window.mshieldCollect = function() {

        var d = {
            // Environment.
            timezone: '',
            timezone_offset: new Date().getTimezoneOffset(),
            language: navigator.language || '',
            languages: navigator.languages ? Array.prototype.slice.call( navigator.languages ) : [],
            screen_width: screen.width || 0,
            screen_height: screen.height || 0,
            color_depth: screen.colorDepth || 0,
            platform: navigator.platform || '',
            webdriver: !!navigator.webdriver,
            hardware_concurrency: navigator.hardwareConcurrency || 0,
            device_memory: navigator.deviceMemory || 0,
            pixel_ratio: window.devicePixelRatio || 0,
            touch_points: navigator.maxTouchPoints || 0,
            has_touch: ( 'ontouchstart' in window ) || ( navigator.maxTouchPoints || 0 ) > 0,
            has_chrome: !! window.chrome,
            plugin_count: ( navigator.plugins && navigator.plugins.length ) || 0,
            webgl_renderer: renderer(),

            // Interaction.
            moves: moves,
            keys: keys,
            pastes: pastes,
            scrolls: scrolls,
            dwell: firstAt ? ( Date.now() - firstAt ) : 0,
            since_load: Date.now() - startedAt,
            scripted_fields: scriptedFields(),
            honeypot: decoyValue()
        };

        try {
            d.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
        } catch ( e ) {
            d.timezone = '';
        }

        d.signature = signature( d );

        return d;

    };

    function start() {
        snapshot();
        plantDecoy();
    }

    if ( document.readyState === 'loading' ) {
        document.addEventListener( 'DOMContentLoaded', start );
    } else {
        start();
    }

} )();
