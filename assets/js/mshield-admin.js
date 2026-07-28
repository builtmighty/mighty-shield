/**
 * MightyShield admin UI behavior.
 *
 * - Theme toggle (persisted per user via admin-ajax).
 * - Logs event-detail drawer.
 * - Logs bulk selection (select-all + count).
 *
 * @package MightyShield
 * @since   1.5.0
 */
( function() {

    'use strict';

    var cfg = window.mshieldAdmin || {};

    function ready( fn ) {
        if ( document.readyState !== 'loading' ) { fn(); }
        else { document.addEventListener( 'DOMContentLoaded', fn ); }
    }

    /* ---------- Theme toggle ---------- */
    function syncBody( theme ) {
        document.body.classList.toggle( 'mshield-theme-dark', theme === 'dark' );
    }

    function initTheme() {
        var app    = document.querySelector( '.mshield-app' );
        var toggle = document.getElementById( 'mshield-theme-toggle' );
        if ( ! app ) return;

        syncBody( app.getAttribute( 'data-theme' ) );
        if ( ! toggle ) return;

        toggle.addEventListener( 'click', function() {
            var next = app.getAttribute( 'data-theme' ) === 'dark' ? 'light' : 'dark';
            app.setAttribute( 'data-theme', next );
            syncBody( next );
            var label = toggle.querySelector( '.ms-theme-label' );
            if ( label ) label.textContent = next === 'dark' ? 'Dark' : 'Light';

            if ( ! cfg.ajaxUrl ) return;
            var body = new URLSearchParams();
            body.set( 'action', 'mshield_set_theme' );
            body.set( 'nonce', cfg.themeNonce || '' );
            body.set( 'theme', next );
            fetch( cfg.ajaxUrl, { method:'POST', credentials:'same-origin', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body.toString() } );
        } );
    }

    /* ---------- Logs drawer ---------- */
    function initDrawer() {
        var mount = document.getElementById( 'mshield-drawer-root' );
        if ( ! mount ) return;

        function esc( s ) {
            return String( s == null ? '' : s ).replace( /[&<>"']/g, function( c ) {
                return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c];
            } );
        }

        var pillClass = { blocked:'is-blocked', rate_limited:'is-rate', flagged:'is-flag', exempt:'is-exempt', allowed:'is-ok' };

        function rowData( row ) {
            var d = {};
            try { d = JSON.parse( row.getAttribute( 'data-event' ) || '{}' ); } catch ( e ) { d = {}; }
            return d;
        }

        function open( d ) {
            var det = d.details || {};
            var rawLines = [];
            if ( det.ua )      rawLines.push( 'user-agent: ' + det.ua );
            if ( det.email )   rawLines.push( 'billing-email: ' + det.email );
            if ( det.user_id ) rawLines.push( 'user-id: ' + det.user_id );
            if ( det.uri )     rawLines.push( 'request-uri: ' + det.uri );
            var raw = rawLines.length ? rawLines.join( '\n' ) : 'No additional request data captured.';

            var actions = '';
            if ( d.wlUrl )  actions += '<a class="mshield-btn" style="flex:1;justify-content:center" href="' + esc( d.wlUrl ) + '">' + esc( cfg.i18n.whitelistIp || 'Whitelist IP' ) + '</a>';
            if ( d.blockUrl ) actions += '<a class="mshield-btn is-danger" style="flex:1;justify-content:center" href="' + esc( d.blockUrl ) + '">' + esc( cfg.i18n.blockPerm || 'Block permanently' ) + '</a>';

            mount.innerHTML =
                '<div class="mshield-drawer-overlay" data-close>' +
                  '<div class="mshield-drawer" role="dialog" aria-label="Event detail">' +
                    '<div class="mshield-drawer-head">' +
                      '<div><div class="mshield-card-title">' + esc( cfg.i18n.eventDetail || 'Event detail' ) + '</div>' +
                      '<div class="mshield-mono" style="font-size:12px;color:var(--fg-3);margin-top:2px">' + esc( d.time || '' ) + '</div></div>' +
                      '<span class="mshield-spacer"></span>' +
                      '<button class="mshield-btn is-small" data-close aria-label="Close">&times;</button>' +
                    '</div>' +
                    '<div class="mshield-drawer-body">' +
                      '<div><span class="mshield-pill ' + ( pillClass[ d.action ] || '' ) + '">' + esc( d.actionLabel || d.action || '' ) + '</span></div>' +
                      '<div class="mshield-kv">' +
                        '<span class="k">' + esc( cfg.i18n.ip || 'IP address' ) + '</span><span class="mshield-mono">' + esc( d.ip || '' ) + '</span>' +
                        '<span class="k">' + esc( cfg.i18n.endpoint || 'Endpoint' ) + '</span><span class="mshield-mono" style="font-size:12.5px">' + esc( d.endpoint || '' ) + '</span>' +
                        '<span class="k">' + esc( cfg.i18n.reason || 'Reason' ) + '</span><span>' + esc( d.reason || '' ) + '</span>' +
                        ( det.user_label ? '<span class="k">' + esc( cfg.i18n.user || 'User' ) + '</span><span>' + esc( det.user_label ) + '</span>' : '' ) +
                      '</div>' +
                      '<div><div class="mshield-eyebrow">' + esc( cfg.i18n.raw || 'Request data' ) + '</div>' +
                      '<pre class="mshield-raw">' + esc( raw ) + '</pre></div>' +
                    '</div>' +
                    ( actions ? '<div class="mshield-drawer-foot">' + actions + '</div>' : '' ) +
                  '</div>' +
                '</div>';
        }

        function close() { mount.innerHTML = ''; }

        document.querySelectorAll( '.mshield-logrow.is-clickable' ).forEach( function( row ) {
            row.addEventListener( 'click', function( e ) {
                // Let checkboxes and inner links behave normally.
                if ( e.target.closest( 'input, a' ) ) return;
                open( rowData( row ) );
            } );
        } );

        mount.addEventListener( 'click', function( e ) {
            if ( e.target.hasAttribute( 'data-close' ) || e.target.closest( '[data-close]' ) === e.target ) {
                if ( e.target.classList.contains( 'mshield-drawer-overlay' ) || e.target.hasAttribute( 'data-close' ) ) close();
            }
        } );
        document.addEventListener( 'keydown', function( e ) { if ( e.key === 'Escape' ) close(); } );
    }

    /* ---------- Logs bulk select ---------- */
    function initBulk() {
        var all = document.getElementById( 'mshield-check-all' );
        if ( ! all ) return;
        var boxes = document.querySelectorAll( '.mshield-logcheck' );
        var count = document.getElementById( 'mshield-sel-count' );

        function refresh() {
            var n = 0;
            boxes.forEach( function( b ) { if ( b.checked ) n++; } );
            if ( count ) count.textContent = n + ' ' + ( cfg.i18n.selected || 'selected' );
        }
        all.addEventListener( 'change', function() {
            boxes.forEach( function( b ) { b.checked = all.checked; } );
            refresh();
        } );
        boxes.forEach( function( b ) { b.addEventListener( 'change', refresh ); } );
        refresh();
    }

    /* ---------- Radio-bubble groups ---------- */
    function initRadios() {
        document.querySelectorAll( '.mshield-radios input[type="radio"]' ).forEach( function( input ) {
            input.addEventListener( 'change', function() {
                var group = input.closest( '.mshield-radios' );
                if ( ! group ) return;
                group.querySelectorAll( '.mshield-radio' ).forEach( function( lbl ) {
                    var r = lbl.querySelector( 'input[type="radio"]' );
                    lbl.classList.toggle( 'is-checked', !!( r && r.checked ) );
                } );
            } );
        } );
    }

    ready( function() { initTheme(); initDrawer(); initBulk(); initRadios(); } );

} )();
