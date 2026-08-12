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
    // Cycles System -> Light -> Dark -> System. "System" follows the OS via
    // prefers-color-scheme in the CSS; Light/Dark are explicit overrides.
    var THEME_ICONS = {
        system: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"></rect><path d="M8 20h8M12 16v4"></path></svg>',
        light:  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path></svg>',
        dark:   '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"></path></svg>'
    };
    var THEME_LABELS = { system: 'System', light: 'Light', dark: 'Dark' };
    var THEME_NEXT   = { system: 'light', light: 'dark', dark: 'system' };

    function syncBody( mode ) {
        document.body.classList.remove( 'mshield-theme-dark', 'mshield-theme-system' );
        if ( mode === 'dark' ) { document.body.classList.add( 'mshield-theme-dark' ); }
        else if ( mode === 'system' ) { document.body.classList.add( 'mshield-theme-system' ); }
    }

    function initTheme() {
        var app    = document.querySelector( '.mshield-app' );
        var toggle = document.getElementById( 'mshield-theme-toggle' );
        if ( ! app ) return;

        syncBody( app.getAttribute( 'data-theme' ) );
        if ( ! toggle ) return;

        toggle.addEventListener( 'click', function() {
            var next = THEME_NEXT[ app.getAttribute( 'data-theme' ) ] || 'system';
            app.setAttribute( 'data-theme', next );
            syncBody( next );

            var icon = toggle.querySelector( '.ms-theme-icon' );
            if ( icon && THEME_ICONS[ next ] ) icon.innerHTML = THEME_ICONS[ next ];
            var label = toggle.querySelector( '.ms-theme-label' );
            if ( label ) label.textContent = THEME_LABELS[ next ];

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
        var current = null, currentRow = null;

        function ipIntelHtml( d ) {
            var head = '<div class="mshield-eyebrow">' + esc( cfg.i18n.ipIntel || 'IP location' ) + '</div>';
            var ip = d.ipData;
            if ( ip && ip.status === 'success' ) {
                var loc = [ ip.city, ip.region, ip.country ].filter( Boolean ).join( ', ' );
                return '<div class="mshield-ipintel" id="mshield-ipintel">' + head +
                    '<div class="mshield-kv">' +
                        '<span class="k">' + esc( cfg.i18n.location || 'Location' ) + '</span><span>' + esc( loc || '—' ) + '</span>' +
                        '<span class="k">' + esc( cfg.i18n.org || 'Organization' ) + '</span><span>' + esc( ip.org || '—' ) + '</span>' +
                    '</div></div>';
            }
            if ( ip && ip.status && ip.status !== 'success' ) {
                return '<div class="mshield-ipintel" id="mshield-ipintel">' + head +
                    '<p style="margin:0;color:var(--fg-3);font-size:13px">' + esc( 'No location data available for this IP.' ) + '</p></div>';
            }
            return '<div class="mshield-ipintel" id="mshield-ipintel">' + head +
                '<button type="button" class="mshield-btn is-small" data-getip>' + esc( cfg.i18n.getIp || 'Get IP' ) + '</button></div>';
        }

        function rowData( row ) {
            var d = {};
            try { d = JSON.parse( row.getAttribute( 'data-event' ) || '{}' ); } catch ( e ) { d = {}; }
            return d;
        }

        function open( d, row ) {
            current = d; currentRow = row || null;
            var det = d.details || {};
            var rawLines = [];
            if ( det.ua )      rawLines.push( 'user-agent: ' + det.ua );
            if ( det.email )   rawLines.push( 'billing-email: ' + det.email );
            if ( det.user_id ) rawLines.push( 'user-id: ' + det.user_id );
            if ( det.uri )     rawLines.push( 'request-uri: ' + det.uri );
            var raw = rawLines.length ? rawLines.join( '\n' ) : 'No additional request data captured.';

            var actions = '';
            if ( d.wlUrl )  actions += '<a class="mshield-btn" style="flex:1;justify-content:center" href="' + esc( d.wlUrl ) + '">' + esc( cfg.i18n.whitelistIp || 'Allowlist IP' ) + '</a>';
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
                      ipIntelHtml( d ) +
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
                open( rowData( row ), row );
            } );
        } );

        mount.addEventListener( 'click', function( e ) {
            if ( e.target.hasAttribute( 'data-close' ) || e.target.closest( '[data-close]' ) === e.target ) {
                if ( e.target.classList.contains( 'mshield-drawer-overlay' ) || e.target.hasAttribute( 'data-close' ) ) close();
            }
        } );

        // "Get IP" button inside the drawer — fetch + cache without a reload.
        mount.addEventListener( 'click', function( e ) {
            var btn = e.target.closest( '[data-getip]' );
            if ( ! btn || ! current || ! cfg.ajaxUrl ) return;
            e.preventDefault();
            btn.disabled = true;
            btn.textContent = cfg.i18n.gettingIp || 'Looking up…';

            var body = new URLSearchParams();
            body.set( 'action', 'mshield_get_ip' );
            body.set( 'nonce', cfg.ipNonce || '' );
            body.set( 'ip', current.ip || '' );

            fetch( cfg.ajaxUrl, { method:'POST', credentials:'same-origin', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body.toString() } )
                .then( function( r ) { return r.json(); } )
                .then( function( res ) {
                    if ( res && res.success && res.data ) {
                        current.ipData = { status: res.data.status || 'success', city:res.data.city, region:res.data.region, country:res.data.country, org:res.data.org };
                        if ( currentRow ) { try { currentRow.setAttribute( 'data-event', JSON.stringify( current ) ); } catch ( err ) {} }
                        var el = document.getElementById( 'mshield-ipintel' );
                        if ( el ) el.outerHTML = ipIntelHtml( current );
                    } else {
                        btn.disabled = false;
                        btn.textContent = cfg.i18n.getIp || 'Get IP';
                        var msg = document.createElement( 'div' );
                        msg.style.cssText = 'color:var(--ink-danger);font-size:12.5px;margin-top:6px';
                        msg.textContent = ( res && res.data && res.data.message ) || cfg.i18n.lookupFail || 'Lookup failed.';
                        btn.parentNode.appendChild( msg );
                    }
                } )
                .catch( function() { btn.disabled = false; btn.textContent = cfg.i18n.getIp || 'Get IP'; } );
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

    /* ---------- Interactive events chart ---------- */
    function initChart() {
        var box = document.getElementById( 'mshield-chart' );
        var dataEl = document.getElementById( 'mshield-chart-data' );
        if ( ! box || ! dataEl ) return;

        var titles = {
            '30d': 'Events over the past 30 days',
            '7d':  'Events over the past 7 days',
            '24h': 'Events over the past 24 hours',
        };
        var titleEl = document.getElementById( 'mshield-chart-title' );
        var subEl   = document.getElementById( 'mshield-chart-sub' );
        var rangeEl = document.getElementById( 'mshield-chart-range' );

        var series = {};
        try { series = JSON.parse( dataEl.textContent || '{}' ); } catch ( e ) { series = {}; }

        // Geometry.
        var W = 760, H = 220, L = 40, Rr = 14, T = 12, Bt = H - 28;
        var pw = W - L - Rr, ph = Bt - T;

        function esc2( s ) { return String( s == null ? '' : s ).replace( /[&<>"]/g, function( c ) { return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c]; } ); }

        function render( s ) {
            var labels = s.labels || [], B = s.blocked || [], R = s.rate_limited || [], F = s.flagged || [];
            var n = labels.length;
            var max = 1;
            [ B, R, F ].forEach( function( a ) { a.forEach( function( v ) { if ( v > max ) max = v; } ); } );

            function X( i ) { return n > 1 ? L + i * ( pw / ( n - 1 ) ) : L + pw / 2; }
            function Y( v ) { return Bt - ( v / max ) * ph; }
            function poly( a, color, w ) {
                var pts = a.map( function( v, i ) { return X( i ).toFixed( 1 ) + ',' + Y( v ).toFixed( 1 ); } ).join( ' ' );
                return '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="' + w + '" stroke-linejoin="round" stroke-linecap="round"></polyline>';
            }

            var grid = '';
            for ( var g = 0; g <= 2; g++ ) {
                var yy = T + ( ph * g / 2 );
                var val = Math.round( max * ( 1 - g / 2 ) );
                grid += '<line x1="' + L + '" y1="' + yy.toFixed( 1 ) + '" x2="' + ( W - Rr ) + '" y2="' + yy.toFixed( 1 ) + '" stroke="var(--line-2)"></line>';
                grid += '<text x="' + ( L - 6 ) + '" y="' + ( yy + 3 ).toFixed( 1 ) + '" text-anchor="end" font-size="10.5" font-family="JetBrains Mono,monospace" fill="var(--fg-3)">' + val + '</text>';
            }

            var step = Math.max( 1, Math.ceil( n / 8 ) ), xl = '';
            for ( var i = 0; i < n; i += step ) {
                xl += '<text x="' + X( i ).toFixed( 1 ) + '" y="' + ( H - 8 ) + '" text-anchor="middle" font-size="10.5" font-family="Public Sans,sans-serif" fill="var(--fg-3)">' + esc2( labels[ i ] ) + '</text>';
            }

            box.innerHTML =
                '<svg viewBox="0 0 ' + W + ' ' + H + '" class="mshield-chart" id="mshield-chart-svg">' +
                    grid + xl +
                    poly( F, '#8c5ce6', 2.2 ) + poly( R, '#dba617', 2.2 ) + poly( B, '#d63638', 2.4 ) +
                    '<line id="mshield-guide" x1="0" y1="' + T + '" x2="0" y2="' + Bt + '" stroke="var(--fg-3)" stroke-width="1" opacity="0"></line>' +
                    '<g id="mshield-dots"></g>' +
                    '<rect id="mshield-hit" x="' + L + '" y="' + T + '" width="' + pw + '" height="' + ph + '" fill="transparent" style="cursor:crosshair"></rect>' +
                '</svg>' +
                '<div class="mshield-charttip" id="mshield-charttip" style="opacity:0"></div>';

            // Sub line: totals for the visible range.
            if ( subEl ) {
                var tot = 0, blk = 0;
                B.forEach( function( v ) { tot += v; blk += v; } );
                R.forEach( function( v ) { tot += v; } );
                F.forEach( function( v ) { tot += v; } );
                var pct = tot > 0 ? Math.round( blk / tot * 100 ) : 0;
                subEl.textContent = tot.toLocaleString() + ' events · ' + pct + '% blocked';
            }

            attachHover( s, X, Y, n );
        }

        function attachHover( s, X, Y, n ) {
            var svg   = document.getElementById( 'mshield-chart-svg' );
            var hit   = document.getElementById( 'mshield-hit' );
            var guide = document.getElementById( 'mshield-guide' );
            var dots  = document.getElementById( 'mshield-dots' );
            var tip   = document.getElementById( 'mshield-charttip' );
            if ( ! svg || ! hit ) return;

            function hide() { guide.setAttribute( 'opacity', '0' ); dots.innerHTML = ''; tip.style.opacity = '0'; }

            hit.addEventListener( 'mousemove', function( e ) {
                var rect = svg.getBoundingClientRect();
                var vbx  = ( e.clientX - rect.left ) / rect.width * W;
                var i    = n > 1 ? Math.round( ( vbx - L ) / ( pw / ( n - 1 ) ) ) : 0;
                i = Math.max( 0, Math.min( n - 1, i ) );

                var px = X( i );
                guide.setAttribute( 'x1', px ); guide.setAttribute( 'x2', px ); guide.setAttribute( 'opacity', '1' );

                var cols = [ [ s.blocked, '#d63638' ], [ s.rate_limited, '#dba617' ], [ s.flagged, '#8c5ce6' ] ];
                var dm = '';
                cols.forEach( function( c ) { dm += '<circle cx="' + px.toFixed( 1 ) + '" cy="' + Y( c[0][i] ).toFixed( 1 ) + '" r="3.6" fill="var(--surface)" stroke="' + c[1] + '" stroke-width="2.2"></circle>'; } );
                dots.innerHTML = dm;

                tip.innerHTML =
                    '<div class="t-label">' + esc2( s.labels[ i ] ) + '</div>' +
                    '<div class="t-row"><i style="background:#d63638"></i>Blocked <b>' + s.blocked[ i ] + '</b></div>' +
                    '<div class="t-row"><i style="background:#dba617"></i>Rate-limited <b>' + s.rate_limited[ i ] + '</b></div>' +
                    '<div class="t-row"><i style="background:#8c5ce6"></i>Flagged <b>' + s.flagged[ i ] + '</b></div>';
                var leftPx = ( px / W ) * rect.width;
                tip.style.left = Math.min( rect.width - 150, Math.max( 0, leftPx + 10 ) ) + 'px';
                tip.style.opacity = '1';
            } );
            hit.addEventListener( 'mouseleave', hide );
        }

        function setRange( range, btn ) {
            if ( rangeEl ) {
                rangeEl.querySelectorAll( '.mshield-range-btn' ).forEach( function( b ) { b.classList.toggle( 'is-active', b === btn ); } );
            }
            if ( titleEl && titles[ range ] ) titleEl.textContent = titles[ range ];

            if ( ! cfg.ajaxUrl ) return;
            var url = cfg.ajaxUrl + '?action=mshield_chart&range=' + encodeURIComponent( range ) + '&nonce=' + encodeURIComponent( cfg.chartNonce || '' );
            fetch( url, { credentials:'same-origin' } )
                .then( function( r ) { return r.json(); } )
                .then( function( res ) { if ( res && res.success ) render( res.data ); } )
                .catch( function() {} );
        }

        if ( rangeEl ) {
            rangeEl.addEventListener( 'click', function( e ) {
                var btn = e.target.closest( '.mshield-range-btn' );
                if ( ! btn ) return;
                setRange( btn.getAttribute( 'data-range' ), btn );
            } );
        }

        render( series );
    }

    ready( function() { initTheme(); initDrawer(); initBulk(); initRadios(); initChart(); } );

} )();
