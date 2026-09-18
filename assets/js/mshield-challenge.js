/**
 * Bot challenge widget renderer.
 *
 * One file for every non-block surface: classic checkout, login, registration,
 * lost password and comments. Each of those prints a `.mshield-challenge` host
 * and a `.mshield-challenge-token` hidden input; this fills the input.
 *
 * Explicit rendering throughout. Turnstile's implicit mode scans for
 * `.cf-turnstile` at script load, which loses to any form rendered later, and
 * it injects its own field name — rendering explicitly means one field name on
 * every surface and one place that knows about timing.
 *
 * The block checkout is NOT served from here. It lives in a React tree that
 * re-renders under us, so it keeps mshield-blocks.js and its MutationObserver.
 *
 * @package MightyShield
 * @since   1.9.4
 */
( function () {

	'use strict';

	var cfg = window.mshieldChallenge || {};

	if ( ! cfg.provider || ! cfg.siteKey ) return;

	/**
	 * Every host on the page that has not been rendered into yet.
	 */
	function hosts() {
		return Array.prototype.slice.call(
			document.querySelectorAll( '.mshield-challenge:not([data-mshield-done])' )
		);
	}

	/**
	 * The token field belonging to one host.
	 *
	 * Scoped to the host's own form where there is one, so a page with both a
	 * login and a registration form does not have one widget writing into the
	 * other's field.
	 */
	function tokenField( host ) {
		var scope = host.closest( 'form' ) || document;
		return scope.querySelector( '.mshield-challenge-token' );
	}

	/**
	 * A stable id per host, so a re-mint function can be found again.
	 */
	var hostSeq = 0;

	function hostId( host ) {
		if ( ! host.getAttribute( 'data-mshield-id' ) ) {
			host.setAttribute( 'data-mshield-id', String( ++hostSeq ) );
		}
		return host.getAttribute( 'data-mshield-id' );
	}

	var remint = {};

	/**
	 * The action this particular widget's token must be signed with.
	 *
	 * Read off the host, never off the page. A page with two challenge forms --
	 * WooCommerce's My Account, which draws login and registration together --
	 * declares the config twice and the last one wins, so a single page-wide
	 * action signed the login form's token for the registration form and the
	 * server rightly rejected it.
	 */
	function actionFor( host ) {
		var surface = host.getAttribute( 'data-surface' ) || '';
		if ( cfg.actions && cfg.actions[ surface ] ) return cfg.actions[ surface ];
		return cfg.action || '';
	}

	function setToken( host, token ) {
		var field = tokenField( host );
		if ( field ) field.value = token || '';
	}

	/**
	 * reCAPTCHA v3: invisible, so there is nothing to draw. Mint a token per
	 * host and refresh it, because a v3 token expires after two minutes and a
	 * login form can easily sit open longer than that.
	 */
	function runRecaptcha() {

		if ( ! window.grecaptcha || ! window.grecaptcha.execute ) return;

		hosts().forEach( function ( host ) {

			host.setAttribute( 'data-mshield-done', '1' );

			function mint() {
				// grecaptcha.ready() guarantees the library has finished
				// initialising. execute() before that rejects, and the catch
				// below would then leave the field empty for ever.
				window.grecaptcha.ready( function () {
					window.grecaptcha.execute( cfg.siteKey, { action: actionFor( host ) } )
						.then( function ( token ) { setToken( host, token ); } )
						.catch( function () { /* leave the field empty; the server decides */ } );
				} );
			}

			// So reset() can re-mint this host. A v3 token is single use and
			// expires after two minutes, exactly like a Turnstile one -- the
			// reset path used to skip reCAPTCHA entirely because only Turnstile
			// was thought to burn its tokens, so a customer who resubmitted
			// after a declined card sent a spent token and was refused.
			remint[ hostId( host ) ] = mint;

			mint();
			// Comfortably inside the two-minute expiry.
			window.setInterval( mint, 100 * 1000 );

		} );

	}

	/**
	 * Turnstile: a real widget, drawn into the host.
	 */
	function runTurnstile() {

		if ( ! window.turnstile || ! window.turnstile.render ) return;

		hosts().forEach( function ( host ) {

			host.setAttribute( 'data-mshield-done', '1' );

			var id = window.turnstile.render( host, {
				sitekey: cfg.siteKey,
				action: actionFor( host ),
				callback: function ( token ) { setToken( host, token ); },
				'expired-callback': function () { setToken( host, '' ); },
				'error-callback': function () {
					// Cloudflare unreachable, or the script blocked. Leave
					// whatever is in the field alone: a spent token reads as
					// "could not confirm" and lets a real person through, while
					// blanking it produced the empty field that used to be a
					// flat refusal.
				}
			} );

			host.setAttribute( 'data-mshield-widget', id );

		} );

	}

	function run() {
		if ( cfg.provider === 'turnstile' ) runTurnstile();
		else runRecaptcha();
	}

	/**
	 * Reset after a failed submit, so a second attempt gets a fresh token.
	 *
	 * BOTH providers burn a token on first verification, and both expire them.
	 * This used to read "a Turnstile token is single-use" and only reset
	 * Turnstile widgets, so under reCAPTCHA a customer correcting a typo or
	 * retrying a declined card resent a spent token and was refused as a bot.
	 */
	function reset() {

		document.querySelectorAll( '.mshield-challenge[data-mshield-done]' ).forEach( function ( host ) {

			var widget = host.getAttribute( 'data-mshield-widget' );

			if ( widget && window.turnstile && window.turnstile.reset ) {
				// Turnstile hands the new token back through its callback.
				window.turnstile.reset( widget );
				return;
			}

			// reCAPTCHA: mint a new one. Deliberately NOT clearing the field
			// first -- an empty field is the one state the server cannot tell
			// apart from a stripped one, whereas a spent token is now read as
			// "could not confirm" and lets the person through.
			var again = remint[ hostId( host ) ];
			if ( again ) again();

		} );

	}

	/**
	 * Keep trying until the provider script has actually loaded.
	 *
	 * run() used to fire exactly once. If window.turnstile or window.grecaptcha
	 * was not populated yet the widget was never drawn, the token stayed empty,
	 * and the server refused a visitor who was never shown anything to solve.
	 * The classic checkout hid this, because jQuery's updated_checkout re-fires
	 * run() repeatedly -- but wp-login.php does not load jQuery, so login,
	 * registration and password reset got one shot and silently lost the race.
	 *
	 * Bounded: roughly ten seconds, then give up. By then the script is blocked
	 * rather than slow, and the server's fail-open path is the right answer.
	 */
	function ready() {
		return cfg.provider === 'turnstile'
			? !! ( window.turnstile && window.turnstile.render )
			// .ready as well as .execute: api.js defines the object before the
			// library is usable, and execute() called too early rejects.
			: !! ( window.grecaptcha && window.grecaptcha.execute && window.grecaptcha.ready );
	}

	var tries = 0;

	function attempt() {

		if ( ready() ) { run(); return; }

		if ( ++tries > 50 ) return;

		window.setTimeout( attempt, 200 );

	}

	function start() {
		if ( cfg.provider !== 'turnstile' && window.grecaptcha && window.grecaptcha.ready ) {
			window.grecaptcha.ready( run );
			return;
		}
		attempt();
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', start );
	} else {
		start();
	}

	// The classic checkout replaces its own markup on every update.
	if ( window.jQuery ) {
		window.jQuery( document.body ).on( 'updated_checkout', run );
		window.jQuery( document.body ).on( 'checkout_error', reset );
	}

	// And any other form that redraws itself -- a block theme's login, a
	// popup checkout -- without depending on jQuery being present to tell us.
	if ( window.MutationObserver ) {
		new window.MutationObserver( function () {
			if ( document.querySelector( '.mshield-challenge:not([data-mshield-done])' ) ) run();
		} ).observe( document.documentElement, { childList: true, subtree: true } );
	}

} )();
