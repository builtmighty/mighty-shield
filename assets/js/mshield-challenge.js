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
				window.grecaptcha.execute( cfg.siteKey, { action: cfg.action } )
					.then( function ( token ) { setToken( host, token ); } )
					.catch( function () { /* leave the field empty; the server decides */ } );
			}

			mint();
			// Comfortably inside the two-minute expiry.
			window.setInterval( mint, 100 * 1000 );

			// A submit that finds a stale field is worse than a slightly slow
			// one, so refresh on the way out too.
			var form = host.closest( 'form' );
			if ( form ) form.addEventListener( 'submit', mint );

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
				action: cfg.action,
				callback: function ( token ) { setToken( host, token ); },
				'expired-callback': function () { setToken( host, '' ); },
				'error-callback': function () {
					// Cloudflare unreachable. Leave the field empty and let the
					// server's fail-open rules decide, rather than blocking a
					// real person because a third party is down.
					setToken( host, '' );
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
	 * A Turnstile token is single-use — without this, correcting a typo in your
	 * password and submitting again fails the challenge rather than the login.
	 */
	function reset() {

		document.querySelectorAll( '.mshield-challenge[data-mshield-widget]' ).forEach( function ( host ) {
			if ( window.turnstile && window.turnstile.reset ) {
				window.turnstile.reset( host.getAttribute( 'data-mshield-widget' ) );
			}
			setToken( host, '' );
		} );

	}

	if ( window.grecaptcha && window.grecaptcha.ready ) {
		window.grecaptcha.ready( run );
	} else if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', run );
	} else {
		run();
	}

	// The classic checkout replaces its own markup on every update.
	if ( window.jQuery ) {
		window.jQuery( document.body ).on( 'updated_checkout', run );
		window.jQuery( document.body ).on( 'checkout_error', reset );
	}

} )();
