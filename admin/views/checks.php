<?php
/**
 * Retired in 1.9.0.
 *
 * The Checks tab held per-layer configuration on its own page. That split
 * configuring a check from deciding what it was worth, so those settings now
 * appear on the signal's own row on the Scoring tab and this tab redirects
 * there.
 *
 * Kept as a stub rather than deleted so a stale bookmark or a cached menu entry
 * cannot produce a missing-file warning.
 *
 * @package MightyShield
 * @since   1.9.0
 */

if( ! defined( 'WPINC' ) ) { die; }

wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=scoring' ) );
exit;
