<?php
/**
 * Access Control tab.
 *
 * Allowlist and Blocklist: one question, who is allowed to reach this store at
 * all. Each keeps its own form and its own save handler, so composing them here
 * changed no behaviour.
 *
 * The Firewall section that used to open this page moved to Blocking in 1.9.3 —
 * the Store API switches decide what gets BLOCKED, which is that page's subject,
 * not this one's. There is no Settings API form left here; both remaining forms
 * self-post to handle_actions().
 *
 * @package MightyShield
 * @since   1.9.0
 */

if( ! defined( 'WPINC' ) ) { die; }

include MSHIELD_PATH . 'admin/views/whitelist.php';
include MSHIELD_PATH . 'admin/views/blocklist.php';
