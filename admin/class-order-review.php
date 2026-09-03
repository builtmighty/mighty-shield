<?php
/**
 * RETIRED — replaced by admin/class-order-panel.php in 1.9.5.
 *
 * This file is a tombstone. It is no longer required or instantiated from
 * mighty-shield.php, and it defines nothing. DELETE IT.
 *
 * It held the Fraud Review panel: an Approve/Deny box in the order screen's
 * main column that rendered only for orders carrying _mshield_ai_flagged, a
 * meta key nothing in the plugin had written for two versions — so its AI
 * branch was unreachable and only the detained branch ever appeared. It also
 * wrote its decision to _mshield_ai_decision and stopped there, never calling
 * outcomes::record(), so denying a fraudulent order taught the scoring engine
 * nothing at all.
 *
 * order_panel replaces it: right column, on every order, with the trust badge,
 * the reasons, a reversible reviewer verdict that does reach identity
 * reputation, and the same capture/void/blocklist logic carried over intact.
 *
 * @package MightyShield
 * @since   1.8.0
 * @deprecated 1.9.5
 */

if( ! defined( 'WPINC' ) ) { die; }
