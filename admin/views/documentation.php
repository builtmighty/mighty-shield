<?php
/**
 * Documentation view.
 *
 * Self-contained, light-mode user guide for MightyShield. Styling follows
 * docs-style-guide.md (Apple HIG-inspired, brand-red accent, no images).
 * All CSS is scoped under .mshield-docs so it never affects other tabs.
 *
 * @package MightyShield
 * @since   1.4.0
 */

if( ! defined( 'WPINC' ) ) { die; }

$fraud_url     = admin_url( 'admin.php?page=mighty-shield&tab=fraud' );
$rates_url     = admin_url( 'admin.php?page=mighty-shield&tab=rates' );
$firewall_url  = admin_url( 'admin.php?page=mighty-shield&tab=firewall' );
$whitelist_url = admin_url( 'admin.php?page=mighty-shield&tab=whitelist' );
$blocklist_url = admin_url( 'admin.php?page=mighty-shield&tab=blocklist' );
$logs_url      = admin_url( 'admin.php?page=mighty-shield&tab=logs' );
?>

<div class="mshield-docs">

    <style>
        .mshield-docs {
            --bg: #ffffff;
            --surface: #f5f5f7;
            --text: #1d1d1f;
            --text-secondary: #6e6e73;
            --border: #d2d2d7;
            --accent: #d4121f;
            --accent-tint: #fdecec;
            font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: var(--text);
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-top: 12px;
            display: flex;
            align-items: flex-start;
            gap: 48px;
            max-width: 1120px;
        }
        .mshield-docs * { box-sizing: border-box; }

        /* Sidebar */
        .mshield-docs-nav {
            flex: 0 0 240px;
            position: sticky;
            top: 32px;
            align-self: flex-start;
            padding: 28px 20px;
            border-right: 1px solid var(--border);
            max-height: calc(100vh - 64px);
            overflow-y: auto;
        }
        .mshield-docs-nav .nav-title {
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-secondary);
            margin: 22px 0 8px;
        }
        .mshield-docs-nav .nav-title:first-child { margin-top: 0; }
        .mshield-docs-nav a {
            display: block;
            padding: 5px 10px;
            font-size: 14px;
            color: var(--text);
            text-decoration: none;
            border-left: 2px solid transparent;
            border-radius: 0 4px 4px 0;
        }
        .mshield-docs-nav a:hover { color: #000; background: var(--surface); }
        .mshield-docs-nav a.active { color: var(--accent); border-left-color: var(--accent); font-weight: 600; }

        /* Reading column */
        .mshield-docs-main {
            flex: 1 1 auto;
            max-width: 760px;
            padding: 32px 40px 64px;
            min-width: 0;
        }
        .mshield-docs-main h1 {
            font-size: 40px;
            font-weight: 700;
            line-height: 1.1;
            letter-spacing: -0.02em;
            margin: 0 0 8px;
            color: var(--text);
        }
        .mshield-docs-main .lede { font-size: 17px; color: var(--text-secondary); margin: 0 0 8px; }
        .mshield-docs-main h2 {
            font-size: 28px;
            font-weight: 600;
            line-height: 1.2;
            letter-spacing: -0.01em;
            margin: 56px 0 12px;
            padding-top: 12px;
            color: var(--text);
        }
        .mshield-docs-main h3 {
            font-size: 20px;
            font-weight: 600;
            line-height: 1.3;
            margin: 32px 0 8px;
            color: var(--text);
        }
        .mshield-docs-main p,
        .mshield-docs-main li { font-size: 16px; line-height: 1.6; color: var(--text); }
        .mshield-docs-main a { color: var(--accent); text-decoration: none; }
        .mshield-docs-main a:hover { text-decoration: underline; }
        .mshield-docs-main code {
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            font-size: 14px;
            background: var(--surface);
            border-radius: 4px;
            padding: 2px 6px;
            color: var(--text);
        }
        .mshield-docs-main table {
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 14px;
        }
        .mshield-docs-main th,
        .mshield-docs-main td {
            border: 1px solid var(--border);
            padding: 8px 12px;
            text-align: left;
            vertical-align: top;
            line-height: 1.5;
        }
        .mshield-docs-main th { background: var(--surface); font-weight: 600; }
        .mshield-docs-main .default { color: var(--text-secondary); white-space: nowrap; }

        .mshield-docs-main .callout {
            border: 1px solid var(--border);
            border-left: 3px solid var(--text-secondary);
            border-radius: 6px;
            padding: 12px 16px;
            margin: 20px 0;
            background: var(--bg);
        }
        .mshield-docs-main .callout .callout-label {
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-secondary);
            display: block;
            margin-bottom: 4px;
        }
        .mshield-docs-main .callout.important { border-left-color: var(--accent); background: var(--accent-tint); }
        .mshield-docs-main .callout.important .callout-label { color: var(--accent); }
        .mshield-docs-main .callout p { margin: 0; font-size: 15px; }

        .mshield-docs-main .field {
            font-weight: 600;
        }
        .mshield-docs-main hr { border: 0; border-top: 1px solid var(--border); margin: 40px 0; }
        .mshield-docs-main ul, .mshield-docs-main ol { padding-left: 22px; }
        .mshield-docs-main li { margin: 4px 0; }

        @media screen and (max-width: 900px) {
            .mshield-docs { flex-direction: column; gap: 0; }
            .mshield-docs-nav {
                position: static;
                flex-basis: auto;
                width: 100%;
                border-right: 0;
                border-bottom: 1px solid var(--border);
                max-height: none;
            }
            .mshield-docs-main { padding: 24px; max-width: none; }
        }
    </style>

    <aside class="mshield-docs-nav">
        <div class="nav-title"><?php esc_html_e( 'Getting started', 'mighty-shield' ); ?></div>
        <a href="#overview"><?php esc_html_e( 'Overview', 'mighty-shield' ); ?></a>
        <a href="#quick-start"><?php esc_html_e( 'Quick start', 'mighty-shield' ); ?></a>
        <a href="#actions"><?php esc_html_e( 'Actions explained', 'mighty-shield' ); ?></a>

        <div class="nav-title"><?php esc_html_e( 'Tabs', 'mighty-shield' ); ?></div>
        <a href="#dashboard"><?php esc_html_e( 'Dashboard', 'mighty-shield' ); ?></a>
        <a href="#firewall"><?php esc_html_e( 'Firewall', 'mighty-shield' ); ?></a>
        <a href="#whitelist"><?php esc_html_e( 'Allowlist', 'mighty-shield' ); ?></a>
        <a href="#blocklist"><?php esc_html_e( 'Blocklist', 'mighty-shield' ); ?></a>
        <a href="#rate-limits"><?php esc_html_e( 'Rate Limits', 'mighty-shield' ); ?></a>
        <a href="#fraud"><?php esc_html_e( 'Fraud Checks', 'mighty-shield' ); ?></a>
        <a href="#ai"><?php esc_html_e( 'AI Detection', 'mighty-shield' ); ?></a>
        <a href="#logs"><?php esc_html_e( 'Logs', 'mighty-shield' ); ?></a>

        <div class="nav-title"><?php esc_html_e( 'Help', 'mighty-shield' ); ?></div>
        <a href="#situations"><?php esc_html_e( 'Common situations', 'mighty-shield' ); ?></a>
    </aside>

    <main class="mshield-docs-main">

        <h1><?php esc_html_e( 'MightyShield documentation', 'mighty-shield' ); ?></h1>
        <p class="lede"><?php esc_html_e( 'What each setting does, and how to set the plugin up. Written for store owners, not developers.', 'mighty-shield' ); ?></p>

        <h2 id="overview"><?php esc_html_e( 'Overview', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'MightyShield protects your WooCommerce store from card testing, where an attacker runs many stolen cards through your checkout to find ones that work. This creates a flood of bad orders and can put your payment processor account at risk.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'Protection works in two layers:', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'Store API firewall.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Blocks automated software from hitting the built-in WooCommerce cart and checkout API endpoints directly. Because your store uses the normal (classic) checkout, real customers are not affected.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Checkout protections.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'A set of fraud checks that run on the real checkout form: rate limits, address checks, a hidden bot trap, timing, device checks, and an optional bot challenge.', 'mighty-shield' ); ?></li>
        </ul>
        <p><?php esc_html_e( 'Most checks let you choose how strict to be. See "Actions explained" below. Anything or anyone you add to the allowlist skips every check, so trusted staff and known-good customers are never affected.', 'mighty-shield' ); ?></p>

        <h2 id="quick-start"><?php esc_html_e( 'Quick start', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'A safe way to get set up without risking real orders:', 'mighty-shield' ); ?></p>
        <ol>
            <li><?php printf( wp_kses_post( __( 'Confirm the plugin is on. Open the <a href="%s">Firewall</a> tab and check that Enable MightyShield is ticked.', 'mighty-shield' ) ), esc_url( $firewall_url ) ); ?></li>
            <li><?php printf( wp_kses_post( __( 'Allowlist yourself. On the <a href="%s">Allowlist</a> tab, add your own IP address (or your WordPress user account) so you can never be blocked while testing.', 'mighty-shield' ) ), esc_url( $whitelist_url ) ); ?></li>
            <li><?php esc_html_e( 'Keep the defaults. The out-of-the-box settings are safe for a normal store. You do not need to change anything to be protected.', 'mighty-shield' ); ?></li>
            <li><?php printf( wp_kses_post( __( 'Watch the <a href="%s">Logs</a> for a few days. See what is being blocked and flagged before you make anything stricter.', 'mighty-shield' ) ), esc_url( $logs_url ) ); ?></li>
            <li><?php esc_html_e( 'Tighten if needed. If you are getting fraud, switch the high-value checks from Flag to Block, turn on the Bot Challenge, and add repeat offenders to the blocklist.', 'mighty-shield' ); ?></li>
        </ol>
        <div class="callout important">
            <span class="callout-label"><?php esc_html_e( 'Important', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'Always allowlist your own IP or account before switching checks to Block. This keeps you from locking yourself out of your own checkout while testing.', 'mighty-shield' ); ?></p>
        </div>

        <h2 id="actions"><?php esc_html_e( 'Actions explained', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'Most checks share the same three choices for what happens when something looks suspicious:', 'mighty-shield' ); ?></p>
        <table>
            <thead><tr><th><?php esc_html_e( 'Action', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What happens', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'When to use it', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td><span class="field"><?php esc_html_e( 'Block', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'The order is stopped before it is placed. The customer sees an error.', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'For checks you trust to be accurate, or when under active attack.', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Flag', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'The order is allowed, but a note is added to it so you can review it later.', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'A safe way to watch a check before you trust it to block.', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Flag + notify', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Same as Flag, and an email is sent to the site admin address.', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'When you want to be told right away but not stop the sale.', 'mighty-shield' ); ?></td></tr>
            </tbody>
        </table>
        <p><?php esc_html_e( 'Every block, flag, and rate limit is recorded on the Logs tab regardless of the action.', 'mighty-shield' ); ?></p>

        <hr>

        <h2 id="dashboard"><?php esc_html_e( 'Dashboard', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'A read-only overview. There is nothing to configure here.', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'Protection status.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Confirms whether MightyShield is active.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Event counts.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Totals for the last 24 hours, 7 days, and 30 days, split into Total Events, Blocked, Rate Limited, and Flagged.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Top Blocked IPs.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'The addresses hitting your store hardest over the last 7 days, with a link into the logs.', 'mighty-shield' ); ?></li>
        </ul>

        <h2 id="firewall"><?php esc_html_e( 'Firewall', 'mighty-shield' ); ?></h2>
        <table>
            <thead><tr><th><?php esc_html_e( 'Setting', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What it does', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Default', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td><span class="field"><?php esc_html_e( 'Enable MightyShield', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'The master switch. When off, every protection stops. The admin screens stay available.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'On', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Block Store API', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Blocks non-allowlisted addresses from the WooCommerce cart and checkout API endpoints. Leave on for classic checkout stores. Turn off only if you use block-based (React) checkout.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'On', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Log Retention', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How many days to keep log entries before they are cleaned up automatically. Range 1 to 365.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '30 days', 'mighty-shield' ); ?></td></tr>
            </tbody>
        </table>
        <div class="callout important">
            <span class="callout-label"><?php esc_html_e( 'Important', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'If you use the newer block-based checkout instead of classic checkout, turn Block Store API off, because that checkout uses the same API endpoints as the firewall protects.', 'mighty-shield' ); ?></p>
        </div>

        <h2 id="whitelist"><?php esc_html_e( 'Allowlist', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'Anything on it bypasses every MightyShield check, with no blocks and no flags. Use it for trusted staff, offices, and known-good customers. An allowlist entry always wins over the blocklist.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'You can allowlist four kinds of thing:', 'mighty-shield' ); ?></p>
        <table>
            <thead><tr><th><?php esc_html_e( 'Type', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What to enter', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Matches', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td><span class="field"><?php esc_html_e( 'IP address / CIDR', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'A single address like 192.168.1.1, or a range like 10.0.0.0/8.', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'Anyone connecting from that address or range.', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'WordPress user', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'A username, an account email, or a user ID.', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'That customer when logged in, and orders tied to their account.', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Email address', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'A full email address.', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'Any checkout using that billing email (guests included).', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'User role', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'A role chosen from the dropdown, such as Administrator or Shop manager.', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'Every logged-in user who has that role.', 'mighty-shield' ); ?></td></tr>
            </tbody>
        </table>
        <div class="callout important">
            <span class="callout-label"><?php esc_html_e( 'Important', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'An allowlisted role exempts every user in it. Allowlisting a broad role such as Customer would let all of those users skip every check, so prefer staff roles like Administrator or Shop manager.', 'mighty-shield' ); ?></p>
        </div>
        <p><?php printf( wp_kses_post( __( 'Add entries with the form on the <a href="%s">Allowlist</a> tab, or use the "allowlist" link on any row in the Logs. Remove an entry with its Remove button.', 'mighty-shield' ) ), esc_url( $whitelist_url ) ); ?></p>

        <h2 id="blocklist"><?php esc_html_e( 'Blocklist', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'A permanent ban list for IP addresses and ranges. Blocked addresses are refused at both the classic checkout and the Store API, and the ban never expires until you remove it. This is different from the automatic temporary blocks, which last 24 hours by default.', 'mighty-shield' ); ?></p>
        <p><?php printf( wp_kses_post( __( 'Add an address on the <a href="%1$s">Blocklist</a> tab, or use the "block" link on any row in the <a href="%2$s">Logs</a>. Allowlisted addresses are never blocked, even if they also appear here.', 'mighty-shield' ) ), esc_url( $blocklist_url ), esc_url( $logs_url ) ); ?></p>

        <h2 id="rate-limits"><?php esc_html_e( 'Rate Limits', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'These limits catch the rapid, repeated attempts that card testing creates. When a limit is passed, the address is temporarily blocked.', 'mighty-shield' ); ?></p>
        <table>
            <thead><tr><th><?php esc_html_e( 'Setting', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What it does', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Default', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td><span class="field"><?php esc_html_e( 'Max Checkout Attempts', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How many checkout attempts one address may make within the time window below.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '5', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Time Window', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'The length of that window, in seconds. 3600 is one hour.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '3600 (1 hour)', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Unique Email Threshold', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Blocks an address that uses more than this many different email addresses in an hour. Card testers rotate emails.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '3', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Order Attempt Threshold', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Blocks an address that places more than this many orders in 15 minutes.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '5', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Failed Payment Threshold', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Temporarily blocks an address after this many failed payments in an hour.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '5', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Temporary Block Duration', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How long a temporary block lasts, in seconds. 86400 is 24 hours.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '86400 (24 hours)', 'mighty-shield' ); ?></td></tr>
            </tbody>
        </table>

        <h2 id="fraud"><?php esc_html_e( 'Fraud Checks', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'The main set of protections that run on the checkout form. Each one can be turned on or off, and most let you pick Block, Flag, or Flag + notify.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Email Domain Blocking', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Blocks checkouts that use disposable or temporary email services. A built-in list of about 160 domains is always active. In Additional Blocked Domains, add your own domains, one per line, to extend the list.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Order Amount Validation', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Card testers often place very small orders to check whether a card works. Minimum Order Amount sets the floor (default 1.00; set to 0 to disable). Action on Suspicious Amount chooses what happens to an order below the floor, and defaults to Flag.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Address Validation', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Scores billing addresses for fake or nonsensical patterns, such as single-character names or repeated-digit ZIP codes. Sensitivity sets how aggressive the scoring is: Low, Medium (default), or High. Higher sensitivity catches more but can flag more real customers by mistake.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Smarty Address Verification (US only)', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Checks US billing addresses against official USPS data to catch fake or undeliverable addresses. It is off by default and needs a free API key.', 'mighty-shield' ); ?></p>
        <ol>
            <li><?php esc_html_e( 'Create an account at smarty.com and get your auth-id and auth-token.', 'mighty-shield' ); ?></li>
            <li><?php esc_html_e( 'Tick Enable Smarty Verification, paste the Auth ID and Auth Token, and save.', 'mighty-shield' ); ?></li>
            <li><?php esc_html_e( 'Choose Action on Failed Verification (default Flag).', 'mighty-shield' ); ?></li>
        </ol>
        <div class="callout note">
            <span class="callout-label"><?php esc_html_e( 'Note', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'The token field stays blank after saving for security. Leave it blank to keep the saved token. If Smarty is ever unavailable, MightyShield falls back to the ZIP/State check automatically.', 'mighty-shield' ); ?></p>
        </div>

        <h3><?php esc_html_e( 'ZIP/State Mismatch (US only)', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Catches US orders where the billing ZIP code does not belong to the billing state. It needs no API and is on by default, with an action of Block. It also serves as the fallback when Smarty is unavailable.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Honeypot Field', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Adds an invisible field to the checkout form. Real people never see it, but many bots fill it in. It has effectively zero false positives, is on by default, and defaults to Block.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Checkout Timing', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Measures how long a shopper takes to submit checkout. Bots submit far faster than a person can. It does not depend on the IP address or the products, so it keeps working even when attackers rotate through VPNs or change products.', 'mighty-shield' ); ?></p>
        <table>
            <thead><tr><th><?php esc_html_e( 'Setting', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What it does', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Default', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td><span class="field"><?php esc_html_e( 'Minimum Seconds', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Submissions faster than this many seconds are treated as automated. Keep it conservative, 3 to 5, to avoid catching fast real shoppers.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '4', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Action on Fast Submission', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'What to do with a too-fast checkout. Defaults to Flag so you can watch the logs before enforcing.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Flag', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Action on Missing Token', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'What to do when the timing token is missing, the sign of a scripted checkout that never loaded the form. Flag by default in case a cache strips the field; set to Block when under attack. Only applies when the action above is Block.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Flag only', 'mighty-shield' ); ?></td></tr>
            </tbody>
        </table>

        <h3><?php esc_html_e( 'Device Fingerprinting', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Collects harmless browser details (timezone, language, screen size) to spot automated browsers and mismatches between the browser and the billing country. It is off by default.', 'mighty-shield' ); ?></p>
        <table>
            <thead><tr><th><?php esc_html_e( 'Setting', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What it does', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Default', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td><span class="field"><?php esc_html_e( 'Action on Suspicious Device', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'What to do when an automated browser or a timezone/country mismatch is detected.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Block', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Action on Missing Fingerprint', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'What to do when no fingerprint is sent (JavaScript did not run). Flag by default for the rare no-JavaScript shopper; set to Block when under attack. Only applies when the action above is Block.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Flag only', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Device Velocity Threshold', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Max checkout attempts from the same device within the checkout time window, no matter how the IP changes. Catches attackers rotating IPs via VPN. Set to 0 to disable.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '5', 'mighty-shield' ); ?></td></tr>
            </tbody>
        </table>

        <h3><?php esc_html_e( 'Bot Challenge (CAPTCHA)', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Adds an invisible bot challenge to checkout. It is off by default and needs keys from the provider. Cloudflare Turnstile is free and privacy-friendly and is the recommended choice; Google reCAPTCHA v3 is also supported.', 'mighty-shield' ); ?></p>
        <ol>
            <li><?php esc_html_e( 'Choose a Provider (Cloudflare Turnstile or Google reCAPTCHA v3).', 'mighty-shield' ); ?></li>
            <li><?php esc_html_e( 'Get a Site Key and Secret Key from the provider. Turnstile: dash.cloudflare.com. reCAPTCHA: google.com/recaptcha/admin.', 'mighty-shield' ); ?></li>
            <li><?php esc_html_e( 'Paste both keys, pick Action on Failed Challenge (default Block), and save.', 'mighty-shield' ); ?></li>
        </ol>

        <h2 id="ai"><?php esc_html_e( 'AI Detection', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'AI Detection sends orders to an AI model to be rated for fraud risk. The model returns a score from 1 (almost certainly fraud) to 10 (clean). Orders that score at or below your threshold are put On hold and queued for you to review, so a real person makes the final call before the order ships.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'It is off by default and needs an API key from one of the supported providers. AI Detection runs after the other checks, as a second opinion on orders that get through — it never blocks a customer at checkout on its own.', 'mighty-shield' ); ?></p>

        <table>
            <thead><tr><th><?php esc_html_e( 'Setting', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What it does', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Default', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td><span class="field"><?php esc_html_e( 'Enable AI Detection', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'The on/off switch for the whole feature. When off, no orders are sent to any AI provider.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Off', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Provider', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Which AI service to use: Anthropic (Claude), OpenAI, or Google Gemini. Each needs its own API key (see setup below).', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Anthropic', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Which orders to review', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Suspicious only sends an order to the AI only when it trips one of the signals below — this keeps API costs down. All orders sends every order for a rating.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Suspicious only', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Sensitivity', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How many signals it takes to treat an order as suspicious. High = any one signal, Medium = any two, Low = all of them.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Medium', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Signals', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'The patterns that mark an order as suspicious: repeated orders from one address, a name that does not match the email, an unusually high order total, and a billing country that does not match the IP location. Each can be turned on or off.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'All on', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Rating threshold', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Orders rated at or below this number (1-10) are held for review. Higher = stricter (more orders held).', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '4', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'When an order is flagged', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Flag for review holds the order after payment. Authorize only (when your gateway supports it) reserves the funds without capturing them, so approving captures and denying releases the hold — no refund needed.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Flag for review', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Notify admin', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Emails you when an order is held for review. You can set custom recipient addresses.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'On', 'mighty-shield' ); ?></td></tr>
            </tbody>
        </table>

        <div class="callout note">
            <span class="callout-label"><?php esc_html_e( 'Note', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'API key fields stay blank after saving for security — an existing key is kept unless you type a new one. If the AI provider is unreachable or the key is wrong, MightyShield fails open (it lets the order through and shows an admin warning) rather than blocking real orders.', 'mighty-shield' ); ?></p>
        </div>

        <h3><?php esc_html_e( 'Reviewing flagged orders', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Held orders appear in two places: a Fraud Review screen under WooCommerce → Orders (with a count badge showing how many are waiting), and a MightyShield — Fraud Review panel at the top of each held order. From the panel you Approve (capture/keep the order and move it to Processing) or Deny (release or flag for refund, and add the customer IP to the blocklist).', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Getting an API key', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Pick one provider and create an API key in its console, then paste it into the matching field on the AI Detection tab. All three are pay-as-you-go; the default models are inexpensive.', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'Anthropic (Claude):', 'mighty-shield' ); ?></strong> <?php echo wp_kses_post( __( 'Sign in at <a href="https://console.anthropic.com/settings/keys" target="_blank" rel="noopener">console.anthropic.com/settings/keys</a> and create a key. Add billing credit under Plans &amp; Billing. Default model: <span class="field">claude-haiku-4-5</span>.', 'mighty-shield' ) ); ?></li>
            <li><strong><?php esc_html_e( 'OpenAI:', 'mighty-shield' ); ?></strong> <?php echo wp_kses_post( __( 'Sign in at <a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener">platform.openai.com/api-keys</a> and create a secret key. An Organization ID (from your account settings) is optional. Default model: <span class="field">gpt-4o-mini</span>.', 'mighty-shield' ) ); ?></li>
            <li><strong><?php esc_html_e( 'Google Gemini:', 'mighty-shield' ); ?></strong> <?php echo wp_kses_post( __( 'Sign in at <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener">aistudio.google.com/app/apikey</a> (Google AI Studio) and click Create API key. Default model: <span class="field">gemini-1.5-flash</span>.', 'mighty-shield' ) ); ?></li>
        </ul>

        <div class="callout note">
            <span class="callout-label"><?php esc_html_e( 'Tip', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'Start with Suspicious only and the default threshold, watch the Fraud Review queue for a few days, then raise the threshold or switch to All orders if you want the AI to weigh in on everything.', 'mighty-shield' ); ?></p>
        </div>

        <h2 id="logs"><?php esc_html_e( 'Logs', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'A record of every action MightyShield takes. Each row shows the time, the IP address, the action (Blocked, Rate Limited, Flagged, or Exempt for allowlisted visitors), the endpoint, the reason, and details such as the email, user, and browser.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'Filter by action or by IP address at the top. On each row you can:', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'filter', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'to show only that IP address.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'block', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'to add that IP to the blocklist.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'allowlist', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'to allow that IP, email, or user past all checks.', 'mighty-shield' ); ?></li>
        </ul>
        <p><?php esc_html_e( 'Clear All Logs in the Maintenance section empties the whole log. This cannot be undone.', 'mighty-shield' ); ?></p>

        <hr>

        <h2 id="situations"><?php esc_html_e( 'Common situations', 'mighty-shield' ); ?></h2>

        <h3><?php esc_html_e( 'A real customer was blocked', 'mighty-shield' ); ?></h3>
        <p><?php printf( wp_kses_post( __( 'Open the <a href="%s">Logs</a>, find their entry, and use the "allowlist" link on that row (by IP, email, or user). They will bypass all checks from then on. If a whole check is catching real customers, switch it from Block to Flag while you investigate.', 'mighty-shield' ) ), esc_url( $logs_url ) ); ?></p>

        <h3><?php esc_html_e( 'We are under active attack', 'mighty-shield' ); ?></h3>
        <p><?php printf( wp_kses_post( __( 'On the <a href="%1$s">Fraud Checks</a> tab, set Action on Missing Token and Action on Missing Fingerprint to Block (and make sure their main actions are Block), and turn on the Bot Challenge. Add the worst repeat IPs to the <a href="%2$s">blocklist</a>. Lower the rate limits on the <a href="%3$s">Rate Limits</a> tab if the flood continues.', 'mighty-shield' ) ), esc_url( $fraud_url ), esc_url( $blocklist_url ), esc_url( $rates_url ) ); ?></p>

        <h3><?php esc_html_e( 'Turn everything off quickly', 'mighty-shield' ); ?></h3>
        <p><?php printf( wp_kses_post( __( 'On the <a href="%s">Firewall</a> tab, untick Enable MightyShield and save. All protections stop at once, and this admin area stays available.', 'mighty-shield' ) ), esc_url( $firewall_url ) ); ?></p>

    </main>

</div>

<script>
( function() {
    // Highlight the sidebar link for the section currently in view.
    var nav = document.querySelector( '.mshield-docs-nav' );
    if ( ! nav ) return;
    var links    = Array.prototype.slice.call( nav.querySelectorAll( 'a' ) );
    var sections = links
        .map( function( a ) { return document.getElementById( a.getAttribute( 'href' ).slice( 1 ) ); } )
        .filter( Boolean );

    function onScroll() {
        var pos = window.scrollY + 120;
        var current = sections[0];
        for ( var i = 0; i < sections.length; i++ ) {
            if ( sections[i].offsetTop <= pos ) current = sections[i];
        }
        links.forEach( function( a ) {
            a.classList.toggle( 'active', current && a.getAttribute( 'href' ) === '#' + current.id );
        } );
    }
    window.addEventListener( 'scroll', onScroll );
    onScroll();
} )();
</script>
