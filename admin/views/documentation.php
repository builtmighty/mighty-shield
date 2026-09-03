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

// Every link points at a tab that exists. The old set pointed at fraud, rates,
// whitelist and blocklist, all merged away in 1.9.0 -- the redirects kept the
// links working while the surrounding prose named tabs nobody could find.
// Prefixed, because a view is included into whatever scope the caller has. A
// bare $tab here overwrote the includer's own $tab, and admin_page::render_page()
// uses exactly that name for the active tab.
$mshield_doc_tab = function( $slug ) { return admin_url( 'admin.php?page=mighty-shield&tab=' . $slug ); };

$dashboard_url = $mshield_doc_tab( 'dashboard' );
$scoring_url   = $mshield_doc_tab( 'scoring' );
$ai_url        = $mshield_doc_tab( 'ai' );
$blocking_url  = $mshield_doc_tab( 'blocking' );
$payment_url   = $mshield_doc_tab( 'payment' );
$access_url    = $mshield_doc_tab( 'access' );
$logs_url      = $mshield_doc_tab( 'logs' );
$queue_url     = admin_url( 'admin.php?page=mshield-fraud-review' );

// The action vocabulary is read from the catalogue rather than restated, so a
// new action cannot appear in the plugin and be missing from the manual.
$actions = \MightyShield\Includes\actions::CATALOG;
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
        .mshield-docs-main h4 {
            font-size: 16px;
            font-weight: 600;
            line-height: 1.35;
            margin: 24px 0 6px;
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
        <a href="#lifecycle"><?php esc_html_e( 'How an order is judged', 'mighty-shield' ); ?></a>
        <a href="#quick-start"><?php esc_html_e( 'Quick start', 'mighty-shield' ); ?></a>
        <a href="#actions"><?php esc_html_e( 'What MightyShield can do', 'mighty-shield' ); ?></a>

        <div class="nav-title"><?php esc_html_e( 'Screens', 'mighty-shield' ); ?></div>
        <a href="#dashboard"><?php esc_html_e( 'Dashboard', 'mighty-shield' ); ?></a>
        <a href="#widget"><?php esc_html_e( 'Dashboard widget', 'mighty-shield' ); ?></a>
        <a href="#scoring"><?php esc_html_e( 'Scoring', 'mighty-shield' ); ?></a>
        <a href="#ai"><?php esc_html_e( 'AI Review', 'mighty-shield' ); ?></a>
        <a href="#blocking"><?php esc_html_e( 'Blocking', 'mighty-shield' ); ?></a>
        <a href="#payment"><?php esc_html_e( 'Payment', 'mighty-shield' ); ?></a>
        <a href="#access"><?php esc_html_e( 'Access', 'mighty-shield' ); ?></a>
        <a href="#logs"><?php esc_html_e( 'Logs', 'mighty-shield' ); ?></a>

        <div class="nav-title"><?php esc_html_e( 'Working orders', 'mighty-shield' ); ?></div>
        <a href="#order-panel"><?php esc_html_e( 'On an order', 'mighty-shield' ); ?></a>
        <a href="#review-queue"><?php esc_html_e( 'Fraud Review', 'mighty-shield' ); ?></a>
        <a href="#memory"><?php esc_html_e( 'How it learns', 'mighty-shield' ); ?></a>

        <div class="nav-title"><?php esc_html_e( 'Help', 'mighty-shield' ); ?></div>
        <a href="#situations"><?php esc_html_e( 'Common situations', 'mighty-shield' ); ?></a>
    </aside>

    <main class="mshield-docs-main">

        <h1><?php esc_html_e( 'MightyShield', 'mighty-shield' ); ?></h1>
        <p class="lede"><?php esc_html_e( 'MightyShield works 24/7 to keep bots, card testers, scammers, fraudsters, and the people running stolen cards from making more work for you, so that you can get on with selling instead of cleaning up after them. It is built to be fine-tuned to your customers rather than somebody else\'s, and everything below explains how to do that by specifying what each setting does and when to reach for it.', 'mighty-shield' ); ?></p>

        <h2 id="overview"><?php esc_html_e( 'Overview', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'MightyShield protects your WooCommerce store from fraudulent and automated orders. The most common is card testing, where an attacker runs many stolen cards through your checkout to find the ones that still work.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'That costs you more than wasted time. Payment processors judge you on how many of your payments are declined or disputed, so a flood of bad orders can put your account under review, into reserves, or shut it down. Stopping those orders before they ever reach your processor matters as much as catching the fraud itself.', 'mighty-shield' ); ?></p>

        <div class="callout important">
            <span class="callout-label"><?php esc_html_e( 'Nothing is enforced until you say so', 'mighty-shield' ); ?></span>
            <p><?php printf( wp_kses_post( __( 'MightyShield installs in Observe mode. It rates every order and records what it would have done, without doing it. Your existing checks carry on working exactly as before. When you are ready, turn enforcement on with the three way switch on the <a href="%s">Dashboard</a>.', 'mighty-shield' ) ), esc_url( $dashboard_url ) ); ?></p>
        </div>

        <h2 id="lifecycle"><?php esc_html_e( 'How an order is judged', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'Every order gets a trust rating from 1 to 100. 100 is completely ordinary; 1 is as bad as it gets. Each check that notices something costs the order some trust, and the rating that comes out decides what happens next.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'Checks work together rather than separately. Three small concerns that individually would not be worth acting on can add up to a rating that is. That is the whole point of a rating: an order that looks slightly odd in several unrelated ways is more suspicious than one that looks odd in a single way.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'The steps, in order', 'mighty-shield' ); ?></h3>
        <ol>
            <li><strong><?php esc_html_e( 'Browsing.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Nothing happens. MightyShield does no work at all on your product and category pages.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'The checkout page loads.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'A hidden trap field, a signed timer, and, if you have turned them on, the device check and the bot challenge are placed in the form.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'The order is submitted.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Every check runs and each one that notices something takes trust away. Some checks can force a risk level on their own, whatever the rating says.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'AI review, if you use it.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'For the risk levels you choose, a model looks at the order and gives its own rating. By default it can only lower the number, never raise it.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'The decision.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'The final rating picks a risk level, the risk level picks an action, and MightyShield checks whether your payment processor can actually carry that action out. Everything is written down before anything is done.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'After payment.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'If your processor reports back on the card checks, an order that paid but failed them is flagged, and held if both the address and the security code failed.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Afterwards.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'How the order turned out is remembered against everyone connected to it, and counts towards the next one.', 'mighty-shield' ); ?></li>
        </ol>

        <h3><?php esc_html_e( 'What each rating means', 'mighty-shield' ); ?></h3>
        <table>
            <thead><tr><th><?php esc_html_e( 'Rating', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Risk Level', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What happens by default', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Reaches your processor', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td>95&ndash;100</td><td><span class="field"><?php esc_html_e( 'Trusted', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Goes through untouched.', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'Yes', 'mighty-shield' ); ?></td></tr>
                <tr><td>76&ndash;94</td><td><span class="field"><?php esc_html_e( 'Low', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Goes through and is marked for you to look at. The customer notices nothing.', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'Yes', 'mighty-shield' ); ?></td></tr>
                <tr><td>51&ndash;75</td><td><span class="field"><?php esc_html_e( 'Elevated', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'The customer confirms the payment with their bank.', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'Yes', 'mighty-shield' ); ?></td></tr>
                <tr><td>26&ndash;50</td><td><span class="field"><?php esc_html_e( 'High', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'The order is created and held with no payment attempted.', 'mighty-shield' ); ?></td><td><strong><?php esc_html_e( 'No', 'mighty-shield' ); ?></strong></td></tr>
                <tr><td>1&ndash;25</td><td><span class="field"><?php esc_html_e( 'Rejected', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Refused at the checkout. No order is created.', 'mighty-shield' ); ?></td><td><strong><?php esc_html_e( 'No', 'mighty-shield' ); ?></strong></td></tr>
                <tr><td><?php esc_html_e( 'n/a', 'mighty-shield' ); ?></td><td><span class="field"><?php esc_html_e( 'Banned', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Refused, and the address is added to your blocklist.', 'mighty-shield' ); ?></td><td><strong><?php esc_html_e( 'No', 'mighty-shield' ); ?></strong></td></tr>
            </tbody>
        </table>
        <p><?php esc_html_e( 'Rejected and Banned orders never reach your payment processor, and High defaults to an action that does not either. That is what keeps spam attempts off your decline and dispute figures.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'Banned has no rating range because no rating can produce it. It is reachable only when a check forces it, and only one does by default: an order linked to a previous chargeback.', 'mighty-shield' ); ?></p>

        <div class="callout">
            <span class="callout-label"><?php esc_html_e( 'Why a new customer is never Trusted', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'An order starts at 100 and spends trust as checks notice things. But an order with nothing known about the customer is capped at 94, which is Low. The top of the scale has to be earned by a clean run of past orders, because knowing nothing about someone is not the same as trusting them.', 'mighty-shield' ); ?></p>
        </div>

        <h2 id="quick-start"><?php esc_html_e( 'Quick start', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'A safe way to get set up without risking real orders:', 'mighty-shield' ); ?></p>
        <ol>
            <li><?php printf( wp_kses_post( __( 'Allowlist yourself first. On the <a href="%s">Access</a> tab, add your own IP address or your WordPress user account, so you can never be blocked while testing.', 'mighty-shield' ) ), esc_url( $access_url ) ); ?></li>
            <li><?php esc_html_e( 'Leave it in Observe mode. Orders are rated and recorded but nothing new is enforced. This is how it arrives, and it is the right place to start.', 'mighty-shield' ); ?></li>
            <li><?php printf( wp_kses_post( __( 'Wait a week or two, then look at <a href="%s">Blocking</a>. It shows how many orders landed at each risk level and how they turned out.', 'mighty-shield' ) ), esc_url( $blocking_url ) ); ?></li>
            <li><?php printf( wp_kses_post( __( 'Check <a href="%s">Scoring</a>. It shows how often each check actually fires on your traffic. Anything firing on most of your orders is describing your customers rather than your fraudsters, so lower what it costs or switch it off.', 'mighty-shield' ) ), esc_url( $scoring_url ) ); ?></li>
            <li><?php printf( wp_kses_post( __( 'Adjust the thresholds until the risk levels match your own judgement, then set the switch on the <a href="%s">Dashboard</a> to Active.', 'mighty-shield' ) ), esc_url( $dashboard_url ) ); ?></li>
        </ol>
        <div class="callout important">
            <span class="callout-label"><?php esc_html_e( 'Important', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'Always allowlist your own IP or account before switching protection to Active. That is what keeps you from locking yourself out of your own checkout.', 'mighty-shield' ); ?></p>
        </div>

        <h2 id="actions"><?php esc_html_e( 'What MightyShield can do', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'Each risk level is set to one action. These are all of them, from the gentlest to the most disruptive, with what each one does to the customer\'s money.', 'mighty-shield' ); ?></p>
        <table>
            <thead><tr><th><?php esc_html_e( 'Action', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What happens', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'The money', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <?php foreach( $actions as $act ) : ?>
                    <tr>
                        <td><span class="field"><?php echo esc_html( $act['label'] ); ?></span></td>
                        <td><?php echo esc_html( $act['desc'] ); ?></td>
                        <td class="default"><?php echo esc_html( $act['money'] ); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <div class="callout important">
            <span class="callout-label"><?php esc_html_e( 'Nothing fails silently', 'mighty-shield' ); ?></span>
            <p><?php printf( wp_kses_post( __( 'Two actions need something from your payment processor. If yours cannot do it, MightyShield does the next best thing rather than nothing: 3-D Secure verification falls back to flagging, and authorize and hold falls back to holding before payment. The <a href="%s">Payment</a> tab shows which of your processors can do what.', 'mighty-shield' ) ), esc_url( $payment_url ) ); ?></p>
        </div>

        <h2 id="dashboard"><?php esc_html_e( 'Dashboard', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'The state of your protection, and what it has been doing.', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'The protection switch.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Three positions, and this is the only place they can be changed. Disabled means no orders are checked at all. Observing means orders are rated and recorded but the rating is not acted on. Active means the rating decides what happens.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'The chart.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Blocked, rate limited and flagged events over 24 hours, 7 days or 30 days. Hovering gives you the numbers for any single point.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Top blocked addresses.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'The busiest offenders of the past week, with where they are and a link to their log entries.', 'mighty-shield' ); ?></li>
        </ul>
        <div class="callout">
            <span class="callout-label"><?php esc_html_e( 'What Observing still does', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'In Observing the individual checks really do still block. What is not happening is the trust rating being acted on. So an order that trips the hidden trap field is still refused; an order that merely scores badly is recorded and let through.', 'mighty-shield' ); ?></p>
        </div>

        <h2 id="widget"><?php esc_html_e( 'Dashboard widget', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'A summary on the main WordPress dashboard, so the state of your protection is the first thing you see when you log in. It reports and does not change anything.', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'The status stripe.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Disabled, Observing or Active. There is no switch on it, because changing that belongs on the screen that explains what the three mean.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'The last 7 days.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'The same chart as the Dashboard, over a shorter window because a sidebar column is narrow, with the totals beside it. The Dashboard tab still shows 30 days.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'What is waiting.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'How many orders are held or flagged with nobody having ruled on them, and a button into the review queue. It only turns amber when there is something to do.', 'mighty-shield' ); ?></li>
        </ul>
        <p><?php esc_html_e( 'The widget appears only for people who can manage WooCommerce. To hide it, use Screen Options at the top of the dashboard. That is a per person setting, so hiding it does not take it away from anyone else.', 'mighty-shield' ); ?></p>

        <h2 id="scoring"><?php esc_html_e( 'Scoring', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'Every check in one table, with what it costs and how often it has actually fired on your traffic. This is where you tune MightyShield to your own customers.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Scoring profiles', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'If you would rather not judge thirty-nine checks one at a time, pick a profile at the top of the tab and it sets every trust cost at once. You can still change any individual row afterwards.', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'Balanced.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'What most stores should use, and what MightyShield ships with. Catches the obvious attacks and leaves ordinary customers alone.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Cautious.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'For a store seeing more fraud than it used to. The checks that point at a specific problem cost more, and MightyShield starts collecting device information at checkout.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Strict.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'For a store under attack, or one selling things worth stealing. Expect to review more orders by hand.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Custom.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Not something you pick. It appears on its own as soon as you change a row yourself, and goes away again if you set that row back. Switching to a profile while you are on Custom replaces the rows you changed, so MightyShield asks first.', 'mighty-shield' ); ?></li>
        </ul>
        <p><?php esc_html_e( 'The stricter profiles deliberately leave some checks alone. Detecting a VPN, a shared office address, a shopper who never moved the mouse or a browser with no cookies all catch real customers as readily as they catch fraud, so raising them would mean turning away travellers, people using a keyboard alone, and small businesses. Those checks stay where they are on every profile, and the ones that point at automation or a stolen card are what goes up.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Reading the table', 'mighty-shield' ); ?></h3>
        <ul>
            <li><strong><?php esc_html_e( 'On or off.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Switching a check off stops it contributing anything at all. Prefer lowering its cost first, so it still counts for something.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Trust cost.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'How much of the 100 an order loses when this check notices something. A check that is only partly sure costs proportionally less, which is what lets several small concerns add up without any one of them taking over.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Force level.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Makes one check decide the outcome on its own, whatever the rating says. Use it only for things a real customer essentially cannot do, such as filling in a hidden trap field. Anything genuinely ambiguous should be left on scoring only, so the rating can weigh it against everything else.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'How often it fires.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Measured on your own orders over the last 30 days. This is the most useful column on the page. A check firing on half your orders is describing your customers, not your fraudsters.', 'mighty-shield' ); ?></li>
        </ul>
        <div class="callout">
            <span class="callout-label"><?php esc_html_e( 'One check gives trust back', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'Known good customer has a negative cost. It is the only check that adds trust rather than spending it, and it is the only way an order can reach Trusted. A customer earns it with three or more orders and a clean history, and loses it the moment anything connected to them goes bad.', 'mighty-shield' ); ?></p>
        </div>

        <h3><?php esc_html_e( 'The checks, and what they look at', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Every check has its own settings on its row. These are the ones with numbers worth knowing about.', 'mighty-shield' ); ?></p>
        <table>
            <thead><tr><th><?php esc_html_e( 'Setting', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What it does', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Default', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td><span class="field"><?php esc_html_e( 'Blocked email domains', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Your own list, on top of the built in list of throwaway email providers. One domain per line.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'empty', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Check the domain can receive mail', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Looks up whether anything is actually listening for email at that domain. A domain that cannot receive mail is not a real customer.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'On', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Address sensitivity', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How willing the made up address check is to call an address nonsense. High catches more and objects to more unusual real addresses.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Medium', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Minimum order amount', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Orders below this are treated as suspicious. Card testers use the cheapest thing in the shop, so set it just under your genuine cheapest item.', 'mighty-shield' ); ?></td><td class="default">1.00</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'High value amount', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Orders at or above this cost a little trust, and a prepaid card used on one is treated as a warning sign after payment.', 'mighty-shield' ); ?></td><td class="default">500.00</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Address velocity', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How many orders to the same delivery address, over how many days, before it looks like a drop address.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '3 orders / 30 days', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Postcode and state check', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Checks that a US postcode belongs to the state given with it.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'On', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Smarty address verification', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Checks the delivery address against a real postal database. Needs a Smarty account and its two credentials. Off unless you have one.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Off', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Hidden trap field', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'An invisible field on the checkout. A person never sees it; a bot fills it in. Almost no false positives.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'On', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Minimum checkout seconds', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'A checkout completed faster than this was almost certainly not typed by a person.', 'mighty-shield' ); ?></td><td class="default">4</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Device check', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Looks at what the browser reports about itself, to spot automated browsers. Off by default because it needs JavaScript and can be noisy.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Off', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Same device order limit', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How many orders one device may place in an hour before it counts against them.', 'mighty-shield' ); ?></td><td class="default">5</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Checkout attempts per hour', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How many checkout attempts one address may make in the window before it is rate limited.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '5 per hour', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Temporary block length', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How long an address stays temporarily blocked after tripping a hard check. It clears itself.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( '24 hours', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Different emails per hour', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How many different email addresses one network may use in an hour. Card testing looks exactly like this.', 'mighty-shield' ); ?></td><td class="default">3</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Orders per 15 minutes', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How many orders one network may place in a quarter of an hour.', 'mighty-shield' ); ?></td><td class="default">5</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Failed payments per hour', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Repeated declines from one address are the clearest sign of card testing there is.', 'mighty-shield' ); ?></td><td class="default">5</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Registrations per hour', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How many accounts one address may create in an hour.', 'mighty-shield' ); ?></td><td class="default">3</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Failed logins per hour', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'How many failed sign ins one address may make before it counts against an order from them.', 'mighty-shield' ); ?></td><td class="default">10</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Failed coupons per hour', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Guessing at discount codes in bulk is its own kind of attack.', 'mighty-shield' ); ?></td><td class="default">5</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'New account minutes', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'An account younger than this when it orders is treated as brand new.', 'mighty-shield' ); ?></td><td class="default">10</td></tr>
            </tbody>
        </table>
        <div class="callout">
            <span class="callout-label"><?php esc_html_e( 'Before you have any orders', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'Until orders have been through the checkout there is nothing to measure, so the How often it fires column shows a dash. It fills in on its own. You do not need to touch any of this; the defaults are sensible for a normal store.', 'mighty-shield' ); ?></p>
        </div>

        <h2 id="ai"><?php esc_html_e( 'AI Review', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'An optional second opinion. After the checks have scored an order, a language model is shown everything MightyShield already knows about it and asked for its own rating out of 100.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'It is off until you add an API key, and it is only asked about the risk levels you choose, so it never costs you anything on ordinary orders. If the provider is unreachable or you have hit your daily cap, the order simply proceeds on its checks alone.', 'mighty-shield' ); ?></p>
        <table>
            <thead><tr><th><?php esc_html_e( 'Setting', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'What it does', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Default', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td><span class="field"><?php esc_html_e( 'Enable AI review', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Nothing is sent anywhere until this is on and a key is saved.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Off', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Provider and model', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Anthropic, OpenAI or Google. Each has its own key field and its own model name, which you can change if you want a cheaper or a stronger one.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Anthropic', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Rating effect', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Lower only means the model can take trust away but never give it back, so it can never talk a bad order into looking fine. Lower or raise lets it rescue an order the checks were too harsh on.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Lower only', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Daily limit', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'A hard ceiling on how many orders can be sent for review in a day, so a flood of traffic cannot run up a bill. 0 means no limit.', 'mighty-shield' ); ?></td><td class="default">0</td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Hide customer details', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Sends the shape of the customer\'s details rather than the details themselves, so the name, address and email never leave your site. It costs some accuracy, which is why the choice is yours.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'Off', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Email me about reviews', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Sends a message when the model rates an order badly. Leave the address list empty to use the site administrator.', 'mighty-shield' ); ?></td><td class="default"><?php esc_html_e( 'On', 'mighty-shield' ); ?></td></tr>
            </tbody>
        </table>
        <div class="callout important">
            <span class="callout-label"><?php esc_html_e( 'What is sent, and to whom', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'Your API key is stored in your database and is only ever sent to the provider you chose. The order details go to that provider and nowhere else. If that matters to you, turn Hide customer details on: the model then sees that an address exists and how it compares to others, but not what it says.', 'mighty-shield' ); ?></p>
        </div>
        <p><?php printf( wp_kses_post( __( 'Which risk levels get a review is set on <a href="%s">Blocking</a>, one switch per level. Elevated and High are on by default; Trusted and Low are not, because that is most of your orders and reviewing them multiplies the cost for very little.', 'mighty-shield' ) ), esc_url( $blocking_url ) ); ?></p>

        <h2 id="blocking"><?php esc_html_e( 'Blocking', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'Where the trust rating turns into something happening. This is the tab that decides what your customers actually experience.', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'Risk levels.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'For each level: the rating at or below which it applies, whether it gets an AI review, what it does, and whether the order still reaches your processor. The last column shows how orders at that level actually turned out, which is what tells you whether a threshold is right.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Failed card checks.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Holds an order before it ships when the payment went through but both the billing address and the security code failed to match the card. The money has been taken at that point, but the goods have not gone out.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Bot challenge.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Cloudflare Turnstile or Google reCAPTCHA v3, and which pages it guards.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Slow down refusals.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Automated card testing relies on a quick, consistent answer. Refusing slowly, with a message that varies and reads like an ordinary bank decline, means an attacker cannot work out what tripped or time their way around it. Genuine customers are never refused, so it does not affect them. It does hold a server process for the length of the delay, which is the only reason to turn it off. The delay is random between a minimum and a maximum you set, 3 and 8 seconds by default, and the randomness is the point: a fixed delay is itself a signal.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Add your own line to the end of every refusal.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'The three refusal messages are shown above the box so you can see what a refused customer reads. They are deliberately vague, and that vagueness is what stops an attacker learning anything from them. The cost is paid by the occasional real customer who gets caught by mistake and has no idea who to talk to. Put your phone number or your support address here and it is added to the end of every refusal, whatever caused it. Links work, so the number can be tapped on a phone. Leave it empty and nothing changes.', 'mighty-shield' ); ?></li>
        </ul>

        <h3><?php esc_html_e( 'Store API Firewall', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'This controls access to the WooCommerce cart and checkout endpoints, and it is the one setting here that can close your shop if it is set wrongly.', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'Allowlist mode.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Refuses those endpoints to everyone who is not on your allowlist. Right for a store using the classic checkout, where customers never touch them.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Blocklist mode.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Refuses only addresses on your blocklist. Required if your checkout page uses the Checkout block, because that checkout is built on those endpoints.', 'mighty-shield' ); ?></li>
        </ul>
        <div class="callout important">
            <span class="callout-label"><?php esc_html_e( 'If your checkout stops working', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'The block based checkout in Allowlist mode means no customer can reach the cart or the checkout at all. MightyShield now detects that combination and says so at the top of this tab and on your WordPress dashboard, but if you ever see an empty cart or a checkout that will not load, this is the first setting to check.', 'mighty-shield' ); ?></p>
        </div>
        <p><strong><?php esc_html_e( 'Block checkout protection', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'runs the checks on the block based checkout as well as the classic one. Leave it on. Every check now works the same on both, including the ones that need something from the browser, such as the checkout timer, the device check, the hidden decoy field and the bot challenge, so the same order is judged the same way whichever checkout your store uses.', 'mighty-shield' ); ?></p>

        <h2 id="payment"><?php esc_html_e( 'Payment', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'What your payment processors can and cannot do, and therefore what MightyShield can ask of them. This tab has no settings. It is a report.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'Three of the actions need cooperation from the processor: asking for 3-D Secure, reserving money without taking it, and reading back the card checks after payment. Processors differ, so the same risk level can behave differently on two orders paid different ways.', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'Supported processors.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'The ones MightyShield was built for specifically, with what each can do and whether you have it active. Every other processor still gets the full scoring pipeline and the full response ladder.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Your payment methods.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Every method currently available at your checkout, with a straight yes or no on each of the three capabilities.', 'mighty-shield' ); ?></li>
        </ul>
        <div class="callout">
            <span class="callout-label"><?php esc_html_e( 'Why an action can change per order', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'If a level is set to ask for 3-D Secure and the customer pays with a method that cannot, that order is flagged instead. If a level is set to authorize and hold and the method cannot reserve money, the order is held before payment instead. Nothing is skipped; something less is done, and the order note says which.', 'mighty-shield' ); ?></p>
        </div>

        <h2 id="access"><?php esc_html_e( 'Access', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'Who skips every check, and who is refused outright.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Allowlist', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Anything here bypasses MightyShield entirely. Four kinds of entry:', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'IP address or range.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'A single address, or a range in CIDR form. Your own office is the usual case.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'WordPress user.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Follows the person rather than where they are, so it survives a changing home address.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Email address.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Only counts when the customer is signed in to an account carrying that address. Typing it at the checkout proves nothing, so it grants nothing.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Role.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Everyone with that role. Be careful with broad roles: allowlisting Customer exempts every registered shopper on your site.', 'mighty-shield' ); ?></li>
        </ul>
        <p><?php esc_html_e( 'Your server\'s own address is added automatically when the plugin is activated, so that scheduled tasks and admin work are never blocked.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'Blocklist', 'mighty-shield' ); ?></h3>
        <p><?php esc_html_e( 'Addresses refused outright, before any check runs. Entries stay until you remove them. MightyShield adds one itself in two cases: when you block an order in review, and when an order is rated Banned.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'Temporary blocks are separate and do not appear here. They are applied automatically for 24 hours when something trips a hard check, and they clear themselves.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'The allowlist always wins. An address on both lists is allowed.', 'mighty-shield' ); ?></p>

        <h2 id="logs"><?php esc_html_e( 'Logs', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'Every event MightyShield recorded, newest first. Click a row for the full detail, including where the address is and what the request looked like.', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'Filters.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'By time, by what happened, or by searching for an address, an email or a reason.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Row actions.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'From the detail panel you can allowlist an address or block it permanently.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Retention.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'How many days of log entries to keep. Older entries are removed automatically once a day.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Export.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Downloads the current filtered view as a spreadsheet file.', 'mighty-shield' ); ?></li>
        </ul>

        <h2 id="order-panel"><?php esc_html_e( 'On an order', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'Open any order and MightyShield is in the right hand column, above the fold. Everything it knows about that order is there, and everything you can do about it.', 'mighty-shield' ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'The rating.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'The dial at the top is the same 1 to 100 scale as the Scoring tab, coloured to match. Underneath are the checks that actually tripped, worst first, with what each one cost.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Unrated orders.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'An order placed before MightyShield was installed, or while it was switched off, has no rating. Rate Order works one out from what the order still contains. It changes nothing about the order and will not hold or cancel anything, however badly it scores.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Clean or Fraud.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Your verdict, and the single most valuable thing on this panel. Change it whenever you like: if a chargeback arrives six months later, mark it Fraud then, and if one turns out to be a family member using the card, mark it Clean and the penalty is taken back off.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Approve and Block.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Shown on orders MightyShield is holding. What they do depends on what happened to the money, which the panel states before the buttons.', 'mighty-shield' ); ?></li>
        </ul>
        <div class="callout important">
            <span class="callout-label"><?php esc_html_e( 'A rating worked out afterwards is a partial one', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'About half the checks look at the visit rather than the order: whether a hidden trap field was filled in, how fast the form was completed, what the browser reported, how many orders that address placed in the previous quarter hour. None of that is kept, and re running it now would measure your own browser sitting in the admin.', 'mighty-shield' ); ?></p>
            <p><?php esc_html_e( 'So Rate Order works from what is left: the address, the email, the location, the totals, and the customer\'s own history with you. That is genuinely useful, but a 90 from it is not the same statement as a 90 earned at checkout, and the panel says so wherever it shows one.', 'mighty-shield' ); ?></p>
        </div>
        <div class="callout">
            <p><strong><?php esc_html_e( 'Held with the payment taken.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Approve moves the order to Processing. Block cancels it and blocks the address, then tells you to refund from the order items panel. It will not refund automatically, because that is real money moving and it should be a decision you make with the amount in front of you.', 'mighty-shield' ); ?></p>
            <p><strong><?php esc_html_e( 'Held with the payment only authorized.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'The funds are reserved on the card but not taken. Approve and Capture takes them and moves the order to Processing. Block releases the reservation, cancels the order and blocks the address, with nothing left to refund.', 'mighty-shield' ); ?></p>
            <p><strong><?php esc_html_e( 'Held before payment.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'The processor was never contacted. Approve sends the order back to Pending and gives you a link to pass to the customer so they can pay. Block cancels it. Either way nothing was charged.', 'mighty-shield' ); ?></p>
            <p><?php esc_html_e( 'Which of the three you see is read from your payment processor, not from what MightyShield asked it to do. The two can differ, and being told your money is merely reserved when it has actually been taken is the worst mistake this screen could make.', 'mighty-shield' ); ?></p>
        </div>

        <h2 id="review-queue"><?php esc_html_e( 'Fraud Review', 'mighty-shield' ); ?></h2>
        <p><?php printf( wp_kses_post( __( 'Under WooCommerce, next to Orders, with a count beside it when something is waiting. <a href="%s">The queue</a> is every order MightyShield stopped or flagged that nobody has ruled on yet, gathered in one place so you can work through them instead of hunting for them.', 'mighty-shield' ) ), esc_url( $queue_url ) ); ?></p>
        <ul>
            <li><strong><?php esc_html_e( 'Why it is held.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Stopped before payment, held after it, held on an authorization, failed card checks, or the name of whichever check flagged it.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'The money.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'Taken in full, reserved but not taken, or never charged. Read from your payment processor rather than from what MightyShield asked it to do.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Waiting.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'How long the order has been sitting there. A held order nobody has looked at for three days is the thing this screen exists to put in front of you.', 'mighty-shield' ); ?></li>
            <li><strong><?php esc_html_e( 'Approve and Block.', 'mighty-shield' ); ?></strong> <?php esc_html_e( 'The same two actions as the panel on the order itself, doing exactly the same things. Clearing ten held orders does not mean opening ten orders.', 'mighty-shield' ); ?></li>
        </ul>
        <p><?php esc_html_e( 'An order leaves the queue the moment you rule on it, whether you do that here or on the order itself. Orders that failed the card checks after paying appear as a warning rather than something to approve or block: the money is already taken and the order is on its way, so the decision is whether to refund and cancel it yourself.', 'mighty-shield' ); ?></p>

        <h2 id="memory"><?php esc_html_e( 'How it learns', 'mighty-shield' ); ?></h2>
        <p><?php esc_html_e( 'The email address, phone number, delivery address, device, network and card behind every order are remembered and linked together. None of it is stored in readable form: it is all scrambled with a key unique to your site, so the records hold no personal detail and cannot be matched against another store.', 'mighty-shield' ); ?></p>
        <p><?php esc_html_e( 'When an order turns out well or badly, that verdict is applied to everything connected to it. The next order from any of them starts with that history behind it. This is what catches someone who changes their email and tries again, because they rarely change everything at once.', 'mighty-shield' ); ?></p>
        <table>
            <thead><tr><th><?php esc_html_e( 'What happened', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Where it comes from', 'mighty-shield' ); ?></th><th><?php esc_html_e( 'Effect on the next order', 'mighty-shield' ); ?></th></tr></thead>
            <tbody>
                <tr><td><span class="field"><?php esc_html_e( 'Completed', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'The order reached Completed', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'A small credit. Three of these with nothing bad is what earns Trusted.', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Refunded', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'The order was refunded', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'A very small mark against. Most refunds are ordinary returns and only matter in volume.', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Fraud', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'You marked it, or blocked it in review', 'mighty-shield' ); ?></td><td><?php esc_html_e( 'A heavy mark against. Enough on its own to push the next order to a level you will see.', 'mighty-shield' ); ?></td></tr>
                <tr><td><span class="field"><?php esc_html_e( 'Chargeback', 'mighty-shield' ); ?></span></td><td><?php esc_html_e( 'Your processor reported a dispute', 'mighty-shield' ); ?></td><td><strong><?php esc_html_e( 'Bans the next order outright, whatever it scores.', 'mighty-shield' ); ?></strong></td></tr>
            </tbody>
        </table>
        <div class="callout">
            <span class="callout-label"><?php esc_html_e( 'Your verdict outranks everything', 'mighty-shield' ); ?></span>
            <p><?php esc_html_e( 'Automatic outcomes only ever get worse: an order recorded as a chargeback will not quietly go back to being fine. Your own Clean or Fraud verdict is the exception. It can be changed as often as you like, in either direction, and changing it takes back whatever the previous verdict did. Once you have ruled on an order, nothing automatic overrides you.', 'mighty-shield' ); ?></p>
        </div>

        <h2 id="situations"><?php esc_html_e( 'Common situations', 'mighty-shield' ); ?></h2>

        <h3><?php esc_html_e( 'A real customer was blocked', 'mighty-shield' ); ?></h3>
        <p><?php printf( wp_kses_post( __( 'Find them in the <a href="%1$s">Logs</a> and read the reason. Allowlist their address from the detail panel if it was a one off. If the same check is catching several real customers, open <a href="%2$s">Scoring</a>, find that check, and either lower its cost or switch it off. If a threshold is the problem, raise it on <a href="%3$s">Blocking</a>.', 'mighty-shield' ) ), esc_url( $logs_url ), esc_url( $scoring_url ), esc_url( $blocking_url ) ); ?></p>

        <h3><?php esc_html_e( 'My checkout stopped working', 'mighty-shield' ); ?></h3>
        <p><?php printf( wp_kses_post( __( 'If your checkout page uses the Checkout block, set the Store API Firewall on <a href="%s">Blocking</a> to Blocklist mode. In Allowlist mode that firewall refuses the cart and checkout to every customer, which looks exactly like a broken shop. MightyShield warns you about this combination, but it is worth checking first whenever the checkout misbehaves.', 'mighty-shield' ) ), esc_url( $blocking_url ) ); ?></p>

        <h3><?php esc_html_e( 'We are under active attack', 'mighty-shield' ); ?></h3>
        <ol>
            <li><?php printf( wp_kses_post( __( 'Set the switch on the <a href="%s">Dashboard</a> to Active, if it is not already. That is what makes the ratings do anything.', 'mighty-shield' ) ), esc_url( $dashboard_url ) ); ?></li>
            <li><?php printf( wp_kses_post( __( 'On <a href="%s">Blocking</a>, raise the Rejected threshold so more orders are refused outright, and set Elevated to something firmer than 3-D Secure if your processor cannot do it.', 'mighty-shield' ) ), esc_url( $blocking_url ) ); ?></li>
            <li><?php printf( wp_kses_post( __( 'On <a href="%s">Scoring</a>, lower the checkout attempts per hour and the different emails per hour, and raise the cost of the checks that are firing on the attack.', 'mighty-shield' ) ), esc_url( $scoring_url ) ); ?></li>
            <li><?php printf( wp_kses_post( __( 'Turn on the bot challenge on <a href="%s">Blocking</a> if you have not. It is the single most effective thing against automated checkout traffic.', 'mighty-shield' ) ), esc_url( $blocking_url ) ); ?></li>
            <li><?php printf( wp_kses_post( __( 'Watch the <a href="%1$s">Logs</a> and block the worst addresses permanently from <a href="%2$s">Access</a>.', 'mighty-shield' ) ), esc_url( $logs_url ), esc_url( $access_url ) ); ?></li>
        </ol>
        <p><?php esc_html_e( 'Put the thresholds back when it is over. Settings tightened during an attack will refuse real customers on ordinary traffic.', 'mighty-shield' ); ?></p>

        <h3><?php esc_html_e( 'I want to turn everything off', 'mighty-shield' ); ?></h3>
        <p><?php printf( wp_kses_post( __( 'On the <a href="%s">Dashboard</a>, set the protection switch to Disabled. Nothing is checked and nothing is recorded until you switch it back. Deactivating the plugin does the same and keeps all your settings and history.', 'mighty-shield' ) ), esc_url( $dashboard_url ) ); ?></p>

    </main>

</div>

<script>
( function() {
    // Highlight the sidebar link for the section currently in view.
    var nav = document.querySelector( '.mshield-docs-nav' );
    if ( ! nav ) return;
    var links    = Array.prototype.slice.call( nav.querySelectorAll( 'a' ) );
    // Sorted by position, not by nav order. The two used to be assumed equal,
    // and when they drifted the highlight stuck on whichever link happened to
    // come last in the sidebar rather than the section you were reading.
    var sections = links
        .map( function( a ) { return document.getElementById( a.getAttribute( 'href' ).slice( 1 ) ); } )
        .filter( Boolean )
        .sort( function( a, b ) { return a.offsetTop - b.offsetTop; } );

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
