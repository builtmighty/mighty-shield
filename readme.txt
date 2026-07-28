=== MightyShield ===
Contributors: tylerjohnsondesign
Donate link: https://builtmighty.com
Tags: woocommerce, security, firewall, fraud, card-testing
Requires at least: 6.0
Tested up to: 6.7
Stable tag: 1.5.0
Requires PHP: 8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WooCommerce firewall for protecting against card spammer orders. Blocks Store API abuse, rate limits checkout, and detects fraudulent patterns.

== Description ==

MightyShield protects WooCommerce stores from card testing attacks by blocking automated Store API abuse and layering fraud detection on the classic checkout flow.

**Features:**

* Block non-whitelisted IPs from Store API cart and checkout endpoints
* Auto-detect and whitelist server IP on activation
* Whitelist by IP/CIDR, WordPress user, or email address — whitelisted entities bypass ALL checks (blocks and flags), with one-click whitelisting from the logs
* Per-IP checkout rate limiting (configurable, default 5/hour)
* Velocity detection — flags IPs using multiple emails or rapid-fire orders
* Temporary IP blocking after repeated failed payments
* Disposable email domain blocking (160+ built-in domains plus custom list)
* Suspicious order amount detection (flag, block, or notify)
* Score-based fake address detection
* Smarty USPS address verification for US billing addresses with automatic ZIP/State fallback
* ZIP/State mismatch detection — catches US orders where the ZIP prefix doesn't match the state
* Honeypot hidden field — invisible bot trap with configurable block/flag/notify action
* Checkout timing — signed token detects implausibly fast (automated) submissions, unaffected by IP or product changes
* Device fingerprinting — detects automated browsers and timezone/country mismatches with configurable action
* Device velocity limiting — rate-limits by device signature regardless of IP, catching VPN/IP-rotating attackers
* Bot challenge — Cloudflare Turnstile or Google reCAPTCHA v3 at checkout
* Persistent IP blocklist with CIDR support, plus one-click blocking from the logs
* Settings link on the plugins page for quick access
* Admin dashboard with stats, top blocked IPs, and filterable logs
* Daily auto-cleanup of old logs and expired rate limits
* CSV log export

== Frequently Asked Questions ==

= Will this block real customers? =

No. The Store API firewall only blocks direct API access — if your store uses classic (shortcode-based) checkout, real customers go through `admin-ajax.php` and are completely unaffected. The classic checkout protections (rate limiting, email blocking, etc.) use sensible defaults that won't trigger on normal shopping behavior.

= What IPs should I whitelist? =

The server IP is auto-whitelisted on activation. You may also want to whitelist your CDN IPs, payment gateway callback IPs, or office IPs if they access the Store API directly.

= Does this work with block-based checkout? =

The Store API firewall will block block-based checkout since it uses the same endpoints. If you use block-based checkout, disable the Store API firewall and rely on the other protection layers (rate limiting, email blocking, address validation, etc.).

= How do I know it's working? =

Check **WooCommerce > MightyShield > Dashboard** for blocked request counts and top blocked IPs. The **Logs** tab shows every blocked, rate-limited, and flagged event.

= What is Smarty address verification? =

Smarty verifies US billing addresses against USPS data to catch fake, non-existent, and undeliverable addresses. It requires a free API key from smarty.com. If the API is unavailable or out of tokens, MightyShield automatically falls back to ZIP/State mismatch detection.

= What does the honeypot do? =

The honeypot adds an invisible field to the checkout form. Real customers never see or fill it, but automated bots do. When filled, MightyShield takes the action you configure — block the checkout (and temporarily ban the IP), flag the order with a note, or flag and email the admin. Zero false positives.

== Screenshots ==

== Changelog ==

= 1.5.0 =
* Redesigned the admin interface: a modern card-based layout, a plugin header, and a light/dark theme toggle saved per user.
* Rebuilt the Dashboard with a protection-status hero (with a quick on/off toggle), a 7-day events trend chart, refreshed stat cards, and a top-blocked-IPs list.
* Rebuilt the Logs screen with search, date-range and action filters, an event-detail drawer, row selection with bulk actions (block / whitelist / delete), and CSV export.
* Restyled every settings tab to match the new design system.

= 1.4.0 =
* Added a built-in Documentation tab that explains every setting and how to set the plugin up.
* Whitelist now applies to every protection — a whitelisted IP, user, or email bypasses all blocks and flags (previously only the Store API firewall honored the whitelist).
* Whitelist entries can now be an IP/CIDR, a WordPress user, a user role, or an email address. Whitelisting a role exempts every user in it.
* Added one-click "whitelist" links (IP, email, and user) in the event logs.
* Logs now capture the logged-in customer's user ID for after-the-fact whitelisting.
* Whitelisted IPs are never treated as temporarily blocked, even if a temp-block was set earlier.

= 1.3.0 =
* Capture request forensics (user agent, billing email, request URI) in the event log for spam-cluster analysis.
* Stopped auto-whitelisting the DNS-resolved site IP (a CDN/proxy edge IP behind Cloudflare) and added a cleanup migration to remove legacy entries.
* Added one-time upgrade migrations that run when the plugin version changes.

= 1.2.0 =
* Added configurable action (block / flag / flag + notify admin) to the honeypot.
* Added checkout timing detection — an HMAC-signed token flags/blocks implausibly fast (automated) submissions; defaults to Flag for safe rollout.
* Added configurable action (block / flag / flag + notify admin) to device fingerprinting; a missing fingerprint is only ever flagged, never blocked.
* Added device velocity limiting — rate-limits checkout by device signature independent of IP to counter VPN/IP rotation.
* Added a bot challenge (Cloudflare Turnstile or Google reCAPTCHA v3) at checkout with block / flag / notify action.
* Added a persistent IP blocklist with CIDR support and a dedicated admin tab.
* Added a one-click "block" link in the logs to add an IP to the blocklist.

= 1.1.2 =
* Fixed settings on other tabs being cleared when saving a single tab.

= 1.1.1 =
* Fixed admin settings page inaccessible when plugin protections are disabled.

= 1.1.0 =
* Added Smarty USPS address verification for US billing addresses.
* Added ZIP/State mismatch detection as a no-API fallback and standalone validator.
* Added honeypot hidden field for bot detection at checkout.
* Added device fingerprinting to detect automated browsers and timezone/country mismatches.
* Added Settings link on the plugins page.
* Smarty API automatically falls back to ZIP/State check on token exhaustion or API errors.

= 1.0.0 =
* Initial release.
* Store API firewall with IP whitelist and CIDR support.
* Auto server IP detection on activation.
* Checkout rate limiting with configurable thresholds.
* Velocity detection for rapid-fire orders and email rotation.
* Failed payment tracking with temporary IP blocking.
* Disposable email domain blocking (160+ domains).
* Suspicious order amount validation (block/flag/notify modes).
* Score-based address validation with configurable sensitivity.
* Admin dashboard with stats, log viewer, and CSV export.
* Daily cron cleanup of expired data.
