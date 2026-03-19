=== MightyShield ===
Contributors: tylerjohnsondesign
Donate link: https://builtmighty.com
Tags: woocommerce, security, firewall, fraud, card-testing
Requires at least: 6.0
Tested up to: 6.7
Stable tag: 1.0.0
Requires PHP: 8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WooCommerce firewall for protecting against card spammer orders. Blocks Store API abuse, rate limits checkout, and detects fraudulent patterns.

== Description ==

MightyShield protects WooCommerce stores from card testing attacks by blocking automated Store API abuse and layering fraud detection on the classic checkout flow.

**Features:**

* Block non-whitelisted IPs from Store API cart and checkout endpoints
* Auto-detect and whitelist server IP on activation
* IP whitelist with CIDR range support
* Per-IP checkout rate limiting (configurable, default 5/hour)
* Velocity detection — flags IPs using multiple emails or rapid-fire orders
* Temporary IP blocking after repeated failed payments
* Disposable email domain blocking (160+ built-in domains plus custom list)
* Suspicious order amount detection (flag, block, or notify)
* Score-based fake address detection
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

== Screenshots ==

== Changelog ==

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
