# MightyShield

WooCommerce firewall for protecting against card spammer orders. Blocks Store API abuse, rate limits checkout attempts, and detects fraudulent order patterns.

[![Download ZIP](https://img.shields.io/badge/Download-ZIP-blue?style=for-the-badge)](https://github.com/builtmighty/mighty-shield/releases/latest/download/mighty-shield.zip)

## Install via WP-CLI

```bash
wp plugin install https://github.com/builtmighty/mighty-shield/releases/latest/download/mighty-shield.zip --activate
```

## Features

- **Store API Firewall** — Hard-blocks non-whitelisted IPs from WooCommerce Store API cart and checkout endpoints
- **Universal Whitelist** — Whitelist by IP/CIDR, WordPress user, user role, or email address; whitelisted entities bypass **all** checks (blocks and flags), not just the firewall. Server IP is auto-whitelisted on activation, and any log row can be whitelisted in one click
- **Persistent IP Blocklist** — Permanently bar IPs/CIDR ranges from checkout and the Store API, with one-click blocking from the logs (whitelist always wins)
- **Checkout Rate Limiting** — Configurable per-IP rate limits on checkout attempts (default: 5/hour)
- **Velocity Detection** — Detects rapid-fire order patterns: multiple unique emails or excessive orders from a single IP
- **Failed Payment Tracking** — Temporarily blocks IPs after repeated payment failures
- **Disposable Email Blocking** — Built-in list of 160+ disposable email domains, plus custom blocklist
- **Order Amount Validation** — Flags or blocks suspicious micro-charges commonly used for card testing
- **Address Validation** — Score-based detection of fake/nonsensical billing addresses
- **Smarty Address Verification** — Verifies US billing addresses against USPS data via Smarty API, with automatic ZIP/State fallback
- **ZIP/State Mismatch Detection** — Pure PHP validation that catches US orders where the ZIP code prefix doesn't match the billing state
- **Honeypot Field** — Invisible checkout field that catches bots, with a configurable block / flag / notify action
- **Checkout Timing** — HMAC-signed token detects implausibly fast (automated) submissions; IP- and content-agnostic, so it survives VPN rotation and changing products
- **Device Fingerprinting** — Detects automated browsers and timezone/country mismatches, with a configurable block / flag / notify action
- **Device Velocity** — Rate-limits checkout by device signature independent of IP, catching attackers who rotate IPs via VPN
- **Bot Challenge (CAPTCHA)** — Cloudflare Turnstile or Google reCAPTCHA v3 at checkout, verified server-side
- **Admin Dashboard** — Real-time stats, top blocked IPs, and filterable event logs under WooCommerce menu
- **Built-in Documentation** — A Documentation tab in the admin that explains every setting and walks through setup
- **Modern Admin UI** — Card-based layout with a light/dark theme toggle, a redesigned dashboard (status hero, 7-day trend chart, stat cards), and a powerful Logs screen with search, filters, bulk actions, and an event-detail drawer
- **Auto Cleanup** — Daily cron job purges old logs and expired rate limit data

## Requirements

- WordPress 6.0+
- PHP 8.1+
- WooCommerce 8.0+

## Setup

1. Install and activate the plugin
2. Go to **WooCommerce > MightyShield**
3. The Store API firewall is enabled by default — your server IP is auto-whitelisted on activation
4. Add any additional trusted IPs (CDN, payment gateways) under the **IP Whitelist** tab, and permanently bar known offenders under the **IP Blocklist** tab
5. Review rate limit thresholds under **Rate Limits**
6. Configure email domain blocklist, address validation, Smarty API credentials, and other fraud checks under **Fraud Checks**
7. Monitor blocked requests and flagged orders under **Logs**

## How It Works

MightyShield provides two layers of protection:

**Layer 1 — Store API Firewall:** Intercepts all requests to `/wc/store/v1/cart` and `/wc/store/v1/checkout` endpoints via `rest_pre_dispatch` at priority 1. Only whitelisted IPs pass through. Since classic checkout uses `admin-ajax.php` (not the Store API), real customers are unaffected.

**Layer 2 — Classic Checkout Protections:** Rate limiting, velocity detection, email/address validation, honeypot field, checkout timing, device fingerprinting and velocity, a bot challenge (Turnstile / reCAPTCHA v3), Smarty address verification, ZIP/State validation, and failed payment tracking on the actual checkout flow via WooCommerce hooks. Each detection can be set to block the checkout, flag the order with a note, or flag and email the admin. These protect against fraud on the checkout form itself.

A persistent IP blocklist backs both layers — blocklisted IPs are refused at classic checkout and the Store API, while the whitelist is honored everywhere: a whitelisted IP, WordPress user, or email address bypasses every check in both layers.

## License

GPL-2.0-or-later
