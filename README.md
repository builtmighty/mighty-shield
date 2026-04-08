# MightyShield

WooCommerce firewall for protecting against card spammer orders. Blocks Store API abuse, rate limits checkout attempts, and detects fraudulent order patterns.

[![Download ZIP](https://img.shields.io/badge/Download-ZIP-blue?style=for-the-badge)](https://github.com/builtmighty/mighty-shield/releases/latest/download/mighty-shield.zip)

## Install via WP-CLI

```bash
wp plugin install https://github.com/builtmighty/mighty-shield/releases/latest/download/mighty-shield.zip --activate
```

## Features

- **Store API Firewall** — Hard-blocks non-whitelisted IPs from WooCommerce Store API cart and checkout endpoints
- **Auto IP Whitelisting** — Automatically detects and whitelists the server IP on activation, with CIDR range support
- **Checkout Rate Limiting** — Configurable per-IP rate limits on checkout attempts (default: 5/hour)
- **Velocity Detection** — Detects rapid-fire order patterns: multiple unique emails or excessive orders from a single IP
- **Failed Payment Tracking** — Temporarily blocks IPs after repeated payment failures
- **Disposable Email Blocking** — Built-in list of 160+ disposable email domains, plus custom blocklist
- **Order Amount Validation** — Flags or blocks suspicious micro-charges commonly used for card testing
- **Address Validation** — Score-based detection of fake/nonsensical billing addresses
- **Smarty Address Verification** — Verifies US billing addresses against USPS data via Smarty API, with automatic ZIP/State fallback
- **ZIP/State Mismatch Detection** — Pure PHP validation that catches US orders where the ZIP code prefix doesn't match the billing state
- **Honeypot Field** — Invisible checkout field that catches bots with zero false positives
- **Device Fingerprinting** — Detects automated browsers and timezone/country mismatches at checkout
- **Admin Dashboard** — Real-time stats, top blocked IPs, and filterable event logs under WooCommerce menu
- **Auto Cleanup** — Daily cron job purges old logs and expired rate limit data

## Requirements

- WordPress 6.0+
- PHP 8.1+
- WooCommerce 8.0+

## Setup

1. Install and activate the plugin
2. Go to **WooCommerce > MightyShield**
3. The Store API firewall is enabled by default — your server IP is auto-whitelisted on activation
4. Add any additional trusted IPs (CDN, payment gateways) under the **IP Whitelist** tab
5. Review rate limit thresholds under **Rate Limits**
6. Configure email domain blocklist, address validation, Smarty API credentials, and other fraud checks under **Fraud Checks**
7. Monitor blocked requests and flagged orders under **Logs**

## How It Works

MightyShield provides two layers of protection:

**Layer 1 — Store API Firewall:** Intercepts all requests to `/wc/store/v1/cart` and `/wc/store/v1/checkout` endpoints via `rest_pre_dispatch` at priority 1. Only whitelisted IPs pass through. Since classic checkout uses `admin-ajax.php` (not the Store API), real customers are unaffected.

**Layer 2 — Classic Checkout Protections:** Rate limiting, velocity detection, email/address validation, honeypot field, device fingerprinting, Smarty address verification, ZIP/State validation, and failed payment tracking on the actual checkout flow via WooCommerce hooks. These protect against fraud on the checkout form itself.

## License

GPL-2.0-or-later
