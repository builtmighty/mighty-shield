# MightyShield

Fraud prevention for WooCommerce. Scores every order out of 100, optionally asks an AI model for a second opinion, then acts once — hold, challenge, refuse, or let through — according to rules you set.

[![Download ZIP](https://img.shields.io/badge/Download-ZIP-blue?style=for-the-badge)](https://github.com/builtmighty/mighty-shield/releases/latest/download/mighty-shield.zip)

## Install via WP-CLI

```bash
wp plugin install https://github.com/builtmighty/mighty-shield/releases/latest/download/mighty-shield.zip --activate
```

## How it works

Five steps, in this order, on both the classic and the block checkout:

1. **Scored.** Forty-five checks run. Each one that notices something costs the order trust on a 1–100 rating, weighted by how sure it is. Nothing decides anything yet.
2. **Reviewed.** If AI review is on and the rating landed on a level you selected, a model is shown everything MightyShield already knows and returns its own rating.
3. **Decided.** The final rating picks a risk level; that level's action is carried out. A refusal happens here — before an order exists and before your payment processor is contacted, which is the whole point.
4. **Created.** The order is placed.
5. **Remembered.** How it turned out is recorded against the customer, address, network and card, and counts towards their next order. Refused checkouts are recorded too.

Checks compound rather than firing independently: three small concerns add up to a rating that means something, where none of them would on its own. Only things a real customer essentially cannot do — a filled hidden trap field, a browser announcing it is automated, a card with a chargeback against it — decide an order alone.

**Card checks are the one exception**, and only because they have to be. Your processor does not report whether the billing address and security code matched until after the payment. Those answers are scored the same way and added to what the checkout found, but by then the only thing left to do is hold the order before it ships.

## Where settings live

Three screens, and only three, decide how an order is treated:

| Screen | What it sets |
|---|---|
| **Scoring** | Every check: on or off, what it costs, whether it can force a level on its own, and its own configuration. Grouped into Identity, Network, Behavior, Order, Payment and History. |
| **AI Review** | Provider, keys, spend cap, redaction — and **Send to Review**, which picks the risk levels worth a second opinion. |
| **Shielding** | What a score means. Six risk levels, each with a threshold and an action. Plus the Store API firewall, the bot challenge and refusal behaviour. |

Dashboard, Payment, Access and Logs report or list; they do not tune scoring or blocking.

## Features

**Scoring**
- Trust rating from 1–100 across 45 checks, each with a cost you control and a "how often it fired on your traffic" column to tune against
- Scoring profiles (Balanced / Cautious / Strict) that set every cost at once, with Custom appearing on its own the moment you change a row
- Identity — disposable and role email addresses, domains that cannot receive mail, fake-looking addresses, ZIP/state mismatches, USPS verification via Smarty, drop-address velocity
- Network — IP blocklist, temporary blocks, datacenter and VPN detection, geolocation mismatch
- Behavior — invisible honeypot, HMAC-signed checkout timer, device fingerprinting, automated-browser detection, Cloudflare Turnstile or Google reCAPTCHA v3
- Order — micro-charge and high-value thresholds
- Payment — billing address match, security code match, prepaid card, your processor's own fraud rating, issuing country
- History — chargebacks, denials, refusals and earned trust across every identity on the order

**Deciding**
- Six risk levels with thresholds you set, and seven actions: reject, no action, flag, 3-D Secure, take payment then hold, authorize then hold, hold before payment
- Every action either runs or degrades to a named fallback — nothing silently does nothing. 3-D Secure falls back to flagging where the gateway cannot do it; authorize-and-hold falls back to holding before payment
- Refusals are slow and deliberately vague, with a randomized delay and a rotating message that reads like an ordinary bank decline, so an attacker cannot time or read their way around them. Add your own contact line to every refusal
- Observe mode: rate and record everything, enforce nothing, until you say so

**Learning**
- Email, phone, delivery address, network and card remembered across orders as per-site salted hashes — no readable personal detail, and nothing that can be matched against another store
- Completions, refunds, chargebacks, your own fraud verdicts and refused checkouts all feed the next order's rating
- Your Clean/Fraud verdict is changeable in both directions and takes back whatever the previous one did; a later chargeback still updates the record
- Daily cleanup of logs, rate limits, IP cache and stale customer history

**AI review (optional)**
- Anthropic, OpenAI or Google, with per-provider model names, a hard daily spend cap and a Test Connection that makes one real request
- Runs before the order is created, so its verdict can still prevent a sale
- Send only the levels you choose; optionally redact customer details so names and addresses never leave your site

**Firewall and access**
- Store API firewall with allowlist and blocklist modes, auto-detected against which checkout your store actually uses
- Allowlist by IP/CIDR, WordPress user, role or email — allowlisted entities bypass every check
- Persistent IP blocklist with CIDR support and one-click blocking from the logs

**Admin**
- Guided setup walkthrough on first activation, re-runnable at any time
- Dashboard with a status hero, trend chart and stat cards; light/dark theme
- Fraud Review queue with per-order Approve/Block, a rating panel on every order, and a re-rate button
- Logs with search, filters, bulk actions, an event drawer and CSV export
- Built-in manual covering every setting and the decisions behind it

## Requirements

- WordPress 6.0+
- PHP 8.1+
- WooCommerce 8.0+
- HPOS compatible

## Setup

1. Install and activate — the setup walkthrough opens on first load
2. Allowlist your own IP or user account under **Access**, so you cannot lock yourself out while testing
3. Leave it in **Observe** mode. It rates and records; it enforces nothing
4. After a week or two, check **Shielding** for how orders landed at each level and how they turned out, and **Scoring** for how often each check fired
5. Turn down anything firing on ordinary customers, adjust the thresholds, then set the switch on the **Dashboard** to Active

## License

GPL-2.0-or-later
