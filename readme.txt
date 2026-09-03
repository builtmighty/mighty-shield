=== MightyShield ===
Contributors: tylerjohnsondesign
Donate link: https://builtmighty.com
Tags: woocommerce, security, firewall, fraud, card-testing
Requires at least: 6.0
Tested up to: 6.7
Stable tag: 2.0.0
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

Yes. Set **Firewall Mode** to "Block/One-page checkout" so real shoppers aren't blocked at the Store API, then enable **Block Checkout Protection**. The server-side fraud checks (disposable email, order amount, address validation, ZIP/State, velocity, rate limiting) run on the block Checkout, along with checkout timing, device fingerprinting, and reCAPTCHA v3 as front-end checks. The honeypot and Cloudflare Turnstile are the only layers that still require classic/one-page checkout.

= How do I know it's working? =

Check **WooCommerce > MightyShield > Dashboard** for blocked request counts and top blocked IPs. The **Logs** tab shows every blocked, rate-limited, and flagged event.

= What is Smarty address verification? =

Smarty verifies US billing addresses against USPS data to catch fake, non-existent, and undeliverable addresses. It requires a free API key from smarty.com. If the API is unavailable or out of tokens, MightyShield automatically falls back to ZIP/State mismatch detection.

= What does the honeypot do? =

The honeypot adds an invisible field to the checkout form. Real customers never see or fill it, but automated bots do. When filled, MightyShield takes the action you configure — block the checkout (and temporarily ban the IP), flag the order with a note, or flag and email the admin. Zero false positives.

== Screenshots ==

== Changelog ==

= 2.0.0 =
* MightyShield now appears on the order itself. Open any order and the right-hand column shows its trust rating, the checks that tripped and what each one cost, and whatever action that order needs. Orders placed before MightyShield was installed can be rated from the same panel.
* Tell MightyShield how an order turned out with a Clean or Fraud verdict, and it weighs your answer against future orders from the same customer, device, address or network. Change your mind at any time: switching the verdict takes back whatever the previous one did to that customer's standing.
* Approve and Block now do the right thing for what actually happened to the money, read from your payment processor rather than from what MightyShield asked it to do. An order held on an authorization captures or voids; one held after payment moves to Processing or is cancelled with refund instructions; one held before payment sends the customer back to pay.
* A new Rating column on the orders list, so you can see at a glance which of a hundred orders is worth opening.
* The Fraud Review queue is rebuilt. It now says why each order is held and what happened to its money, and Approve and Block work directly from the list, so clearing ten held orders no longer means opening ten orders.
* A MightyShield widget on the WordPress dashboard: whether protection is on, the last 30 days of activity, and how many orders are waiting for you.
* Fixed: the Fraud Review queue could time out and fail to load on stores with only a few dozen orders.
* Fixed: AI review was rejected by the provider on every request and silently stopped reviewing orders. Failed reviews now report what the provider actually objected to instead of only a status code.
* Fixed: reCAPTCHA v3 could never succeed on the block-based checkout, which would have refused every order the moment it was switched on.
* New: MightyShield now warns you when the Store API Firewall is set in a way that closes a block-based checkout to your customers. That combination previously took a store offline with nothing anywhere to say why.
* Rewrote the built-in documentation against the plugin as it actually is. It now covers every setting, including twelve that were not documented at all, and a Payment section explaining why the same risk level can do different things on different orders.

= 1.9.0 =
* Reorganised the settings screens around how an order is actually judged. Each check's own settings now sit on its row on the Scoring tab, alongside what it costs and how often it fires, so configuring a check and deciding what it is worth are no longer two different pages. Firewall, Allowlist and Blocklist are now one Access tab, and a new Payment tab shows what each of your payment methods can and cannot check. Old bookmarks still work and no settings were changed.
* Cloudflare Turnstile now works on the block-based checkout, not just the classic one. The widget appears just above the Place Order button, and if it cannot load for any reason the order goes through rather than being stopped.
* Card checks now work on Square, Authorize.Net and Braintree as well as Stripe. When a payment succeeds but the billing address or security code did not match the card, the order is flagged for review before it ships — previously only Stripe stores got this, and these gateways only mentioned it in an order note when their own fraud filter had already caught it.
* Payment methods MightyShield does not recognise are handled gracefully rather than ignored: those stores get everything except the card checks and the extra card verification, and nothing breaks.
* Log entries now record which order they belong to, and the trust rating at the time, so you can trace an event back to the order instead of matching on address and timestamp by eye.
* The hidden bot trap now works on the block-based checkout too. It previously only existed on the classic checkout, because there was no server-rendered form to put it in.
* Rewrote the built-in documentation, which still described how the plugin worked two versions ago.
* Security: a whitelisted email address no longer exempts anyone who simply types it at checkout. Previously, anyone who learned or guessed an allowlisted address could enter it and bypass every check in the plugin. An email now only grants an exemption to someone signed in to the account that owns it; whitelist the IP, user or role instead for anyone else. Attempts to use an allowlisted address without being signed in are recorded in your logs.
* Security: fraud checks now run on the block-based checkout by default. They previously shipped switched off, so stores using WooCommerce's newer checkout had the firewall and none of the fraud checks. Existing stores are switched on during the update and told so once.
* Velocity counters moved out of temporary storage that a caching plugin could clear at any moment, which could silently switch off velocity detection exactly when a burst of orders was filling the cache.
* IP lookups now use an encrypted connection, and API credentials for Smarty and Google Gemini are sent as headers rather than in the address, where they end up in server and proxy logs.
* Added an option to keep customers' personal details out of AI reviews. The review still sees the email domain, whether the address looks plausible, the town and postcode and the network the order came from — but not the street address, mailbox name, phone number or exact IP.
* Added a unified trust rating. Every order is rated from 1 to 100 — 100 totally trustworthy, 1 as bad as it gets — and every protection layer now spends trust instead of deciding block/flag on its own, so several weak signals can combine into a strong verdict rather than producing separate order notes that nobody reads. An unknown customer starts as Monitored, not Trusted: the top of the scale has to be earned with a clean history.
* Added a six-band response ladder — Trusted, Monitored, Challenged, Detained, Rejected, Banned. Detained, Rejected and Banned orders never reach the payment processor, which keeps spam and card-testing orders off your merchant account's decline and fraud ratios.
* Added persistent identity memory. Email (with Gmail aliases collapsed), phone, address, device and IP network are remembered across orders and linked to each other, so a fraudster who changes one detail is still recognised. Values are hashed with a per-site key — no readable customer data is stored.
* Added per-signal tuning: every signal has a weight, and can optionally force a band on its own regardless of the total score.
* Enforcement is off by default. New installs and upgrades run in observation mode, recording what band each order would have landed in so you can tune thresholds against your own traffic before anything is enforced.
* Refusals no longer announce themselves: the message is generic, varies between attempts, and is delayed, so automated card testing can no longer use the response to work out what tripped.
* Added a step-up challenge for borderline orders: where the payment method supports it, additional card verification (3-D Secure) is requested instead of blocking. Genuine cardholders complete their bank's prompt and the sale goes through; someone using a stolen card cannot, and liability for the chargeback moves to the card issuer. Payment methods that cannot do this are unaffected and say so plainly on the order.
* Added outcome learning. Refunds, chargebacks, completed orders and your own "Report as fraud" decisions are now remembered against the customer, device, address and network behind the order, so the next order from any of them is judged with hindsight. Includes a "Report as fraud" bulk action on the Orders screen, which also works on orders placed before this update.
* Added payment-instrument checks for Stripe. When a payment succeeds but the billing address or security code did not match the card, the order is flagged for review before it ships — a common sign of a stolen card. Orders failing both are held automatically. Stripe's own risk rating and prepaid-card use on high-value orders are read too. Requires Stripe webhooks to be configured.
* Orders held or flagged for any of these reasons now appear together in the Fraud Review queue.
* AI review now returns a structured verdict — a 1-100 trust rating, an allow/review/deny call, and written reasons — instead of a bare number scraped out of a sentence. The reasons appear on the order, so you can see why an order was held rather than just that it was.
* AI review is now sent everything MightyShield already worked out: which checks fired, what each cost, what is known about the customer, the device, the address and the network, and how old the account is. Previously it was asked to judge an order with less information than the plugin already had.
* AI review can now run just after checkout instead of during it, so customers never wait on the AI provider and nobody who can place an order can run up your API bill. Recommended, and now the setting to reach for unless you rely on reserving funds without taking them, which has to happen during payment.
* Added a daily limit on AI reviews. Once reached, orders carry on as normal without a review and a note is added to your logs.
* Fixed a crash at checkout whenever the AI provider was unreachable, rate limited, or misconfigured. The failure was supposed to let the order through quietly and instead brought down the checkout — the opposite of what was intended, and it affected 1.8.0 and 1.8.1.
* AI review now runs where it can change the outcome. Known-good customers and already-decided orders are skipped, concentrating spend on the genuinely ambiguous ones. Reviewing every order remains an option.
* Disposable email detection now uses a maintained list refreshed daily, instead of ~49 domains frozen at release. The built-in list stays as a fallback, and a failed or malformed download never replaces a good list.
* Added an email deliverability check: an address at a domain that cannot receive mail at all is flagged. Domains with no MX record but a valid A record are treated as deliverable, because they are — plenty of small legitimate businesses are set up that way.
* Added protection either side of the checkout, which previously had none: coupon-code guessing, repeated failed logins, bursts of new accounts from one address, and orders from accounts created moments earlier. All of it feeds the order's trust rating.
* Added checkout behaviour checks that tell a person from a script: whether form fields were filled without anyone typing, pasting or using autofill, and whether the browser's own description of itself holds together. Tuned to leave real customers alone — mobile taps, password managers, keyboard-only shoppers and low-spec machines all pass untouched.
* Fixed device recognition, which previously identified a rough demographic rather than a device: thousands of ordinary customers shared one signature, so repeat-device limits flagged real shoppers and could be sidestepped by resizing a browser window.
* The classic and block checkouts now share one collector, so a check cannot be avoided by using the other checkout.
* Added datacenter, proxy/VPN and network-operator detection to IP lookups.
* Fixed the IP location signal never firing for first-time visitors, because their address was only ever cached after they had already been blocked.
* Fixed log cleanup silently never running on stores with the Store API firewall switched off, which let the log table grow without limit.

= 1.8.1 =
* Added a Fraud Review screen under WooCommerce → Orders (shown only when AI Detection is enabled) that lists every order the AI flagged and is still waiting on, with a count badge on the menu item — a dedicated queue instead of hunting for held orders one at a time.
* The admin theme now follows your operating system's light/dark setting by default, with a System / Light / Dark toggle so you can override it.
* Documented AI Detection in the built-in Documentation, including where to get an API key for each provider (Anthropic, OpenAI, Google Gemini).

= 1.8.0 =
* Added AI Fraud Detection: optionally send orders to an AI model (Anthropic Claude, OpenAI, or Google Gemini) for a 1–10 fraud rating; low-rated orders are held On hold for review with a per-order Approve/Deny panel, an optional authorize-only hold on supported gateways, and admin email alerts. Off by default.
* Added block-based (Store API) checkout support: the server-side fraud checks — disposable email, order amount, address validation, ZIP/State, velocity, and rate limiting — now run on the block Checkout via the Store API, blocking or flagging per each layer's existing settings.
* Added a Firewall Mode setting: "Classic checkout" (block all non-whitelisted IPs from the Store API, as before) or "Block/One-page checkout" (allow real shoppers, block only blocklisted IPs) so block-checkout stores are not locked out.
* Added front-end checks to the block Checkout: checkout timing, device fingerprinting, and Google reCAPTCHA v3 now ride along with the Store API request and are verified server-side, honoring each layer's block / flag / notify action.
* Removed Test Mode (added in 1.7.0): the admin-bar force-trip toggle has been retired. Its per-user settings and log entries are cleaned up automatically on upgrade.
* Note: on block checkout the honeypot and Cloudflare Turnstile are not evaluated — both require a rendered field/widget that the React Checkout block does not provide. Use reCAPTCHA v3 for a bot challenge on block checkout, or classic/one-page checkout for the full set.

= 1.7.0 =
* Added Test Mode: a toolbar (admin bar) toggle that lets shop managers exercise the protection layers against their own checkout, with per-layer "force trip" controls and a Simulate (log-only) vs Enforce switch. State is per-user and never affects real customers.
* Fixed One Page Checkout: Device Fingerprinting no longer interferes with the AJAX order review — the collector now loads wherever the checkout form renders (not only on standard checkout pages), renders a single field, refreshes after order-review updates, and never runs during the review refresh.
* Hardened the bot challenge: reCAPTCHA v3 tokens are kept fresh and re-issued after checkout errors; Cloudflare Turnstile resets its single-use token on a failed attempt so retries work; the challenge now loads on shortcode/one-page checkouts; and a misconfigured secret key now fails open with an admin notice instead of silently blocking every checkout.

= 1.6.0 =
* Added IP location intelligence (city, region, country, organization) via ip-api.com, cached in a new table so each IP is only ever fetched once.
* Dashboard automatically enriches the top blocked IPs on load (missing IPs only, in a single batched request) and shows their location and network.
* Added a "Get IP" button in the Logs event drawer that fetches and stores IP data on demand without a page reload; cached data loads automatically on future views.
* Log cleanup now also drops cached IP data for IPs no longer present in the log.
* Made the events trend chart interactive: hover tooltips, and switchable 24-hour / 7-day / 30-day ranges (defaults to 30 days).
* Fixed IPv6 display: no longer overlaps the bar in Top Blocked IPs or the Endpoint column in the logs; capitalized the "Top Blocked IPs" heading.

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
