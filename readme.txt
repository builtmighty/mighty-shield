=== MightyShield ===
Contributors: tylerjohnsondesign
Donate link: https://builtmighty.com
Tags: woocommerce, security, firewall, fraud, card-testing
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 2.2.0
Requires PHP: 8.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WooCommerce firewall for protecting against card spammer orders. Blocks Store API abuse, rate limits checkout, and detects fraudulent patterns.

== Description ==

MightyShield protects WooCommerce stores from card testing attacks and stolen-card orders. Every order is scored out of 100 by 45 checks, optionally reviewed by an AI model, and then acted on once — held, challenged, refused, or let through — according to rules you set.

Nothing is enforced until you say so. MightyShield installs in Observe mode: it rates every order and records what it would have done, so you can tune it against your own traffic before it touches a single sale.

**Features:**

* Block non-whitelisted IPs from Store API cart and checkout endpoints
* Auto-detect and whitelist server IP on activation
* Whitelist by IP/CIDR, WordPress user, or email address — whitelisted entities bypass ALL checks (blocks and flags), with one-click whitelisting from the logs
* Trust rating out of 100 — every check contributes a cost you control, so several small concerns add up instead of one check deciding alone
* Six risk levels, each with a threshold and an action you choose: no action, flag, 3-D Secure, three kinds of hold, or refuse outright
* Per-IP checkout rate limiting (configurable, default 20/hour)
* Velocity detection — flags IPs using multiple emails or rapid-fire orders
* Temporary IP blocking after repeated failed payments
* Disposable email domain blocking (160+ built-in domains plus custom list)
* Suspicious order amount detection
* Score-based fake address detection
* Smarty USPS address verification for US billing addresses with automatic ZIP/State fallback
* ZIP/State mismatch detection — catches US orders where the ZIP prefix doesn't match the state
* Honeypot hidden field — invisible bot trap
* Checkout timing — signed token detects implausibly fast (automated) submissions, unaffected by IP or product changes
* Device fingerprinting — detects automated browsers and timezone/country mismatches
* Card checks — reads back what your processor says about the card (address match, security code, prepaid, its own risk rating) and scores it
* Customer history — email, phone, delivery address, network and card are remembered across orders as salted hashes, so a fraudster who changes one detail is still recognised
* Outcome learning — completions, refunds, chargebacks, your own fraud verdicts and refused checkouts all feed back into the next order's rating
* AI review — send only the risk levels you choose to Anthropic, OpenAI or Google for a second opinion, before the order is decided
* Setup walkthrough — a guided first run covering the decisions that matter
* Device velocity limiting — rate-limits by device signature regardless of IP, catching VPN/IP-rotating attackers
* Bot challenge — Cloudflare Turnstile or Google reCAPTCHA v3 at checkout
* Persistent IP blocklist with CIDR support, plus one-click blocking from the logs
* Settings link on the plugins page for quick access
* Admin dashboard with stats, top blocked IPs, and filterable logs
* Daily auto-cleanup of old logs and expired rate limits
* CSV log export

== Frequently Asked Questions ==

= Will this block real customers? =

It ships in Observe mode, so on day one it blocks nobody at all: it rates orders and records what it would have done, and you turn enforcement on when the ratings look right for your traffic.

Once enforced, no single ordinary check turns anyone away by itself. Checks contribute a cost to a rating out of 100, and the rating picks the level. Only the things a real customer essentially cannot do — filling in a hidden field that is invisible on the page, a browser announcing that software is driving it, a card the bank has already charged back — decide an order on their own.

The Scoring tab shows how often each check fires on your own orders. Anything firing on most of them is describing your customers rather than your fraudsters, and should be turned down.

= What IPs should I whitelist? =

The server IP is auto-whitelisted on activation. You may also want to whitelist your CDN IPs, payment gateway callback IPs, or office IPs if they access the Store API directly.

= Does this work with block-based checkout? =

Yes, and identically. Every check runs on both checkouts, including the ones that need something from the browser — the checkout timer, the device check, the hidden trap field and the bot challenge — so the same order is judged the same way whichever checkout your store uses.

MightyShield detects which checkout you use and sets the Store API Firewall accordingly. The one combination that breaks a shop is the block checkout with the firewall in Allowlist mode, because that checkout is built on the very endpoints Allowlist mode closes. MightyShield warns you at the top of the Shielding tab and on your WordPress dashboard if it ever sees that pairing.

= In what order does everything happen? =

1. The order is scored by every check that applies.
2. If you have AI review on, and the rating landed on a level you selected, a model gives its own rating.
3. The final rating picks a risk level, and that level's action is carried out — which may mean refusing the checkout before any order exists and before your processor is contacted.
4. The order is created.
5. How it turns out is remembered against the customer, address, network and card, and counts towards their next order.

Card checks are the one exception, and only because they have to be: your processor does not report whether the address and security code matched until after the payment. Those answers are scored the same way and added to what the checkout found, but by then the only thing left to do is hold the order before it ships.

= How do I know it's working? =

Check **WooCommerce > MightyShield > Dashboard** for blocked request counts and top blocked IPs. The **Logs** tab shows every blocked, rate-limited, and flagged event.

= What is Smarty address verification? =

Smarty verifies US billing addresses against USPS data to catch fake, non-existent, and undeliverable addresses. It requires a free API key from smarty.com. If the API is unavailable or out of tokens, MightyShield automatically falls back to ZIP/State mismatch detection.

= What does the honeypot do? =

The honeypot adds an invisible field to the checkout form. Real customers never see or fill it, but automated bots do. It is one of very few checks set to decide an order on its own, because a person using your site cannot trip it: the field is off-screen, hidden from screen readers and out of tab order. A filled trap field refuses the checkout and temporarily bars the address.

== Screenshots ==

== Changelog ==

= 2.2.0 =
* Changed: everything now happens in one order, and it is the order you would expect. An order is scored, then reviewed by AI if you use it, then acted on, then created. Before this, half the scoring ran after the order already existed, which is after the last moment anything can be refused — so the decision to turn a checkout away was made on half the evidence, and the other half could only change what happened to an order that had already gone through.
* Changed: every check now only scores. Nine settings used to let an individual check refuse an order on its own, around the risk levels rather than through them, and eight of those settings had no screen you could reach. Scoring is set in two places, Scoring and AI Review; what happens to a score is set in one, Shielding. Nothing else decides anything.
* Changed: the Blocking tab is now called Shielding.
* New: Reject is offered as an action on any risk level, so you can refuse an order outright before it is created rather than holding it afterwards.
* New: what your payment processor says about the card — whether the billing address matched, whether the security code matched, whether it was prepaid, its own fraud rating, and where the card was issued — are five checks on the Scoring tab with costs you control. They used to be a single checkbox that held an order when two of them failed, with no way to see what it weighed or to disagree with part of it. The defaults do exactly what that checkbox did.
* New: Send to Review on the AI Review tab. Pick the risk levels worth a second opinion. Rejected can now be one of them: the review happens before the refusal, so a model can rescue an order the checks were too harsh on. Orders stopped by a single decisive check are never sent, because the model cannot overturn those and the call would be wasted.
* New: a checkout that MightyShield refuses is now remembered. Every record it kept required an order to exist, so it only ever learned from the orders it let through — somebody refused fifty times arrived at the fifty-first looking like a stranger.
* Fixed: an order you released from Fraud Review could never afterwards record a chargeback, a refund, or anything else. That is exactly the population where being wrong matters most — the orders MightyShield flagged and you overruled — and it was also the only population the tuning report exists to measure. Your judgement still stands; a chargeback now updates the record anyway.
* Fixed: a card was recorded but never read. A fraudster reusing a card behind a fresh email and a fresh address scored as a stranger while that card's chargeback sat in the table.
* Fixed: an order that completed and was later charged back was counted as both, so a card that had just cost you a dispute still carried a completed order in its favour.
* Fixed: re-rating an order from the admin counted as another order from that customer, inflating the count that decides whether they are trusted and the one shown to the AI.
* Fixed: a customer's reputation could run away in both directions. Thirteen ordinary retail refunds over several years was enough to mark someone as a known bad customer permanently, with nothing wrong with them.
* Fixed: the customer history tables were the only ones the daily cleanup never touched, so they grew without limit. Old, clean records with nothing linked to them are now cleared out after a year, which you can change or switch off on the Logs tab. Anything carrying a chargeback, a refund, a fraud verdict or a refusal is kept.
* Fixed: on the block checkout, order velocity was never counted at all, so two of the velocity checks could not fire on it.
* Fixed: a mismatched timezone temporarily barred the address it came from. That is a VPN, a traveller or an expat far more often than a bot, and the setting that caused it shipped switched on.
* Fixed: the manual quoted five limits that had been relaxed in 2.1.1 and never updated, so it advertised thresholds five times tighter than the ones actually in use.
* Fixed: the Risk Levels and Scoring tables were sized by their columns rather than by the panel holding them, leaving a gap down the right-hand side.

= 2.1.1 =
* Fixed: choosing "Disabled" for protection broke every WordPress admin page, and the only way back to the setting was the admin page it had just broken. Recovering needed database access.
* Fixed: Observing mode did not observe. A dozen checks refused customers outright whatever the mode was set to, so a store you believed was only watching was still turning people away. Observing now means what it says: orders are rated and recorded and nobody is refused.
* Fixed: one chargeback marked the whole network an order came from, so unrelated shoppers who happened to share an internet provider were refused and permanently blocked. The same breadth also handed out trust: a few cheap orders from one network vouched for everyone on it. Networks and shared addresses now count as history, and no longer decide an order by themselves.
* Fixed: five declined payments from one address blocked that address for a full day and refused every order from it. A shopper working through three cards, or anyone sharing a mobile or office connection, could trigger it. A temporary block now costs an order trust instead of refusing it, and lasts an hour.
* Fixed: the limits on checkout attempts, orders and email addresses per address were far too tight for any connection shared by more than one person. Existing stores are moved to the new values unless you had changed them.
* Fixed: saving the Blocking tab before setting up AI review switched AI review off for every risk level, permanently and silently, so turning it on later reviewed nothing.
* Fixed: customers in the US Virgin Islands, Northern Mariana Islands, Micronesia, the Marshall Islands and Palau were refused at checkout because their postal codes were mapped to the wrong territory.
* Fixed: on a store using the newer block checkout, the Store API firewall could close the cart and the checkout to every customer. It now recognises which checkout your store uses.
* Fixed: the bot challenge's safety valve could be tripped on purpose by anyone, disarming the challenge across the whole site. It now needs failures from several different networks and only affects the form they happened on.
* Fixed: on the block checkout, leaving the bot challenge or device data out of a request cost nothing, while leaving it out of the classic checkout cost trust. The same order is now judged the same way on both.
* Fixed: an allowlist entry for a user role could be added but never removed. It exempts everyone in that role from every check, so undoing it needed database access.
* Fixed: approving or blocking an order from the second page of Fraud Review dropped you on the single order screen and hid the result.
* Fixed: a first-time customer whose order tripped nothing at all was still flagged for review, filling the queue with orders that had nothing wrong with them.
* Fixed: an order from a company VPN was treated as much more suspicious than it deserves, which on its own could hold a legitimate first order.
* Fixed: a single anonymous request could raise a red "your bot challenge is broken" warning and email you about it on a store where nothing was wrong.
* Fixed: eight settings that decide whether a check refuses an order or merely notes it had no screen at all, and three of them were set to refuse. They now sit beside the check they govern on the Scoring tab.
* Fixed: several screens described behaviour the plugin no longer had, including the Blocking tab telling you front-end checks did not work on the block checkout.
* Fixed: typing a currency symbol into an amount, like "$500", stored it as zero. A high-value threshold of zero treats every order as high value, and nothing said so. Amounts and scores now accept what people actually type and are kept inside sensible bounds.
* New: the Bot Challenge panel now tells you what the challenge has been doing, instead of only what it is set to. How many visitors it turned away, how many it could not judge either way, and whether it has stopped refusing anyone on a form because the keys look wrong.
* New: the action for each risk level now says what happens to the customer's money, which is the real difference between the three kinds of hold.
* Fixed: an order held by the block checkout showed a vague reason in Fraud Review where the identical order from the classic checkout showed a clear one.
* Fixed: three of the four ways a shopper gets temporarily blocked left nothing in the Logs, so there was no way to find out why somebody could not check out.
* Fixed: the Logs filter could not select MightyShield's own "needs attention" events, which are the ones worth finding.
* Fixed: exporting the log ignored the filters you had just set and handed back everything.
* Fixed: a message asking you to go and check something in your payment processor was styled as though it were good news.
* Fixed: the Scoring and Blocking tables overflowed their panel on smaller laptop screens.
* Fixed: in some translations the Remove button on the allowlist silently stopped working.
* Fixed: the manual's table of what each rating means printed fixed numbers, so it became wrong the moment you adjusted a threshold. It now reads your actual settings.
* Fixed: the warning before switching scoring profile did not mention that it also switches every check back on, including any you had deliberately turned off.
* Fixed: the Refusals panel said refusals never tell the customer what tripped. That is true of refusals from the rating, and not of an individual check like a mistyped postcode, which says so on purpose.
* Removed 150 lines of duplicated scoring code that nothing called and that had already drifted from the version actually in use.

= 2.1.0 =
* New: a setup walkthrough the first time you activate MightyShield. Five short steps that explain what it does before asking you to decide anything, and leave the store observing rather than enforcing. Existing stores never see it. You can run it again from the documentation page whenever you want.
* Fixed: signing in from the My Account page failed with "we could not verify that you are a person", while the same details worked on the normal WordPress login screen. My Account shows the sign-in and registration forms together, and the two were sharing one setting between them, so the sign-in form's check was being made out to the registration form. Each form now carries its own. This affected every store using the My Account page for sign-in.
* Fixed: changes to MightyShield's front-end scripts were not reaching visitors who had been to the site before, because the files were labelled with the plugin version rather than their own. A fix could be live on the server while browsers kept running the old file. All scripts and stylesheets now label themselves.
* Fixed: when the bot challenge provider rejects something, the log now records the provider's own reason and the domain it believes your store is on, instead of only "not genuine". Those two facts are the difference between a key set up for the wrong domain and a real bot, which otherwise look identical.
* New: if the bot challenge refuses a run of visitors without a single one passing, MightyShield now treats that as its own fault rather than an attack, stops refusing people, and emails you. One success puts it straight back. A misconfigured key should cost you a warning, not every customer.
* Fixed: a brand new install was shown a notice about a default that "changed on upgrade", on a store that had never been upgraded. Fresh installs no longer run any of the old upgrade steps.
* Fixed: activating MightyShield rewrote parts of its own database tables every single time, including five changes the database refused outright and logged as errors. On a store with a long history that was a needless rebuild of large tables on every activation. Activation now leaves the tables alone unless something has genuinely changed.

= 2.0.1 =
* Fixed: on the classic checkout, "authorize and hold" charged the card in full instead of only reserving the funds, while the order note said the card had not been charged. This affected every payment processor. Authorizations are now held as intended, and the order says what actually happened to the money.
* Fixed: a successful capture from the order screen was reported as a failure, leaving the order on hold after the money had already been taken.
* Fixed: an order that was charged and then held could be described as merely authorized, and blocking it issued a silent refund while the screen said nothing had been taken.
* Fixed: releasing an authorization that the processor did not confirm no longer cancels the order. It stays on hold with a note telling you to check the authorization in your processor dashboard, because cancelling an order whose funds may still be reserved helps nobody.
* Fixed: password reset on the My Account page showed no bot challenge but refused every request anyway, locking real customers out of their own accounts. The challenge now renders there, and more importantly, MightyShield will never refuse somebody a challenge they were never shown.
* Fixed: a bot challenge with a site key but no secret key used to fail every single block-checkout order. It now stays out of the way until both keys are in place.
* Fixed: the bot challenge could lose a race with its own provider script on the login, registration and password reset forms, so the box never appeared. It now waits for the provider instead of giving up.
* Fixed: pressing Place order or Log in a second time was treated as a bot. Both Cloudflare and Google accept a challenge token only once, so a shopper retrying after a declined card, or anyone correcting a typo, sent a token that had already been spent and was refused. The browser now fetches a fresh one, and a spent token no longer counts against anybody.
* Fixed: the same applied to anyone who took more than two minutes over a form, because the token had quietly expired.
* Fixed: a shopper whose browser could not load the challenge at all, through an ad blocker, a company network or a provider outage, was refused with no box on screen and nothing to solve. That can no longer refuse anyone.
* Fixed: a low reCAPTCHA score no longer locks anybody out of their own account. reCAPTCHA v3 returns a probability rather than a verdict, and real customers on a VPN, a company network or a new site key score low routinely. It still counts against an order at checkout, where you can review it.
* New: the reCAPTCHA minimum score is now yours to set, on the Scoring tab beside the signal it governs. It was fixed at 0.5.
* New: a separate score for a challenge that could not be confirmed, kept apart from one that was actually failed. Only a real failure can reject an order on its own.
* Fixed: the log recorded every one of these as "Bot challenge failed", so there was no way to tell a card tester from a customer retrying a payment. It now records which of them it was.
* Fixed: signing in from the My Account page failed with "we could not verify that you are a person", while the same details worked on the normal WordPress login screen. My Account shows the sign-in and registration forms together, and the two were sharing one setting between them, so the sign-in form's check was being made out to the registration form. Each form now carries its own. This affected every store using the My Account page, which is most of them.
* Fixed: when the challenge provider rejects something, the log now records the provider's own reason and the domain it thinks your store is on, instead of only "not genuine". Those two facts are the difference between a key registered for the wrong domain and a real bot, which otherwise look identical.
* New: if the challenge refuses a run of visitors without a single one passing, MightyShield now treats that as its own fault rather than an attack, stops refusing people, and emails you. One success puts it straight back to normal. A broken key should cost you a warning, not every customer.
* Fixed: Smarty address verification returned HTTP 401 on every call because credentials were sent in a form Smarty does not accept. Address verification works again.
* Smarty and AI errors now tell you what actually went wrong. Rejected credentials, an exhausted subscription, a rate limit and an outage are four different problems needing four different responses, and they used to arrive as the same bare status code with advice that was wrong for three of them.
* New: a Test Connection button for Smarty and for AI. It makes one real call using your saved credentials and tells you what came back. For Smarty it also works out which way this particular server can send credentials, and keeps it.
* New: Smarty and AI warnings can be dismissed once you have dealt with them. If the problem is still there, the next failed call brings the warning straight back.
* Fixed: a warning about rejected credentials disappeared the moment you cleared the credentials it was warning about, which read as though the problem had been fixed.
* Fixed: a Smarty or AI warning could stay on screen for several minutes after the service had recovered.
* The protection status bar now appears on every MightyShield page rather than only the Dashboard, so it is always clear whether ratings are being enforced, observed or ignored.
* Fixed: the dark theme escaped onto the WordPress dashboard and the orders list, where it painted pale text onto a white background.
* The whole-page Save button on Scoring and Blocking now sits at the foot of the page instead of inside a card.

= 2.0.0 =
* MightyShield now appears on the order itself. Open any order and the right-hand column shows its trust rating, the checks that tripped and what each one cost, and whatever action that order needs. Orders placed before MightyShield was installed can be rated from the same panel.
* Tell MightyShield how an order turned out with a Clean or Fraud verdict, and it weighs your answer against future orders from the same customer, device, address or network. Change your mind at any time: switching the verdict takes back whatever the previous one did to that customer's standing.
* Approve and Block now do the right thing for what actually happened to the money, read from your payment processor rather than from what MightyShield asked it to do. An order held on an authorization captures or voids; one held after payment moves to Processing or is cancelled with refund instructions; one held before payment sends the customer back to pay.
* A new Rating column on the orders list, so you can see at a glance which of a hundred orders is worth opening.
* The Fraud Review queue is rebuilt. It now says why each order is held and what happened to its money, and Approve and Block work directly from the list, so clearing ten held orders no longer means opening ten orders.
* A MightyShield widget on the WordPress dashboard: whether protection is on, the last 7 days of activity, and how many orders are waiting for you.
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
