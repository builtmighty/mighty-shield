<?php
/**
 * Signal catalog.
 *
 * The single source of truth for every scoring signal: its label, its group,
 * how much it contributes, and whether tripping it forces a risk level on its own.
 *
 * Phase 1 detectors emit into risk_context; Phase 2 turns the result into a
 * risk level. This class sits between them and owns the tunables, so the admin
 * Scoring tab and the checkout path can never disagree about what a signal is
 * worth.
 *
 * A weight is how much trust the signal COSTS when it fires, on the 1-100 trust
 * rating (100 = totally trustworthy). Negative weights are legal and meaningful
 * — a known-good returning customer earns trust back, which is what allows the
 * "trusted" risk level to fall out of the same arithmetic as every other risk level rather
 * than needing a special case.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes;

defined( 'ABSPATH' ) || exit;

class signals {

    /**
     * Signal group keys, in display order.
     *
     * Keys only since 3.0.0. The labels moved to groups(), because a const
     * cannot hold a __() call and these are column headings on the Scoring
     * tab. Anything that renders should call groups(); this is for code that
     * only needs the order or the set.
     *
     * @since   1.9.0
     */
    const GROUPS = [ 'identity', 'network', 'behavior', 'order', 'payment', 'history' ];

    /**
     * The catalog.
     *
     * group   Which section of the Scoring tab it appears under.
     * weight  Trust cost when this signal fires. Positive spends trust;
     *         negative earns it back. Scaled by detector confidence.
     * floor   Risk level this signal forces on its own, regardless of total score.
     *         'none' means the signal only contributes weight.
     *
     * The label and the description used to live here too, and moved to
     * strings() in 3.0.0: a const array cannot hold a __() call, so keeping
     * them here made every one of them permanently English. What is left is
     * the part that is not language, which is also the part the checkout path
     * reads — so the hot path still touches a const and nothing else.
     *
     * A floor is reserved for signals a legitimate shopper essentially cannot
     * trip. Everything ambiguous contributes weight and lets the total decide —
     * that is the whole point of scoring, and over-using floors collapses this
     * back into the all-or-nothing system being replaced.
     *
     * @since   1.9.0
     */
    const CATALOG = [

        // Identity.
        // 80, because this check used to refuse the order itself and the
        // merchant had no way to see or change that. Converting it to a pure
        // score without moving the weight would have quietly softened every
        // store on upgrade; 80 lands inside the rejected band on its own, so a
        // stock store behaves exactly as it did, and the number is now on a
        // screen where it can be turned down.
        'email_disposable' => [
            'group'  => 'identity',
            'weight' => 80.0,
            'floor'  => 'none',
        ],
        'email_no_mx' => [
            'group'  => 'identity',
            'weight' => 40.0,
            'floor'  => 'none',
        ],
        'email_role' => [
            'group'  => 'identity',
            // Weak alone — small businesses really do order from info@.
            'weight' => 10.0,
            'floor'  => 'none',
        ],
        'email_name_mismatch' => [
            'group'  => 'identity',
            'weight' => 10.0,
            'floor'  => 'none',
        ],
        // 80, for the same reason as email_disposable above -- and this one
        // gets strictly better in the process. The detector scales confidence
        // by how far its internal score got towards its threshold, so an
        // address AT the threshold now costs the full 80 and rejects, exactly
        // where the old hard block sat, while one at half the threshold costs
        // 40 and merely contributes. A cliff became a ramp with the same edge.
        'address_fake' => [
            'group'  => 'identity',
            'weight' => 80.0,
            'floor'  => 'none',
        ],
        'zip_state_mismatch' => [
            'group'  => 'identity',
            'weight' => 35.0,
            'floor'  => 'none',
        ],
        'address_unverified' => [
            'group'  => 'identity',
            'weight' => 30.0,
            'floor'  => 'none',
        ],
        'address_velocity' => [
            'group'  => 'identity',
            // The drop-address signature — but also apartment buildings,
            // offices, dorms and families.
            //
            // When this fires, address_bill_ship_mismatch is charged at half:
            // the two say the same thing about the same parcel, and charging
            // both in full (30 + 20) pushed the legitimate twin of the
            // stolen-card profile -- a first gift to a dorm from a mailbox
            // with no name in it -- past the Rejected line. The sums, on the
            // default ladder: gift to a busy address (this + bill/ship at 10
            // + name mismatch + high value + first order) is 70, High, a hold
            // and a human; the same order from an IP in another country adds
            // ip_geo_mismatch and is 85, Rejected. That is where each belongs:
            // the ambiguous one is looked at, the one with the network
            // against it too is refused, and the refusal is recorded against
            // its identities.
            'weight' => 30.0,
            'floor'  => 'none',
        ],
        'address_reshipper' => [
            'group'  => 'identity',
            // Heavier than address_velocity, and the difference is the point.
            //
            // address_velocity infers a drop address from behaviour: the same
            // street taking orders under several names. That needs the second
            // or third order before it says anything, and the first one has
            // already shipped.
            //
            // This is the merchant naming the address outright, so it is worth
            // more and it works on the first order. Still no floor: plenty of
            // people legitimately use a forwarding service to buy from
            // abroad, and refusing all of them on one signal would be a
            // policy decision, not a fraud finding. A store that wants it to
            // be a policy can set the weight to 100.
            'weight' => 45.0,
            'floor'  => 'none',
        ],
        'address_bill_ship_mismatch' => [
            'group'  => 'identity',
            // Deliberately low, and the reasoning matters because every
            // competitor weights this heavily.
            //
            // It is the most common fraud heuristic there is and also one of
            // the most common legitimate shapes: gifts, work addresses,
            // parcel lockers, students, anyone who has moved recently. On a
            // store that sells gifts it describes a large minority of real
            // customers, which is exactly what the Scoring tab's "how often
            // did this fire" column is there to reveal.
            //
            // 20 is enough to matter next to email_name_mismatch and not
            // enough to detain a birthday present. Next to address_velocity
            // it is charged at half -- see that signal's comment -- because
            // the two describe the same parcel.
            'weight' => 20.0,
            'floor'  => 'none',
        ],
        'phone_area_mismatch' => [
            'group'  => 'identity',
            // Very weak, and it has to stay that way. Area codes stopped
            // meaning geography when numbers became portable -- someone who
            // grew up in Ohio keeps a 614 number for life. It is worth
            // something only alongside other things.
            'weight' => 10.0,
            'floor'  => 'none',
        ],
        'phone_voip' => [
            'group'  => 'identity',
            'weight' => 20.0,
            'floor'  => 'none',
        ],
        'identity_blocklisted' => [
            'group'  => 'identity',
            // Same floor as ip_blocklisted, for the same reason: this is the
            // merchant's own instruction, not a verdict MightyShield formed,
            // and an instruction should not have to out-argue a trust score.
            'weight' => 100.0,
            'floor'  => 'banned',
        ],
        'country_blocked' => [
            'group'  => 'identity',
            // A floor, and one of only seven. This is not evidence about the
            // order -- it is the merchant saying "not there", and a decision
            // the merchant already made should not have to win an argument
            // against a trust score.
            'weight' => 100.0,
            'floor'  => 'rejected',
        ],
        'country_high_risk' => [
            'group'  => 'identity',
            'weight' => 30.0,
            'floor'  => 'none',
        ],

        // Network.
        'ip_blocklisted' => [
            'group'  => 'network',
            'weight' => 100.0,
            'floor'  => 'banned',
        ],
        // No floor any more, and no longer worth 100.
        //
        // A temporary block is MightyShield's own inference -- five declined
        // cards in an hour, or five checkout attempts -- and it is keyed on an
        // IP address, which on a carrier NAT, an office or a campus is hundreds
        // of unrelated people. Flooring it to Rejected meant one shopper working
        // through three cards locked out everybody sharing their address for a
        // day, whatever else was true of their order.
        //
        // 60 still drops a first-time order into High on its own, which is a
        // hold and a look from a human. It just is not a refusal by itself.
        'ip_temp_blocked' => [
            'group'  => 'network',
            'weight' => 60.0,
            'floor'  => 'none',
        ],
        'ip_geo_mismatch' => [
            'group'  => 'network',
            // Noisy on its own — gifts, travel, mobile carrier geolocation and
            // corporate egress all trip it. Useful in combination, weak alone.
            'weight' => 15.0,
            'floor'  => 'none',
        ],
        // 25, not 40.
        //
        // At 40 this reached High on its own alongside one other ordinary fact
        // -- an email that does not contain the buyer's name, say -- because
        // High begins at 50 and the maths is a flat subtraction with no
        // diminishing returns. Corporate egress through AWS or Azure is how a
        // large share of office workers reach the internet now, and Cloudflare
        // WARP and Zscaler both look like this. It is worth knowing and it is
        // not worth holding an order by itself.
        'ip_datacenter' => [
            'group'  => 'network',
            'weight' => 25.0,
            'floor'  => 'none',
        ],
        // ip_proxy was removed in 3.0.0. It is not a judgement about VPNs
        // changing — it is that there was never anything behind it.
        //
        // The data came from ip-api.com over HTTPS, which that service answers
        // with 403 unless you pay, so the lookup failed on every install and
        // this signal had never once fired. Replacing the source did not bring
        // it back: proxy, VPN and Tor status is a paid MaxMind product with no
        // free equivalent, and the whole point of the tri-state in ip_data is
        // that we do not guess when we cannot know.
        //
        // Nothing reads it now, and removing the entry is what makes that
        // true — a signal left in the catalogue is a row on the Scoring tab
        // with a weight a merchant can tune, which would be a lie about what
        // the plugin is measuring. A stored mshield_sig_ip_proxy_* override is
        // harmless: all three accessors resolve through this catalogue and
        // return early on an unknown key.

        // Behavior.
        'honeypot' => [
            'group'  => 'behavior',
            'weight' => 100.0,
            'floor'  => 'rejected',
        ],
        'device_automated' => [
            'group'  => 'behavior',
            'weight' => 100.0,
            'floor'  => 'rejected',
        ],
        'captcha_failed' => [
            'group'  => 'behavior',
            'weight' => 100.0,
            'floor'  => 'rejected',
        ],
        // Deliberately separate from captcha_failed, and deliberately without a
        // floor. This is every outcome that is NOT the provider saying "not a
        // person": a token already spent because the customer resubmitted after
        // a declined card, a token expired on a slowly filled form, or a widget
        // whose script an ad blocker or a corporate proxy never let load.
        //
        // All three used to land on captcha_failed, which floors to Rejected, so
        // pressing Place order twice rejected the order outright. A modest cost
        // and no floor means a run of them still drags an order down among
        // everything else known about it, while one on its own decides nothing.
        'captcha_unverified' => [
            'group'  => 'behavior',
            'weight' => 20.0,
            'floor'  => 'none',
        ],
        'timing_fast' => [
            'group'  => 'behavior',
            'weight' => 45.0,
            'floor'  => 'none',
        ],
        'timing_missing' => [
            'group'  => 'behavior',
            'weight' => 20.0,
            'floor'  => 'none',
        ],
        'device_tz_mismatch' => [
            'group'  => 'behavior',
            'weight' => 25.0,
            'floor'  => 'none',
        ],
        'device_missing' => [
            'group'  => 'behavior',
            'weight' => 20.0,
            'floor'  => 'none',
        ],
        'device_headless' => [
            'group'  => 'behavior',
            'weight' => 55.0,
            'floor'  => 'none',
        ],
        'input_scripted' => [
            'group'  => 'behavior',
            // Strong: a real customer cannot fill a field without the browser
            // emitting something, however they entered it.
            'weight' => 60.0,
            'floor'  => 'none',
        ],
        'interaction_none' => [
            'group'  => 'behavior',
            // Lower than it looks like it should be: keyboard-only shoppers,
            // assistive technology and heavily-autofilled forms all produce
            // very little, so this only earns its weight alongside something else.
            'weight' => 25.0,
            'floor'  => 'none',
        ],
        'cookies_none' => [
            'group'  => 'behavior',
            // Suggestive, not conclusive. A CDN or edge rule that strips
            // cookies would misfire on every order, so this compounds with
            // other signals rather than convicting on its own — and Scoring's
            // "how often it fires" column shows that failure immediately.
            'weight' => 30.0,
            'floor'  => 'none',
        ],
        'device_velocity' => [
            'group'  => 'behavior',
            'weight' => 50.0,
            'floor'  => 'none',
        ],

        // Order.
        'amount_low' => [
            'group'  => 'order',
            'weight' => 35.0,
            'floor'  => 'none',
        ],
        'high_value' => [
            'group'  => 'order',
            'weight' => 15.0,
            'floor'  => 'none',
        ],
        'amount_over_ceiling' => [
            'group'  => 'order',
            // Off by default (the ceiling ships at 0, which disables it).
            // Heavier than high_value because it is a deliberate line rather
            // than a statistic, but still short of deciding alone: a real
            // customer placing a genuinely large order is a good day, not an
            // incident.
            'weight' => 40.0,
            'floor'  => 'none',
        ],

        // Payment instrument.
        //
        // What the processor knows about the card, which the checkout form
        // never reveals. None of it reached this catalogue until 2.2.0: the
        // card layer read all of it, formed its own verdict, and held the order
        // on a single checkbox of its own on the Blocking tab. It was a second
        // fraud engine with one lever, and the merchant could not see what it
        // weighed or disagree with any part of it.
        //
        // These arrive after payment, so they are scored in a second pass that
        // replays the checkout verdict and adds them to it. See
        // card_signals::decide().
        'card_avs_fail' => [
            'group'  => 'payment',
            'weight' => 35.0,
            'floor'  => 'none',
        ],
        'card_cvc_fail' => [
            'group'  => 'payment',
            // 35 each, so AVS and CVC together reach 70 -- a trust rating of 30,
            // inside High, whose default action is to hold. That is exactly what
            // the old "hold on both" checkbox did, reached through the ladder
            // instead of around it. Unlike the checkbox, either one alone can
            // now be made to hold by raising its weight.
            'weight' => 35.0,
            'floor'  => 'none',
        ],
        'card_processor_risk' => [
            'group'  => 'payment',
            'weight' => 40.0,
            'floor'  => 'none',
        ],
        'card_prepaid_high_value' => [
            'group'  => 'payment',
            'weight' => 30.0,
            'floor'  => 'none',
        ],
        'card_country_mismatch' => [
            'group'  => 'payment',
            'weight' => 15.0,
            'floor'  => 'none',
        ],

        // Account behaviour, before the checkout.
        'coupon_bruteforce' => [
            'group'  => 'behavior',
            'weight' => 40.0,
            'floor'  => 'none',
        ],
        'login_failures' => [
            'group'  => 'behavior',
            'weight' => 35.0,
            'floor'  => 'none',
        ],
        'account_changed' => [
            'group'  => 'identity',
            // The other half of a takeover: the email, the password or the
            // saved address changed shortly before this order. People do
            // change these, so it is a cost, not a verdict -- but it is the
            // one thing that separates "an old customer somewhere new" from
            // "someone in an old customer's account", and it caps what a good
            // history can hand back (see risk_context::trust()).
            'weight' => 25.0,
            'floor'  => 'none',
        ],
        'registration_velocity' => [
            'group'  => 'behavior',
            'weight' => 45.0,
            'floor'  => 'none',
        ],
        'account_new' => [
            'group'  => 'history',
            // Everyone is new once. Only meaningful alongside something else.
            'weight' => 15.0,
            'floor'  => 'none',
        ],
        'email_root_velocity' => [
            'group'  => 'history',
            // Between velocity_emails (55) and velocity_orders (50), because
            // it is better evidence than either. Those two say an ADDRESS has
            // been busy, which behind a carrier NAT or in an office is a lot
            // of unrelated people. This says one identity has been busy, and
            // it holds even when the address changes -- which is the whole
            // reason a card tester rotates them.
            'weight' => 52.0,
            'floor'  => 'none',
        ],
        'first_order' => [
            'group'  => 'history',
            // 5, and it should stay near there.
            //
            // Competitors flag first-time buyers prominently, and on a growing
            // store that describes most of the order book. The useful work is
            // already done by entity_trusted, which pays 40 trust BACK to a
            // customer with real history -- the gap between a first order and
            // a tenth is 45 points, and this is only the smaller, honest half
            // of it.
            //
            // Charging a new customer heavily for being new is how a fraud
            // tool starts refusing growth.
            'weight' => 5.0,
            'floor'  => 'none',
        ],

        // History.
        // 80: it refused on its own before, so it still does.
        'rate_limited' => [
            'group'  => 'history',
            'weight' => 80.0,
            'floor'  => 'none',
        ],
        'velocity_emails' => [
            'group'  => 'history',
            'weight' => 55.0,
            'floor'  => 'none',
        ],
        'velocity_orders' => [
            'group'  => 'history',
            'weight' => 50.0,
            'floor'  => 'none',
        ],
        'failed_payments' => [
            'group'  => 'history',
            'weight' => 55.0,
            'floor'  => 'none',
        ],
        'store_under_attack' => [
            'group'  => 'network',
            // Not about this order: about the store. While the store-wide
            // decline rate is running far above normal, every unknown
            // customer costs a little more, because the one thing a spread-
            // out card-testing script cannot hide is the aggregate.
            //
            // "A little more" is the promise, so this stays under
            // ANOMALY_WEIGHT: at 30 it took a clean first-timer from Low to
            // Elevated on its own and, with one gift address, into a hold --
            // and capped every regular's history credit for the whole wave.
            // At 12 it tips an order that already has something against it
            // and leaves a clean one where it was.
            'weight' => 12.0,
            'floor'  => 'none',
        ],
        'entity_chargeback' => [
            'group'  => 'history',
            'weight' => 100.0,
            'floor'  => 'banned',
        ],
        'entity_denied' => [
            'group'  => 'history',
            'weight' => 70.0,
            'floor'  => 'none',
        ],
        'entity_linked_bad' => [
            'group'  => 'history',
            'weight' => 45.0,
            'floor'  => 'none',
        ],
        'entity_trusted' => [
            'group'  => 'history',
            'weight' => -40.0,
            'floor'  => 'none',
        ],
    ];

    /**
     * Per-signal configuration.
     *
     * The plumbing each check needs to do its job — thresholds, keys, limits —
     * shown on the signal's own row rather than on a separate tab. Everything
     * about a signal in one place: whether it is on, what it costs, whether it
     * forces a risk level, how often it fires, and how it is configured.
     *
     * These are pre-existing option names, deliberately unchanged. Renaming
     * them would silently reset every store's configuration on upgrade.
     *
     * type: check | number | text | password | textarea | select | radios
     *
     * @since   1.9.0
     */
    const SETTINGS = [

        // There is deliberately no "When this trips" here any more.
        //
        // Eight checks used to carry their own refuse-or-flag setting, and each
        // one was a second decision engine sitting in front of the real one: it
        // decided WHEN a signal was emitted, not only what happened next, so a
        // check set to flag emitted after the order existed, which is after the
        // last moment a checkout can be refused. The score arrived in two
        // halves either side of the order and the refusal was made on the first
        // half.
        //
        // Every row on this tab now does one thing: it scores. The weight is
        // the lever -- set one to 100 and that check rejects on its own -- and
        // what a score is worth doing is set once, on the Blocking tab.

        'email_disposable' => [
            [ 'option' => 'mshield_blocked_email_domains', 'type' => 'textarea',
              'label'  => 'Extra blocked domains, one per line' ],
            [ 'option' => 'mshield_email_list_enabled', 'type' => 'check',
              'label'  => 'Also use the shared list of known throwaway domains' ],
        ],
        'email_no_mx' => [
            [ 'option' => 'mshield_email_dns_check', 'type' => 'check',
              'label'  => 'Check that the domain can receive mail' ],
        ],
        'address_fake' => [
            [ 'option' => 'mshield_address_sensitivity', 'type' => 'radios',
              'label'  => 'Sensitivity',
              'choices' => [ 'low' => 'Low', 'medium' => 'Medium', 'high' => 'High' ] ],
        ],
        'zip_state_mismatch' => [
            [ 'option' => 'mshield_zip_state_enabled', 'type' => 'check', 'label' => 'Check US ZIP against state' ],
        ],
        'address_unverified' => [
            [ 'option' => 'mshield_smarty_enabled',    'type' => 'check',    'label' => 'Verify US addresses with Smarty' ],
            // stack: a credential is long and is copied in whole, so these get
            // a line each rather than sharing one at 190px.
            [ 'option' => 'mshield_smarty_auth_id',    'type' => 'text',     'label' => 'Auth ID',    'stack' => true ],
            [ 'option' => 'mshield_smarty_auth_token', 'type' => 'password', 'label' => 'Auth token', 'stack' => true ],
        ],
        'address_reshipper' => [
            [ 'option' => 'mshield_reshipper_addresses', 'type' => 'textarea',
              'label'  => 'Forwarding addresses, one per line — a street line, or a postcode' ],
        ],
        'address_velocity' => [
            [ 'option' => 'mshield_ai_velocity_orders', 'type' => 'number', 'label' => 'Other orders needed', 'min' => 2, 'max' => 100 ],
            [ 'option' => 'mshield_ai_velocity_days',   'type' => 'number', 'label' => 'Within days', 'min' => 1, 'max' => 365 ],
        ],
        'amount_low' => [
            [ 'option' => 'mshield_min_order_amount', 'type' => 'decimal', 'label' => 'Minimum order total', 'min' => 0, 'max' => 100000 ],
        ],
        'high_value' => [
            [ 'option' => 'mshield_ai_high_value_amount', 'type' => 'decimal',
              'label'  => 'High-value threshold (0 = work it out from my orders)', 'min' => 0, 'max' => 1000000 ],
        ],
        'amount_over_ceiling' => [
            [ 'option' => 'mshield_max_order_amount', 'type' => 'decimal',
              'label'  => 'Never accept above (0 = no ceiling)', 'min' => 0, 'max' => 10000000 ],
        ],
        'country_blocked' => [
            [ 'option' => 'mshield_blocked_countries', 'type' => 'textarea',
              'label'  => 'Countries you do not sell to — two-letter codes, one per line' ],
        ],
        'country_high_risk' => [
            [ 'option' => 'mshield_high_risk_countries', 'type' => 'textarea',
              'label'  => 'Countries to treat as higher risk — two-letter codes, one per line' ],
        ],
        'phone_voip' => [
            [ 'option' => 'mshield_phone_voip_prefixes', 'type' => 'textarea',
              'label'  => 'Extra virtual-line area codes, one per line' ],
        ],
        'honeypot' => [
            [ 'option' => 'mshield_honeypot_enabled', 'type' => 'check', 'label' => 'Add a hidden trap field to checkout' ],
        ],
        'timing_fast' => [
            [ 'option' => 'mshield_timing_enabled',     'type' => 'check',  'label' => 'Time how long checkout takes' ],
            [ 'option' => 'mshield_timing_min_seconds', 'type' => 'number', 'label' => 'Minimum seconds', 'min' => 1, 'max' => 120 ],
        ],
        'device_velocity' => [
            [ 'option' => 'mshield_fingerprint_velocity_threshold', 'type' => 'number',
              'label'  => 'Checkouts allowed per device', 'min' => 0, 'max' => 100 ],
        ],
        'device_missing' => [
            [ 'option' => 'mshield_fingerprint_enabled', 'type' => 'check', 'label' => 'Collect device information' ],
        ],
        // The provider, the keys and which forms are guarded live on the
        // Blocking tab, because the same challenge now guards login,
        // registration, lost password and comments as well as checkout. What
        // belongs here is what is purely a scoring concern -- and the reCAPTCHA
        // score threshold is exactly that. It was a hard-coded 0.5, which is
        // Google's suggested starting point and nothing more: v3 returns a
        // probability, and real customers on a VPN, a corporate proxy or a
        // datacenter IP score below it routinely, as does everybody on a brand
        // new key with no traffic history to learn from.
        'captcha_failed' => [
            [ 'option' => 'mshield_captcha_min_score', 'type' => 'decimal', 'min' => 0.05, 'max' => 0.95,
              'label'  => 'reCAPTCHA minimum score' ],
        ],
        'rate_limited' => [
            [ 'option' => 'mshield_rate_checkout_limit',  'type' => 'number', 'label' => 'Attempts allowed', 'min' => 1, 'max' => 100 ],
            [ 'option' => 'mshield_rate_checkout_window', 'type' => 'number', 'label' => 'Per how many seconds', 'min' => 60, 'max' => 86400 ],
        ],
        'ip_temp_blocked' => [
            [ 'option' => 'mshield_temp_block_duration', 'type' => 'number', 'label' => 'Block lasts (seconds)', 'min' => 3600, 'max' => 2592000 ],
        ],
        'velocity_emails' => [
            [ 'option' => 'mshield_velocity_email_threshold', 'type' => 'number', 'label' => 'Emails allowed per hour', 'min' => 1, 'max' => 100 ],
        ],
        'velocity_orders' => [
            [ 'option' => 'mshield_velocity_order_threshold', 'type' => 'number', 'label' => 'Orders allowed per 15 min', 'min' => 1, 'max' => 100 ],
        ],
        'failed_payments' => [
            [ 'option' => 'mshield_failed_payment_threshold', 'type' => 'number', 'label' => 'Failures allowed per hour', 'min' => 1, 'max' => 100 ],
        ],
        'coupon_bruteforce' => [
            [ 'option' => 'mshield_coupon_failure_threshold', 'type' => 'number', 'label' => 'Invalid codes allowed per hour', 'min' => 0, 'max' => 100 ],
        ],
        'login_failures' => [
            [ 'option' => 'mshield_login_failure_threshold', 'type' => 'number', 'label' => 'Failed logins allowed per hour', 'min' => 0, 'max' => 200 ],
        ],
        'registration_velocity' => [
            [ 'option' => 'mshield_registration_threshold', 'type' => 'number', 'label' => 'New accounts allowed per hour', 'min' => 0, 'max' => 100 ],
        ],
        'email_root_velocity' => [
            [ 'option' => 'mshield_velocity_root_threshold', 'type' => 'number',
              'label'  => 'Orders allowed per hour from one email', 'min' => 0, 'max' => 100 ],
        ],
        'account_new' => [
            [ 'option' => 'mshield_new_account_minutes', 'type' => 'number', 'label' => 'Counts as new for (minutes)', 'min' => 0, 'max' => 1440 ],
        ],
    ];

    /**
     * Configuration fields for a signal.
     *
     * @since   1.9.0
     *
     * @param   string  $key    Signal key.
     * @return  array
     */
    public static function fields( $key ) {

        if( ! isset( self::SETTINGS[ $key ] ) ) return [];

        return array_map( [ __CLASS__, 'translate_field' ], self::SETTINGS[ $key ] );

    }

    /**
     * The settings-field strings, written out so the translation extractor
     * can see them.
     *
     * translate_field() passes each label to __() as a variable, which makes
     * it invisible to a scanner -- the string would be translatable at run
     * time and absent from the .pot file, so no translator would ever be
     * offered it. Listing them here is the standard way round that.
     *
     * Nothing calls this. It exists to be read by tooling, and to fail
     * loudly in review if somebody adds a field and forgets its string.
     *
     * @since   3.0.0
     *
     * @codeCoverageIgnore
     */
    private static function settings_strings() {

        return [
            __( 'Extra blocked domains, one per line', 'mighty-shield' ),
            __( 'Also use the shared list of known throwaway domains', 'mighty-shield' ),
            __( 'Check that the domain can receive mail', 'mighty-shield' ),
            __( 'Sensitivity', 'mighty-shield' ),
            __( 'Low', 'mighty-shield' ),
            __( 'Medium', 'mighty-shield' ),
            __( 'High', 'mighty-shield' ),
            __( 'Check US ZIP against state', 'mighty-shield' ),
            __( 'Verify US addresses with Smarty', 'mighty-shield' ),
            __( 'Auth ID', 'mighty-shield' ),
            __( 'Auth token', 'mighty-shield' ),
            __( 'Forwarding addresses, one per line — a street line, or a postcode', 'mighty-shield' ),
            __( 'Other orders needed', 'mighty-shield' ),
            __( 'Within days', 'mighty-shield' ),
            __( 'Minimum order total', 'mighty-shield' ),
            __( 'High-value threshold (0 = work it out from my orders)', 'mighty-shield' ),
            __( 'Never accept above (0 = no ceiling)', 'mighty-shield' ),
            __( 'Countries you do not sell to — two-letter codes, one per line', 'mighty-shield' ),
            __( 'Countries to treat as higher risk — two-letter codes, one per line', 'mighty-shield' ),
            __( 'Extra virtual-line area codes, one per line', 'mighty-shield' ),
            __( 'Add a hidden trap field to checkout', 'mighty-shield' ),
            __( 'Time how long checkout takes', 'mighty-shield' ),
            __( 'Minimum seconds', 'mighty-shield' ),
            __( 'Checkouts allowed per device', 'mighty-shield' ),
            __( 'Collect device information', 'mighty-shield' ),
            __( 'reCAPTCHA minimum score', 'mighty-shield' ),
            __( 'Attempts allowed', 'mighty-shield' ),
            __( 'Per how many seconds', 'mighty-shield' ),
            __( 'Block lasts (seconds)', 'mighty-shield' ),
            __( 'Emails allowed per hour', 'mighty-shield' ),
            __( 'Orders allowed per hour from one email', 'mighty-shield' ),
            __( 'Orders allowed per 15 min', 'mighty-shield' ),
            __( 'Failures allowed per hour', 'mighty-shield' ),
            __( 'Invalid codes allowed per hour', 'mighty-shield' ),
            __( 'Failed logins allowed per hour', 'mighty-shield' ),
            __( 'New accounts allowed per hour', 'mighty-shield' ),
            __( 'Counts as new for (minutes)', 'mighty-shield' ),
        ];

    }

    /**
     * Translate the human-readable parts of one settings field.
     *
     * SETTINGS is a const like the catalogue, so the same problem applies: a
     * const cannot hold a __() call, and these are the labels beside every
     * input on the Scoring tab. Unlike the catalogue there is nothing to split
     * out -- the option name and the field type sit in the same row as the
     * label -- so the translation happens on the way out instead.
     *
     * The label is passed to __() as a variable, which the string extractor
     * cannot see. settings_strings() above exists to make them visible to it;
     * nothing calls it.
     *
     * @since   3.0.0
     *
     * @param   array   $field
     * @return  array
     */
    private static function translate_field( $field ) {

        if( isset( $field['label'] ) ) {
            // phpcs:ignore WordPress.WP.I18n.NonSingularStringLiteralText
            $field['label'] = __( $field['label'], 'mighty-shield' );
        }

        if( isset( $field['choices'] ) && is_array( $field['choices'] ) ) {
            foreach( $field['choices'] as $value => $choice_label ) {
                // phpcs:ignore WordPress.WP.I18n.NonSingularStringLiteralText
                $field['choices'][ $value ] = __( $choice_label, 'mighty-shield' );
            }
        }

        return $field;

    }

    /**
     * Every option name that appears on a signal row.
     *
     * Used to register them all against the Scoring group, so they save with
     * the rest of the tab.
     *
     * @since   1.9.0
     *
     * @return  array   option => field definition.
     */
    public static function all_fields() {

        $out = [];

        foreach( self::SETTINGS as $fields ) {
            foreach( $fields as $field ) $out[ $field['option'] ] = $field;
        }

        return $out;

    }

    /**
     * Whether a signal is enabled.
     *
     * @since   1.9.0
     *
     * @param   string  $key    Signal key.
     * @return  bool
     */
    public static function is_enabled( $key ) {

        if( ! isset( self::CATALOG[ $key ] ) ) return false;

        return get_option( 'mshield_sig_' . $key . '_enabled', 'yes' ) === 'yes';

    }

    /**
     * The configured trust cost of a signal.
     *
     * @since   1.9.0
     *
     * @param   string  $key    Signal key.
     * @return  float
     */
    public static function weight( $key ) {

        if( ! isset( self::CATALOG[ $key ] ) ) return 0.0;

        $stored = get_option( 'mshield_sig_' . $key . '_weight', null );

        if( $stored === null || $stored === '' ) {
            return (float) self::CATALOG[ $key ]['weight'];
        }

        return (float) $stored;

    }

    /**
     * The configured floor risk level of a signal.
     *
     * Returns 'none' when the signal only contributes weight.
     *
     * @since   1.9.0
     *
     * @param   string  $key    Signal key.
     * @return  string
     */
    public static function floor( $key ) {

        if( ! isset( self::CATALOG[ $key ] ) ) return 'none';

        $stored = get_option( 'mshield_sig_' . $key . '_floor', null );

        if( $stored === null || $stored === '' ) {
            return (string) self::CATALOG[ $key ]['floor'];
        }

        // Never trust a stored value that is not a real risk level — a typo in the
        // options table must not silently disable a floor.
        if( $stored !== 'none' && ! isset( risk_levels::LADDER[ $stored ] ) ) {
            return (string) self::CATALOG[ $key ]['floor'];
        }

        return (string) $stored;

    }

    /**
     * What each signal is called, and what it means, in the merchant's
     * language rather than the code's.
     *
     * Separate from CATALOG because a const array cannot hold a __() call,
     * and these all used to live in one. That made every label and every
     * description permanently English -- on the Scoring tab, which is the
     * screen a merchant spends the most time on and the one that has to be
     * readable for any of the tuning advice to mean anything.
     *
     * Built once per request. CATALOG keeps the part that is not language:
     * the group, the weight and the floor.
     *
     * @since   3.0.0
     *
     * @return  array   key => [ 'label' => string, 'desc' => string ]
     */
    private static function strings() {

        // Keyed by locale, not a plain memo.
        //
        // A plain static would freeze whichever language happened to be
        // active at the first call and serve it for the rest of the request.
        // That is wrong twice: a multilingual plugin can switch locale
        // mid-request, and anything that reached one of these accessors
        // before the textdomain loaded would pin the whole catalogue to
        // English. Keying on the locale costs one function call and makes
        // both cases correct.
        static $strings = [];

        $locale = function_exists( 'determine_locale' ) ? determine_locale() : '';

        if( isset( $strings[ $locale ] ) ) return $strings[ $locale ];

        $strings[ $locale ] = [

            'email_disposable' => [
                'label' => __( 'Disposable email address', 'mighty-shield' ),
                'desc'  => __( 'A throwaway inbox from a service that hands them out freely and deletes them minutes later.', 'mighty-shield' ),
            ],

            'email_no_mx' => [
                'label' => __( 'Email address cannot receive mail', 'mighty-shield' ),
                'desc'  => __( 'Nothing is listening at that domain, so the customer could never read an order confirmation.', 'mighty-shield' ),
            ],

            'email_role' => [
                'label' => __( 'Ordered from a shared mailbox', 'mighty-shield' ),
                'desc'  => __( 'An address like sales@ or info@ that belongs to a job rather than a person. Small businesses do order this way, so it means little on its own.', 'mighty-shield' ),
            ],

            'email_name_mismatch' => [
                'label' => __( 'Name does not appear in the email address', 'mighty-shield' ),
                'desc'  => __( 'The delivery name and the email share nothing. Ordinary for older or work addresses, but common on orders placed with someone else\'s details.', 'mighty-shield' ),
            ],

            'address_fake' => [
                'label' => __( 'Address looks made up', 'mighty-shield' ),
                'desc'  => __( 'Placeholder text, repeated characters, or a street line too short to be real.', 'mighty-shield' ),
            ],

            'zip_state_mismatch' => [
                'label' => __( 'US postcode does not match the state', 'mighty-shield' ),
                'desc'  => __( 'The ZIP code belongs to a different state from the one entered — usually a typo, sometimes an address that was never checked.', 'mighty-shield' ),
            ],

            'address_unverified' => [
                'label' => __( 'Address is not deliverable', 'mighty-shield' ),
                'desc'  => __( 'The postal service does not recognise it. Checked against USPS records, US addresses only.', 'mighty-shield' ),
            ],

            'address_velocity' => [
                'label' => __( 'Address used by several other buyers', 'mighty-shield' ),
                'desc'  => __( 'The same delivery address has recently taken orders under other names. The pattern of a drop address, though also of flats, offices and families.', 'mighty-shield' ),
            ],

            'address_reshipper' => [
                'label' => __( 'Delivering to a parcel-forwarding address', 'mighty-shield' ),
                'desc'  => __( 'The address is one you have listed as a freight forwarder or reshipper. Goods bought on a stolen card are often sent to one so they can leave the country before the chargeback lands.', 'mighty-shield' ),
            ],

            'address_bill_ship_mismatch' => [
                'label' => __( 'Billing and delivery addresses disagree', 'mighty-shield' ),
                'desc'  => __( 'The card is registered at one address and the goods go to another. Ordinary for a gift or a work delivery, so it counts for little on its own — but it is on almost every stolen-card order.', 'mighty-shield' ),
            ],

            'phone_area_mismatch' => [
                'label' => __( 'US phone area code is from a different state', 'mighty-shield' ),
                'desc'  => __( 'The number belongs to a state the order has nothing to do with. Weak on its own: mobile numbers follow people when they move.', 'mighty-shield' ),
            ],

            'phone_voip' => [
                'label' => __( 'Phone number is a virtual line', 'mighty-shield' ),
                'desc'  => __( 'The number belongs to a service that hands out disposable numbers rather than to a carrier, so it cannot be used to reach anyone later.', 'mighty-shield' ),
            ],

            'identity_blocklisted' => [
                'label' => __( 'Details are on your blocklist', 'mighty-shield' ),
                'desc'  => __( 'The email, phone, name, postcode, city or country on this order matches something you barred.', 'mighty-shield' ),
            ],

            'country_blocked' => [
                'label' => __( 'Country you do not sell to', 'mighty-shield' ),
                'desc'  => __( 'The order is going somewhere on your blocked list. A statement you made, not a judgement MightyShield formed.', 'mighty-shield' ),
            ],

            'country_high_risk' => [
                'label' => __( 'Country you treat as higher risk', 'mighty-shield' ),
                'desc'  => __( 'Somewhere you still sell to, but want looked at. Contributes to the rating; never decides on its own.', 'mighty-shield' ),
            ],

            'ip_blocklisted' => [
                'label' => __( 'Address is on your blocklist', 'mighty-shield' ),
                'desc'  => __( 'You or MightyShield barred this network earlier.', 'mighty-shield' ),
            ],

            'ip_temp_blocked' => [
                'label' => __( 'Address is under a temporary block', 'mighty-shield' ),
                'desc'  => __( 'Recently blocked for repeated failures or rapid-fire attempts. Lifts by itself.', 'mighty-shield' ),
            ],

            'ip_geo_mismatch' => [
                'label' => __( 'Order placed from a different region', 'mighty-shield' ),
                'desc'  => __( 'The connection resolves somewhere other than the delivery address. Normal for gifts, travel and mobile networks, so it counts most alongside something else.', 'mighty-shield' ),
            ],

            'ip_datacenter' => [
                'label' => __( 'Order came from a server, not a home connection', 'mighty-shield' ),
                'desc'  => __( 'The connection belongs to a hosting company. Real shoppers rarely buy from inside a data centre.', 'mighty-shield' ),
            ],

            'honeypot' => [
                'label' => __( 'Hidden trap field was filled in', 'mighty-shield' ),
                'desc'  => __( 'The checkout carries a field no person can see or reach. Only software fills it.', 'mighty-shield' ),
            ],

            'device_automated' => [
                'label' => __( 'Browser is being driven by software', 'mighty-shield' ),
                'desc'  => __( 'The browser openly reports that something is controlling it, which is how automated testing tools behave.', 'mighty-shield' ),
            ],

            'captcha_failed' => [
                'label' => __( 'Failed the bot challenge', 'mighty-shield' ),
                'desc'  => __( 'Cloudflare or Google judged the visitor not to be a person.', 'mighty-shield' ),
            ],

            'captcha_unverified' => [
                'label' => __( 'Bot challenge could not be confirmed', 'mighty-shield' ),
                'desc'  => __( 'The challenge was neither passed nor failed. Usually a resubmitted form or a blocked provider script, not a bot.', 'mighty-shield' ),
            ],

            'timing_fast' => [
                'label' => __( 'Checkout completed impossibly fast', 'mighty-shield' ),
                'desc'  => __( 'The form was submitted quicker than anyone could read and fill it.', 'mighty-shield' ),
            ],

            'timing_missing' => [
                'label' => __( 'Checkout could not be timed', 'mighty-shield' ),
                'desc'  => __( 'The timing marker never came back. Usually page caching stripping it, occasionally a script that skipped the form.', 'mighty-shield' ),
            ],

            'device_tz_mismatch' => [
                'label' => __( 'Device clock is set to another country', 'mighty-shield' ),
                'desc'  => __( 'The browser\'s time zone does not match where the order is billed.', 'mighty-shield' ),
            ],

            'device_missing' => [
                'label' => __( 'No device information was sent', 'mighty-shield' ),
                'desc'  => __( 'The page\'s scripts never ran. A few people block scripts; most automated checkouts do too.', 'mighty-shield' ),
            ],

            'device_headless' => [
                'label' => __( 'Browser is not what it claims to be', 'mighty-shield' ),
                'desc'  => __( 'It says it is one thing but behaves like another — the fingerprint of a browser running on a server with no screen.', 'mighty-shield' ),
            ],

            'input_scripted' => [
                'label' => __( 'Checkout was filled in by a script', 'mighty-shield' ),
                'desc'  => __( 'Fields gained values with no typing, pasting or autofill behind them. A person cannot fill a form without the browser noticing.', 'mighty-shield' ),
            ],

            'interaction_none' => [
                'label' => __( 'Nobody moved, typed or scrolled', 'mighty-shield' ),
                'desc'  => __( 'Not a single sign of a person on the page. Skipped on phones and tablets, where a quick tap-and-pay genuinely leaves almost nothing.', 'mighty-shield' ),
            ],

            'cookies_none' => [
                'label' => __( 'Browser arrived with no cookies', 'mighty-shield' ),
                'desc'  => __( 'Nothing in the cookie jar at all, which a shopper who filled a cart cannot manage. Scripted checkouts skip the jar entirely.', 'mighty-shield' ),
            ],

            'device_velocity' => [
                'label' => __( 'Too many orders from one device', 'mighty-shield' ),
                'desc'  => __( 'The same device has run through checkout repeatedly, whatever address it came from.', 'mighty-shield' ),
            ],

            'amount_low' => [
                'label' => __( 'Order total is unusually small', 'mighty-shield' ),
                'desc'  => __( 'Tiny charges are how stolen cards get tested before anything expensive is bought.', 'mighty-shield' ),
            ],

            'high_value' => [
                'label' => __( 'Order total is large', 'mighty-shield' ),
                'desc'  => __( 'Not suspicious by itself — it simply raises what is at stake if the order turns out to be fraud. Judged against your own order history unless you set a figure.', 'mighty-shield' ),
            ],

            'amount_over_ceiling' => [
                'label' => __( 'Order total is above your ceiling', 'mighty-shield' ),
                'desc'  => __( 'A hard limit you set. Different from the check above, which scales with your own takings — this one is a number you chose and does not move.', 'mighty-shield' ),
            ],

            'card_avs_fail' => [
                'label' => __( 'Billing address did not match the card', 'mighty-shield' ),
                'desc'  => __( 'The bank checked the address against its records and said no. One of the strongest stolen-card tells there is.', 'mighty-shield' ),
            ],

            'card_cvc_fail' => [
                'label' => __( 'Security code did not match', 'mighty-shield' ),
                'desc'  => __( 'The three digits on the back were wrong, which someone holding the real card rarely gets wrong.', 'mighty-shield' ),
            ],

            'card_processor_risk' => [
                'label' => __( 'The payment processor rated this risky', 'mighty-shield' ),
                'desc'  => __( 'Stripe Radar, or your processor\'s own fraud scoring, called this payment elevated or highest risk.', 'mighty-shield' ),
            ],

            'card_prepaid_high_value' => [
                'label' => __( 'Prepaid card on a large order', 'mighty-shield' ),
                'desc'  => __( 'A gift or prepaid card used for an expensive physical order. Untraceable and non-recoverable, which is the appeal.', 'mighty-shield' ),
            ],

            'card_country_mismatch' => [
                'label' => __( 'Card issued in another country', 'mighty-shield' ),
                'desc'  => __( 'The card was issued somewhere other than where the order ships. Ordinary for expats, travellers and gifts, so it counts most alongside something else.', 'mighty-shield' ),
            ],

            'coupon_bruteforce' => [
                'label' => __( 'Guessing at discount codes', 'mighty-shield' ),
                'desc'  => __( 'A run of invalid codes tried in a short time, which is someone fishing for a working one.', 'mighty-shield' ),
            ],

            'login_failures' => [
                'label' => __( 'Repeated failed sign-ins', 'mighty-shield' ),
                'desc'  => __( 'Many wrong passwords from one connection, which usually precedes an attempt to take over an account.', 'mighty-shield' ),
            ],

            'account_changed' => [
                'label' => __( 'Account details changed just before ordering', 'mighty-shield' ),
                'desc'  => __( 'The email, password or saved address on this account changed within the last three days. People do change these — but it is also the first thing done with a stolen login.', 'mighty-shield' ),
            ],

            'registration_velocity' => [
                'label' => __( 'Many new accounts from one connection', 'mighty-shield' ),
                'desc'  => __( 'Accounts being created in bulk rather than by people signing up.', 'mighty-shield' ),
            ],

            'account_new' => [
                'label' => __( 'Account created just before ordering', 'mighty-shield' ),
                'desc'  => __( 'Everyone is new once, so this only matters next to something else.', 'mighty-shield' ),
            ],

            'email_root_velocity' => [
                'label' => __( 'This email has ordered repeatedly, under variations', 'mighty-shield' ),
                'desc'  => __( 'Dots, plus-tags and alias domains all point at one inbox, and that inbox has ordered several times in the last hour. Changing the spelling is how a card tester gets a fresh start.', 'mighty-shield' ),
            ],

            'first_order' => [
                'label' => __( 'Nobody on this order has bought here before', 'mighty-shield' ),
                'desc'  => __( 'Not the email, the phone, the address, the device or the card. Every store wants first-time customers, so this is close to weightless — it is here so the rating can tell "new" apart from "known good".', 'mighty-shield' ),
            ],

            'rate_limited' => [
                'label' => __( 'Too many checkout attempts', 'mighty-shield' ),
                'desc'  => __( 'This connection has tried to check out more times than you allow in the window.', 'mighty-shield' ),
            ],

            'velocity_emails' => [
                'label' => __( 'Many different email addresses from one connection', 'mighty-shield' ),
                'desc'  => __( 'One visitor cycling through addresses, which is how card testing looks from the outside.', 'mighty-shield' ),
            ],

            'velocity_orders' => [
                'label' => __( 'Orders placed in rapid succession', 'mighty-shield' ),
                'desc'  => __( 'More orders from one connection in minutes than a shopper would place.', 'mighty-shield' ),
            ],

            'failed_payments' => [
                'label' => __( 'Repeated payment failures', 'mighty-shield' ),
                'desc'  => __( 'A run of declines from one connection or one mailbox — the clearest sign of cards being tried until one works.', 'mighty-shield' ),
            ],

            'store_under_attack' => [
                'label' => __( 'The store is seeing a wave of declines', 'mighty-shield' ),
                'desc'  => __( 'Failed payments across the whole store are running far above normal, which is what card testing spread across many addresses looks like. For an hour, every unknown customer costs a little more.', 'mighty-shield' ),
            ],

            'entity_chargeback' => [
                'label' => __( 'Linked to a previous chargeback', 'mighty-shield' ),
                'desc'  => __( 'The email, phone, address or card on this order was on an order the bank later reversed.', 'mighty-shield' ),
            ],

            'entity_denied' => [
                'label' => __( 'Linked to an order you rejected', 'mighty-shield' ),
                'desc'  => __( 'Something on this order matches one you previously turned down in review.', 'mighty-shield' ),
            ],

            'entity_linked_bad' => [
                'label' => __( 'Linked to a poor history', 'mighty-shield' ),
                'desc'  => __( 'Connected to earlier orders that did not end well, without a chargeback or rejection specifically.', 'mighty-shield' ),
            ],

            'entity_trusted' => [
                'label' => __( 'Known good customer', 'mighty-shield' ),
                'desc'  => __( 'A clean run of past orders, so this one starts with the benefit of the doubt. The only signal that adds trust rather than spending it.', 'mighty-shield' ),
            ],

        ];

        return $strings[ $locale ];

    }

    /**
     * Signal groups, in display order.
     *
     * Replaces the GROUPS const for anything that renders. GROUP_KEYS below
     * is still the const, for code that only needs the order.
     *
     * @since   3.0.0
     *
     * @return  array   group key => label
     */
    public static function groups() {

        return [
            'identity'   => __( 'Identity', 'mighty-shield' ),
            'network'    => __( 'Network', 'mighty-shield' ),
            'behavior'   => __( 'Behavior', 'mighty-shield' ),
            'order'      => __( 'Order', 'mighty-shield' ),
            'payment'    => __( 'Payment', 'mighty-shield' ),
            'history'    => __( 'History', 'mighty-shield' ),
        ];

    }

    /**
     * The human-readable label of a signal.
     *
     * @since   1.9.0
     *
     * @param   string  $key    Signal key.
     * @return  string
     */
    public static function label( $key ) {

        $strings = self::strings();

        return isset( $strings[ $key ]['label'] ) ? $strings[ $key ]['label'] : $key;

    }

    /**
     * A one-line explanation of what a signal means.
     *
     * Written for whoever is tuning the store, not for whoever wrote the check
     * — the admin shows this instead of the internal rule name, which told a
     * shop owner nothing.
     *
     * @since   1.9.0
     *
     * @param   string  $key    Signal key.
     * @return  string
     */
    public static function description( $key ) {

        $strings = self::strings();

        return isset( $strings[ $key ]['desc'] ) ? $strings[ $key ]['desc'] : '';

    }

    /**
     * Every signal key in a group.
     *
     * @since   1.9.0
     *
     * @param   string  $group  Group key (see GROUPS).
     * @return  string[]
     */
    public static function in_group( $group ) {

        $keys = [];

        foreach( self::CATALOG as $key => $signal ) {
            if( $signal['group'] === $group ) $keys[] = $key;
        }

        return $keys;

    }

}
