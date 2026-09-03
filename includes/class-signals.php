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

class signals {

    /**
     * Signal groups, in display order.
     *
     * @since   1.9.0
     */
    const GROUPS = [
        'identity' => 'Identity',
        'network'  => 'Network',
        'behavior' => 'Behavior',
        'order'    => 'Order',
        'history'  => 'History',
    ];

    /**
     * The catalog.
     *
     * label   Short name, shown in the admin.
     * desc    One line explaining what it means, shown on hover.
     * weight  Trust cost when this signal fires. Positive spends trust;
     *         negative earns it back. Scaled by detector confidence.
     * floor   Risk level this signal forces on its own, regardless of total score.
     *         'none' means the signal only contributes weight.
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
        'email_disposable' => [
            'label'  => 'Disposable email address',
            'desc'   => 'A throwaway inbox from a service that hands them out freely and deletes them minutes later.',
            'group'  => 'identity',
            'weight' => 45.0,
            'floor'  => 'none',
        ],
        'email_no_mx' => [
            'label'  => 'Email address cannot receive mail',
            'desc'   => 'Nothing is listening at that domain, so the customer could never read an order confirmation.',
            'group'  => 'identity',
            'weight' => 40.0,
            'floor'  => 'none',
        ],
        'email_role' => [
            'label'  => 'Ordered from a shared mailbox',
            'desc'   => 'An address like sales@ or info@ that belongs to a job rather than a person. Small businesses do order this way, so it means little on its own.',
            'group'  => 'identity',
            // Weak alone — small businesses really do order from info@.
            'weight' => 10.0,
            'floor'  => 'none',
        ],
        'email_name_mismatch' => [
            'label'  => 'Name does not appear in the email address',
            'desc'   => 'The delivery name and the email share nothing. Ordinary for older or work addresses, but common on orders placed with someone else\'s details.',
            'group'  => 'identity',
            'weight' => 10.0,
            'floor'  => 'none',
        ],
        'address_fake' => [
            'label'  => 'Address looks made up',
            'desc'   => 'Placeholder text, repeated characters, or a street line too short to be real.',
            'group'  => 'identity',
            'weight' => 40.0,
            'floor'  => 'none',
        ],
        'zip_state_mismatch' => [
            'label'  => 'US postcode does not match the state',
            'desc'   => 'The ZIP code belongs to a different state from the one entered — usually a typo, sometimes an address that was never checked.',
            'group'  => 'identity',
            'weight' => 35.0,
            'floor'  => 'none',
        ],
        'address_unverified' => [
            'label'  => 'Address is not deliverable',
            'desc'   => 'The postal service does not recognise it. Checked against USPS records, US addresses only.',
            'group'  => 'identity',
            'weight' => 30.0,
            'floor'  => 'none',
        ],
        'address_velocity' => [
            'label'  => 'Address used by several other buyers',
            'desc'   => 'The same delivery address has recently taken orders under other names. The pattern of a drop address, though also of flats, offices and families.',
            'group'  => 'identity',
            // The drop-address signature — but also apartment buildings,
            // offices, dorms and families. Tuned so the classic stolen-card
            // profile (this + name mismatch + high value + geo mismatch) lands
            // in "detained" rather than "rejected": that combination is real
            // evidence but genuinely ambiguous, and refusing it outright would
            // lose legitimate gift orders, keep no record, and teach the
            // system nothing.
            'weight' => 30.0,
            'floor'  => 'none',
        ],

        // Network.
        'ip_blocklisted' => [
            'label'  => 'Address is on your blocklist',
            'desc'   => 'You or MightyShield barred this network earlier.',
            'group'  => 'network',
            'weight' => 100.0,
            'floor'  => 'banned',
        ],
        'ip_temp_blocked' => [
            'label'  => 'Address is under a temporary block',
            'desc'   => 'Recently blocked for repeated failures or rapid-fire attempts. Lifts by itself.',
            'group'  => 'network',
            'weight' => 100.0,
            'floor'  => 'rejected',
        ],
        'ip_geo_mismatch' => [
            'label'  => 'Order placed from a different region',
            'desc'   => 'The connection resolves somewhere other than the delivery address. Normal for gifts, travel and mobile networks, so it counts most alongside something else.',
            'group'  => 'network',
            // Noisy on its own — gifts, travel, mobile carrier geolocation and
            // corporate egress all trip it. Useful in combination, weak alone.
            'weight' => 15.0,
            'floor'  => 'none',
        ],
        'ip_datacenter' => [
            'label'  => 'Order came from a server, not a home connection',
            'desc'   => 'The connection belongs to a hosting company. Real shoppers rarely buy from inside a data centre.',
            'group'  => 'network',
            'weight' => 40.0,
            'floor'  => 'none',
        ],
        'ip_proxy' => [
            'label'  => 'Order came through a VPN or proxy',
            'desc'   => 'The real location is hidden. Common among privacy-minded customers, so weighted lightly.',
            'group'  => 'network',
            // Deliberately low. VPNs are mainstream now, and this signal is
            // strongly correlated with device_tz_mismatch — a VPN is usually
            // what causes the timezone to disagree. Weighting both highly
            // double-counts one underlying fact and detains real travellers.
            'weight' => 15.0,
            'floor'  => 'none',
        ],

        // Behavior.
        'honeypot' => [
            'label'  => 'Hidden trap field was filled in',
            'desc'   => 'The checkout carries a field no person can see or reach. Only software fills it.',
            'group'  => 'behavior',
            'weight' => 100.0,
            'floor'  => 'rejected',
        ],
        'device_automated' => [
            'label'  => 'Browser is being driven by software',
            'desc'   => 'The browser openly reports that something is controlling it, which is how automated testing tools behave.',
            'group'  => 'behavior',
            'weight' => 100.0,
            'floor'  => 'rejected',
        ],
        'captcha_failed' => [
            'label'  => 'Failed the bot challenge',
            'desc'   => 'Cloudflare or Google judged the visitor not to be a person.',
            'group'  => 'behavior',
            'weight' => 100.0,
            'floor'  => 'rejected',
        ],
        'timing_fast' => [
            'label'  => 'Checkout completed impossibly fast',
            'desc'   => 'The form was submitted quicker than anyone could read and fill it.',
            'group'  => 'behavior',
            'weight' => 45.0,
            'floor'  => 'none',
        ],
        'timing_missing' => [
            'label'  => 'Checkout could not be timed',
            'desc'   => 'The timing marker never came back. Usually page caching stripping it, occasionally a script that skipped the form.',
            'group'  => 'behavior',
            'weight' => 20.0,
            'floor'  => 'none',
        ],
        'device_tz_mismatch' => [
            'label'  => 'Device clock is set to another country',
            'desc'   => 'The browser\'s time zone does not match where the order is billed.',
            'group'  => 'behavior',
            'weight' => 25.0,
            'floor'  => 'none',
        ],
        'device_missing' => [
            'label'  => 'No device information was sent',
            'desc'   => 'The page\'s scripts never ran. A few people block scripts; most automated checkouts do too.',
            'group'  => 'behavior',
            'weight' => 20.0,
            'floor'  => 'none',
        ],
        'device_headless' => [
            'label'  => 'Browser is not what it claims to be',
            'desc'   => 'It says it is one thing but behaves like another — the fingerprint of a browser running on a server with no screen.',
            'group'  => 'behavior',
            'weight' => 55.0,
            'floor'  => 'none',
        ],
        'input_scripted' => [
            'label'  => 'Checkout was filled in by a script',
            'desc'   => 'Fields gained values with no typing, pasting or autofill behind them. A person cannot fill a form without the browser noticing.',
            'group'  => 'behavior',
            // Strong: a real customer cannot fill a field without the browser
            // emitting something, however they entered it.
            'weight' => 60.0,
            'floor'  => 'none',
        ],
        'interaction_none' => [
            'label'  => 'Nobody moved, typed or scrolled',
            'desc'   => 'Not a single sign of a person on the page. Skipped on phones and tablets, where a quick tap-and-pay genuinely leaves almost nothing.',
            'group'  => 'behavior',
            // Lower than it looks like it should be: keyboard-only shoppers,
            // assistive technology and heavily-autofilled forms all produce
            // very little, so this only earns its weight alongside something else.
            'weight' => 25.0,
            'floor'  => 'none',
        ],
        'cookies_none' => [
            'label'  => 'Browser arrived with no cookies',
            'desc'   => 'Nothing in the cookie jar at all, which a shopper who filled a cart cannot manage. Scripted checkouts skip the jar entirely.',
            'group'  => 'behavior',
            // Suggestive, not conclusive. A CDN or edge rule that strips
            // cookies would misfire on every order, so this compounds with
            // other signals rather than convicting on its own — and Scoring's
            // "how often it fires" column shows that failure immediately.
            'weight' => 30.0,
            'floor'  => 'none',
        ],
        'device_velocity' => [
            'label'  => 'Too many orders from one device',
            'desc'   => 'The same device has run through checkout repeatedly, whatever address it came from.',
            'group'  => 'behavior',
            'weight' => 50.0,
            'floor'  => 'none',
        ],

        // Order.
        'amount_low' => [
            'label'  => 'Order total is unusually small',
            'desc'   => 'Tiny charges are how stolen cards get tested before anything expensive is bought.',
            'group'  => 'order',
            'weight' => 35.0,
            'floor'  => 'none',
        ],
        'high_value' => [
            'label'  => 'Order total is large',
            'desc'   => 'Not suspicious by itself — it simply raises what is at stake if the order turns out to be fraud.',
            'group'  => 'order',
            'weight' => 15.0,
            'floor'  => 'none',
        ],

        // Account behaviour, before the checkout.
        'coupon_bruteforce' => [
            'label'  => 'Guessing at discount codes',
            'desc'   => 'A run of invalid codes tried in a short time, which is someone fishing for a working one.',
            'group'  => 'behavior',
            'weight' => 40.0,
            'floor'  => 'none',
        ],
        'login_failures' => [
            'label'  => 'Repeated failed sign-ins',
            'desc'   => 'Many wrong passwords from one connection, which usually precedes an attempt to take over an account.',
            'group'  => 'behavior',
            'weight' => 35.0,
            'floor'  => 'none',
        ],
        'registration_velocity' => [
            'label'  => 'Many new accounts from one connection',
            'desc'   => 'Accounts being created in bulk rather than by people signing up.',
            'group'  => 'behavior',
            'weight' => 45.0,
            'floor'  => 'none',
        ],
        'account_new' => [
            'label'  => 'Account created just before ordering',
            'desc'   => 'Everyone is new once, so this only matters next to something else.',
            'group'  => 'history',
            // Everyone is new once. Only meaningful alongside something else.
            'weight' => 15.0,
            'floor'  => 'none',
        ],

        // History.
        'rate_limited' => [
            'label'  => 'Too many checkout attempts',
            'desc'   => 'This connection has tried to check out more times than you allow in the window.',
            'group'  => 'history',
            'weight' => 60.0,
            'floor'  => 'none',
        ],
        'velocity_emails' => [
            'label'  => 'Many different email addresses from one connection',
            'desc'   => 'One visitor cycling through addresses, which is how card testing looks from the outside.',
            'group'  => 'history',
            'weight' => 55.0,
            'floor'  => 'none',
        ],
        'velocity_orders' => [
            'label'  => 'Orders placed in rapid succession',
            'desc'   => 'More orders from one connection in minutes than a shopper would place.',
            'group'  => 'history',
            'weight' => 50.0,
            'floor'  => 'none',
        ],
        'failed_payments' => [
            'label'  => 'Repeated payment failures',
            'desc'   => 'A run of declines from one connection — the clearest sign of cards being tried until one works.',
            'group'  => 'history',
            'weight' => 55.0,
            'floor'  => 'none',
        ],
        'entity_chargeback' => [
            'label'  => 'Linked to a previous chargeback',
            'desc'   => 'The email, phone, address, device or card on this order was on an order the bank later reversed.',
            'group'  => 'history',
            'weight' => 100.0,
            'floor'  => 'banned',
        ],
        'entity_denied' => [
            'label'  => 'Linked to an order you rejected',
            'desc'   => 'Something on this order matches one you previously turned down in review.',
            'group'  => 'history',
            'weight' => 70.0,
            'floor'  => 'none',
        ],
        'entity_linked_bad' => [
            'label'  => 'Linked to a poor history',
            'desc'   => 'Connected to earlier orders that did not end well, without a chargeback or rejection specifically.',
            'group'  => 'history',
            'weight' => 45.0,
            'floor'  => 'none',
        ],
        'entity_trusted' => [
            'label'  => 'Known good customer',
            'desc'   => 'A clean run of past orders, so this one starts with the benefit of the doubt. The only signal that adds trust rather than spending it.',
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

        'email_disposable' => [
            [ 'option' => 'mshield_blocked_email_domains', 'type' => 'textarea',
              'label'  => 'Extra blocked domains, one per line' ],
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
            [ 'option' => 'mshield_smarty_auth_id',    'type' => 'text',     'label' => 'Auth ID' ],
            [ 'option' => 'mshield_smarty_auth_token', 'type' => 'password', 'label' => 'Auth token' ],
        ],
        'address_velocity' => [
            [ 'option' => 'mshield_ai_velocity_orders', 'type' => 'number', 'label' => 'Other orders needed', 'min' => 2, 'max' => 100 ],
            [ 'option' => 'mshield_ai_velocity_days',   'type' => 'number', 'label' => 'Within days', 'min' => 1, 'max' => 365 ],
        ],
        'amount_low' => [
            [ 'option' => 'mshield_min_order_amount', 'type' => 'text', 'label' => 'Minimum order total' ],
        ],
        'high_value' => [
            [ 'option' => 'mshield_ai_high_value_amount', 'type' => 'text', 'label' => 'High-value threshold' ],
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
        // captcha_failed has no settings row of its own: the provider, keys and
        // surfaces are configured on the Blocking tab, because the same
        // challenge now guards login, registration, lost password and comments
        // as well as checkout. What stays here is the SIGNAL -- its weight and
        // floor -- which is a scoring concern.
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

        return isset( self::SETTINGS[ $key ] ) ? self::SETTINGS[ $key ] : [];

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
     * The human-readable label of a signal.
     *
     * @since   1.9.0
     *
     * @param   string  $key    Signal key.
     * @return  string
     */
    public static function label( $key ) {

        return isset( self::CATALOG[ $key ] ) ? self::CATALOG[ $key ]['label'] : $key;

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

        return isset( self::CATALOG[ $key ]['desc'] ) ? self::CATALOG[ $key ]['desc'] : '';

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
