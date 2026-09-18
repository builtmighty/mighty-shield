<?php
/**
 * Entity memory.
 *
 * The persistent identity graph. Every order is decomposed into the identities
 * behind it — email, phone, address, device, IP block, and later the card — and
 * each is tracked across orders with its own history.
 *
 * This is what catches the patient attacker. Velocity checks built on
 * transients forget everything within the hour, so a fraudster only has to wait.
 * An identity that caused a chargeback in March is still remembered in August.
 *
 * It also catches the one who rotates: fraudsters change attributes between
 * attempts, but never all of them at once, because every rotation costs money
 * or time. Linking orders through shared identities surfaces the overlap.
 *
 * Values are never stored in the clear. Everything is HMAC-hashed with a
 * per-site salt, so the tables carry no readable PII and cannot be correlated
 * across sites — see hash() for why the scope argument matters.
 *
 * @package MightyShield
 * @since   1.9.0
 */
namespace MightyShield\Includes;

class entities {

    /**
     * Entity types.
     *
     * @since   1.9.0
     */
    const TYPES = [
        'email'      => 'Email address',
        'email_root' => 'Email root (aliases collapsed)',
        'phone'      => 'Phone number',
        'address'    => 'Shipping address',
        'device'     => 'Device signature',
        'ip_block'   => 'IP network',
        'card_fp'    => 'Card fingerprint',
        'bin'        => 'Card BIN',
    ];

    /**
     * Domains that treat dots as insignificant and "+" as a tag separator.
     *
     * @since   1.9.0
     */
    const DOT_INSENSITIVE = [ 'gmail.com', 'googlemail.com' ];

    /**
     * Domains that are aliases of another domain.
     *
     * @since   1.9.0
     */
    const DOMAIN_ALIASES = [
        'googlemail.com' => 'gmail.com',
        'hotmail.co.uk'  => 'hotmail.com',
        'live.co.uk'     => 'live.com',
    ];

    /**
     * Reputation penalty applied per recorded outcome.
     *
     * A chargeback is worth far more than a denial, which is worth far more
     * than a refund — refunds are a normal part of retail and only matter in
     * volume.
     *
     * @since   1.9.0
     */
    const OUTCOME_WEIGHTS = [
        'approved'   => 1.0,
        'refunded'   => -2.0,
        'refused'    => -10.0,
        'denied'     => -25.0,
        'chargeback' => -100.0,
    ];

    /**
     * Reputation cannot run away in either direction.
     *
     * It was unbounded, and both ends were a problem. Three chargebacks on one
     * email reached -300, which is 200 points of penalty nothing can ever read,
     * and it made a later reversal arithmetically meaningless. At the other end
     * a customer with thirteen ordinary retail refunds over five years crossed
     * BAD_REPUTATION and started tripping entity_linked_bad on every order,
     * permanently, with nothing wrong with them.
     *
     * The floor is four times the worst single event and the ceiling is well
     * clear of GOOD_REPUTATION, so nothing here changes what a first, second or
     * third bad outcome means — only how far past the point of decision it can
     * accumulate.
     *
     * @since   2.2.0
     */
    const REPUTATION_FLOOR   = -200.0;
    const REPUTATION_CEILING = 50.0;

    /**
     * Reputation at or below which an identity is treated as known-bad.
     *
     * @since   1.9.0
     */
    const BAD_REPUTATION = -25.0;

    /**
     * Reputation at or above which an identity is treated as known-good, given
     * enough orders to mean anything.
     *
     * @since   1.9.0
     */
    const GOOD_REPUTATION = 3.0;

    /**
     * Orders an identity needs before a positive reputation counts as trusted.
     *
     * One clean order is not a track record, and treating it as one would let
     * an attacker mint trust with a single small purchase.
     *
     * @since   1.9.0
     */
    const TRUST_MIN_ORDERS = 3;

    /**
     * Hash a value for storage.
     *
     * The salt is per-site by default, so two MightyShield installs produce
     * different hashes for the same email and the tables cannot be joined
     * across sites. The scope argument exists so a shared-salt variant can be
     * derived later without a schema migration — cross-store intelligence is
     * deliberately not built here, but the door is left open at no cost.
     *
     * @since   1.9.0
     *
     * @param   string  $type   Entity type.
     * @param   string  $value  Normalized value.
     * @param   string  $scope  'site' (default) or 'global'.
     * @return  string  64-character hex digest, or '' for an empty value.
     */
    public static function hash( $type, $value, $scope = 'site' ) {

        $value = (string) $value;
        if( $value === '' ) return '';

        return hash_hmac( 'sha256', $type . '|' . $value, self::salt( $scope ) );

    }

    /**
     * The hashing salt for a scope.
     *
     * @since   1.9.0
     *
     * @param   string  $scope  'site' or 'global'.
     * @return  string
     */
    private static function salt( $scope ) {

        if( $scope === 'global' ) {
            // Reserved. Until cross-store intelligence exists there is nothing
            // to share, so this falls back to the site salt rather than
            // inventing a fixed constant that would leak correlatable hashes.
            return (string) apply_filters( 'mshield_entity_global_salt', self::salt( 'site' ) );
        }

        $salt = get_option( 'mshield_entity_salt', '' );

        if( empty( $salt ) ) {
            $salt = wp_generate_password( 64, true, true );
            update_option( 'mshield_entity_salt', $salt, false );
        }

        return $salt;

    }

    /**
     * Normalize a raw value for its entity type.
     *
     * @since   1.9.0
     *
     * @param   string  $type   Entity type.
     * @param   mixed   $value  Raw value.
     * @return  string  Normalized value, or '' when there is nothing usable.
     */
    public static function normalize( $type, $value ) {

        $value = trim( (string) $value );
        if( $value === '' ) return '';

        switch( $type ) {

            case 'email':
                return strtolower( $value );

            case 'email_root':
                return self::normalize_email_root( $value );

            case 'phone':
                return self::normalize_phone( $value );

            case 'address':
                return strtolower( $value );

            case 'ip_block':
                return self::normalize_ip_block( $value );

            case 'bin':
                $digits = preg_replace( '/\D/', '', $value );
                return strlen( $digits ) >= 6 ? substr( $digits, 0, 6 ) : '';

            case 'device':
            case 'card_fp':
            default:
                return $value;

        }

    }

    /**
     * Collapse an email to its deliverable root.
     *
     * "j.o.h.n+shopping@googlemail.com" and "john@gmail.com" reach the same
     * inbox, so treating them as different identities hands an attacker an
     * unlimited supply of "new" customers for free. This is the cheapest
     * evasion class to close in the whole system.
     *
     * @since   1.9.0
     *
     * @param   string  $email
     * @return  string
     */
    private static function normalize_email_root( $email ) {

        $email = strtolower( trim( $email ) );

        $at = strrpos( $email, '@' );
        if( $at === false ) return '';

        $local  = substr( $email, 0, $at );
        $domain = substr( $email, $at + 1 );

        if( $local === '' || $domain === '' ) return '';

        if( isset( self::DOMAIN_ALIASES[ $domain ] ) ) {
            $domain = self::DOMAIN_ALIASES[ $domain ];
        }

        // "+tag" suffixes are ignored by essentially every major provider.
        $plus = strpos( $local, '+' );
        if( $plus !== false ) {
            $local = substr( $local, 0, $plus );
        }

        if( in_array( $domain, self::DOT_INSENSITIVE, true ) ) {
            $local = str_replace( '.', '', $local );
        }

        if( $local === '' ) return '';

        return $local . '@' . $domain;

    }

    /**
     * Normalize a phone number to comparable digits.
     *
     * Not true E.164 — that needs a full country-prefix table this plugin has
     * no business carrying. This strips formatting and drops a NANP country
     * code so "+1 (555) 123-4567" and "5551234567" compare equal, which covers
     * the overwhelming majority of real traffic. Numbers too short to be a real
     * phone are discarded rather than compared.
     *
     * @since   1.9.0
     *
     * @param   string  $phone
     * @return  string
     */
    private static function normalize_phone( $phone ) {

        $digits = preg_replace( '/\D/', '', $phone );

        if( strlen( $digits ) === 11 && strpos( $digits, '1' ) === 0 ) {
            $digits = substr( $digits, 1 );
        }

        return strlen( $digits ) >= 7 ? $digits : '';

    }

    /**
     * Reduce an IP to its network block.
     *
     * /24 for IPv4 and /48 for IPv6. An attacker rotating within one subnet is
     * still one attacker, and IPv6 in particular hands out enormous ranges to a
     * single subscriber, so tracking individual addresses there is useless.
     *
     * @since   1.9.0
     *
     * @param   string  $ip
     * @return  string
     */
    private static function normalize_ip_block( $ip ) {

        // Already normalized. Idempotence matters more than it looks: every
        // other type round-trips, and an ip_block that silently returned ''
        // when handed its own output would make the identity disappear rather
        // than fail loudly — the worst failure mode for a fraud signal.
        if( preg_match( '#^[0-9a-f.:]+/(24|48)$#i', $ip ) ) return strtolower( $ip );

        if( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            $parts = explode( '.', $ip );
            return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
        }

        if( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            $expanded = self::expand_ipv6( $ip );
            if( $expanded === '' ) return '';
            return implode( ':', array_slice( explode( ':', $expanded ), 0, 3 ) ) . '::/48';
        }

        return '';

    }

    /**
     * Expand a compressed IPv6 address to its full eight-group form.
     *
     * @since   1.9.0
     *
     * @param   string  $ip
     * @return  string
     */
    private static function expand_ipv6( $ip ) {

        $packed = @inet_pton( $ip );
        if( $packed === false ) return '';

        $hex = bin2hex( $packed );

        return implode( ':', str_split( $hex, 4 ) );

    }

    /**
     * Build the full identity set for an order.
     *
     * @since   1.9.0
     *
     * @param   \WC_Order   $order
     * @return  array   type => normalized value (empty values omitted).
     */
    public static function for_order( $order ) {

        if( ! is_object( $order ) || ! method_exists( $order, 'get_billing_email' ) ) return [];

        $email = (string) $order->get_billing_email();

        $street = ai_detection::shipping_or_billing( $order, 'address_1' );
        $post   = ai_detection::shipping_or_billing( $order, 'postcode' );
        $ctry   = ai_detection::shipping_or_billing( $order, 'country' );

        $address = trim( ai_detection::normalize_address( $street ) . ' ' . $post . ' ' . $ctry );

        $raw = [
            'email'      => $email,
            'email_root' => $email,
            'phone'      => (string) $order->get_billing_phone(),
            'address'    => $street !== '' ? $address : '',
            'ip_block'   => (string) $order->get_customer_ip_address(),

            // The card, when the processor gave us one.
            //
            // card_fp is in PRECISE_IDENTITIES, so a card carrying a chargeback
            // is supposed to raise the banned floor -- but it was absent from
            // here and from for_checkout(), the only two places an identity set
            // is built. So assess() never saw a card: it was written by
            // card_signals and read by nothing, and the effective precise set
            // was email and email_root alone. A fraudster reusing a card behind
            // a fresh email and a fresh address scored clean with that card's
            // chargeback sitting in the table.
            //
            // Empty at checkout time on a new order -- the processor answers
            // after payment -- so this earns its keep on the re-rate, on the
            // outcome links, and in the history the model is shown.
            'card_fp'    => (string) $order->get_meta( '_mshield_card_fingerprint' ),
        ];

        return self::normalize_set( $raw );

    }

    /**
     * Build the identity set available before an order exists.
     *
     * @since   1.9.0
     *
     * @param   array   $data   Checkout data (billing_email, billing_phone, ...).
     * @return  array   type => normalized value.
     */
    public static function for_checkout( $data ) {

        $street = $data['shipping_address_1'] ?? ( $data['billing_address_1'] ?? '' );
        $post   = $data['shipping_postcode'] ?? ( $data['billing_postcode'] ?? '' );
        $ctry   = $data['shipping_country'] ?? ( $data['billing_country'] ?? '' );

        $address = trim( ai_detection::normalize_address( $street ) . ' ' . $post . ' ' . $ctry );

        $email = $data['billing_email'] ?? '';

        $raw = [
            'email'      => $email,
            'email_root' => $email,
            'phone'      => $data['billing_phone'] ?? '',
            'address'    => $street !== '' ? $address : '',
            'ip_block'   => ip_utils::get_client_ip(),
        ];

        return self::normalize_set( $raw );

    }

    /**
     * Normalize a raw type => value map, dropping anything unusable.
     *
     * @since   1.9.0
     *
     * @param   array   $raw
     * @return  array
     */
    private static function normalize_set( $raw ) {

        $set = [];

        foreach( $raw as $type => $value ) {

            $normalized = self::normalize( $type, $value );
            if( $normalized === '' ) continue;

            $set[ $type ] = $normalized;

        }

        return $set;

    }

    /**
     * Look up the stored record for one identity.
     *
     * @since   1.9.0
     *
     * @param   string  $type   Entity type.
     * @param   string  $value  Normalized value.
     * @return  array|null
     */
    public static function get( $type, $value ) {

        global $wpdb;

        $hash = self::hash( $type, $value );
        if( $hash === '' ) return null;

        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}mshield_entities WHERE entity_type = %s AND entity_hash = %s",
            $type,
            $hash
        ), ARRAY_A );

        return $row ?: null;

    }

    /**
     * Look up every identity in a set in one query.
     *
     * Batched deliberately: this runs on the checkout request, and one query
     * for six identities is the difference between a usable check and a
     * per-order latency cost nobody will accept.
     *
     * @since   1.9.0
     *
     * @param   array   $set    type => normalized value.
     * @return  array   type => row.
     */
    public static function get_many( $set ) {

        global $wpdb;

        if( empty( $set ) ) return [];

        $hashes   = [];
        $by_hash  = [];

        foreach( $set as $type => $value ) {
            $hash = self::hash( $type, $value );
            if( $hash === '' ) continue;
            $hashes[]         = $hash;
            $by_hash[ $hash ] = $type;
        }

        if( empty( $hashes ) ) return [];

        $placeholders = implode( ',', array_fill( 0, count( $hashes ), '%s' ) );

        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}mshield_entities WHERE entity_hash IN ({$placeholders})",
            $hashes
        ), ARRAY_A );

        $out = [];

        foreach( $rows as $row ) {
            // Match on type too: the hash already includes it, so a collision
            // across types is not possible, but reading it back this way keeps
            // the result keyed the way callers expect.
            if( ! isset( $by_hash[ $row['entity_hash'] ] ) ) continue;
            $out[ $row['entity_type'] ] = $row;
        }

        return $out;

    }

    /**
     * Record that an identity set was seen on an order.
     *
     * Creates any identity that does not exist yet, bumps last_seen and
     * order_count, and links each to the order.
     *
     * @since   1.9.0
     *
     * @param   array   $set        type => normalized value.
     * @param   int     $order_id   Order the identities were seen on.
     */
    public static function record( $set, $order_id = 0 ) {

        global $wpdb;

        $now = gmdate( 'Y-m-d H:i:s' );

        $order_id = (int) $order_id;

        foreach( $set as $type => $value ) {

            $hash = self::hash( $type, $value );
            if( $hash === '' ) continue;

            // Does this identity already know about this order?
            //
            // order_count used to be incremented unconditionally while link()
            // was an INSERT IGNORE, so it counted times-seen rather than
            // distinct orders -- and rescore::collect() calls this on every
            // click of "Rate Order". An admin re-rating one order five times
            // added five to the count behind it. That number gates
            // TRUST_MIN_ORDERS and is narrated to the AI as "seen on N previous
            // orders", so it was wrong in the two places it is read.
            $counts = $order_id > 0 ? ! self::is_linked( $type, $hash, $order_id ) : true;

            // Atomic upsert so two concurrent checkouts sharing an identity
            // cannot race to create duplicate rows.
            $wpdb->query( $wpdb->prepare(
                "INSERT INTO {$wpdb->prefix}mshield_entities
                    (entity_type, entity_hash, first_seen, last_seen, order_count)
                 VALUES (%s, %s, %s, %s, %d)
                 ON DUPLICATE KEY UPDATE
                    last_seen   = VALUES(last_seen),
                    order_count = order_count + %d",
                $type,
                $hash,
                $now,
                $now,
                $counts ? 1 : 0,
                $counts ? 1 : 0
            ) );

            if( $order_id > 0 ) {
                self::link( $type, $hash, $order_id, $now );
            }

        }

    }

    /**
     * Whether this identity is already linked to this order.
     *
     * @since   2.2.0
     *
     * @param   string  $type
     * @param   string  $hash
     * @param   int     $order_id
     * @return  bool
     */
    private static function is_linked( $type, $hash, $order_id ) {

        global $wpdb;

        return (bool) $wpdb->get_var( $wpdb->prepare(
            "SELECT 1 FROM {$wpdb->prefix}mshield_entity_links l
             INNER JOIN {$wpdb->prefix}mshield_entities e ON e.id = l.entity_id
             WHERE e.entity_type = %s AND e.entity_hash = %s AND l.order_id = %d
             LIMIT 1",
            $type,
            $hash,
            $order_id
        ) );

    }

    /**
     * Link an identity to an order.
     *
     * @since   1.9.0
     *
     * @param   string  $type
     * @param   string  $hash
     * @param   int     $order_id
     * @param   string  $now
     */
    private static function link( $type, $hash, $order_id, $now ) {

        global $wpdb;

        $entity_id = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT id FROM {$wpdb->prefix}mshield_entities WHERE entity_type = %s AND entity_hash = %s",
            $type,
            $hash
        ) );

        if( $entity_id <= 0 ) return;

        $wpdb->query( $wpdb->prepare(
            "INSERT IGNORE INTO {$wpdb->prefix}mshield_entity_links (entity_id, order_id, created_at)
             VALUES (%d, %d, %s)",
            $entity_id,
            $order_id,
            $now
        ) );

    }

    /**
     * Record an outcome against every identity on an order.
     *
     * This is the write half of the learning loop: Phase 4 calls it when an
     * order is approved, denied, refunded, or charged back, and Phase 1 reads
     * the result on the next order from the same identity.
     *
     * @since   1.9.0
     *
     * @param   int     $order_id   Order the outcome belongs to.
     * @param   string  $outcome    approved | denied | refunded | chargeback.
     * @return  int     Identities updated.
     */
    public static function record_outcome( $order_id, $outcome ) {

        global $wpdb;

        if( ! isset( self::OUTCOME_WEIGHTS[ $outcome ] ) ) return 0;

        $order_id = (int) $order_id;
        if( $order_id <= 0 ) return 0;

        $column = [
            'approved'   => 'approved_count',
            'denied'     => 'denied_count',
            'refunded'   => 'refund_count',
            'chargeback' => 'chargeback_count',
        ][ $outcome ];

        $delta = (float) self::OUTCOME_WEIGHTS[ $outcome ];

        // Update every identity linked to this order in one statement.
        // Clamped in SQL rather than in PHP, because this is a set update
        // across an unknown number of rows and reading them back to clamp
        // them would turn one statement into a loop with a race in it.
        return (int) $wpdb->query( $wpdb->prepare(
            "UPDATE {$wpdb->prefix}mshield_entities e
             INNER JOIN {$wpdb->prefix}mshield_entity_links l ON l.entity_id = e.id
             SET e.{$column} = e.{$column} + 1,
                 e.reputation = GREATEST(%f, LEAST(%f, e.reputation + %f))
             WHERE l.order_id = %d",
            self::REPUTATION_FLOOR,
            self::REPUTATION_CEILING,
            $delta,
            $order_id
        ) );

    }

    /**
     * Record that a checkout was refused, against the identities behind it.
     *
     * The other half of the learning loop, and it did not exist. Every write in
     * this class took an order id, and a refusal happens before an order does —
     * so the graph only ever learned from checkouts that were allowed through.
     * An attacker refused fifty times arrived at the fifty-first with no
     * history at all, which is the one case where history would have been
     * worth the most.
     *
     * Deliberately its own outcome rather than a `denied`. A denial is a person
     * looking at an order and saying no; a refusal is the plugin's own
     * arithmetic. Keeping them apart means a human's judgement still outranks a
     * heuristic, and lets one refusal cost less than one denial — at -10, three
     * refusals cross BAD_REPUTATION and the fourth attempt trips
     * entity_linked_bad, while a single one decides nothing.
     *
     * There is no order to link to, so nothing is linked. That leaves these
     * rows unlinked and therefore prunable, which is correct: a bot's
     * throwaway address should not be kept forever, and db::prune_entities()
     * keeps anything with a refusal on it for the full retention window before
     * letting it go.
     *
     * @since   2.2.0
     *
     * @param   array   $set    type => normalized value, from for_checkout().
     * @return  int     Identities recorded.
     */
    public static function record_refusal( $set ) {

        global $wpdb;

        if( empty( $set ) ) return 0;

        $now     = gmdate( 'Y-m-d H:i:s' );
        $delta   = (float) self::OUTCOME_WEIGHTS['refused'];
        $touched = 0;

        foreach( $set as $type => $value ) {

            $hash = self::hash( $type, $value );
            if( $hash === '' ) continue;

            // One statement, so a first-time identity and a returning one take
            // the same path -- and order_count is NOT incremented, because a
            // refused checkout is not an order and counting it as one would
            // feed TRUST_MIN_ORDERS with attempts the store turned away.
            $wpdb->query( $wpdb->prepare(
                "INSERT INTO {$wpdb->prefix}mshield_entities
                    (entity_type, entity_hash, first_seen, last_seen, refused_count, reputation)
                 VALUES (%s, %s, %s, %s, 1, %f)
                 ON DUPLICATE KEY UPDATE
                    last_seen     = VALUES(last_seen),
                    refused_count = refused_count + 1,
                    reputation    = GREATEST(%f, LEAST(%f, reputation + %f))",
                $type,
                $hash,
                $now,
                $now,
                max( self::REPUTATION_FLOOR, $delta ),
                self::REPUTATION_FLOOR,
                self::REPUTATION_CEILING,
                $delta
            ) );

            $touched++;

        }

        return $touched;

    }

    /**
     * Undo a previously recorded outcome.
     *
     * The mirror of record_outcome(). Reputation is cumulative, so a human
     * changing their mind about an order is not a relabelling — the -25 a
     * "denied" put on every identity is still there, and would keep depressing
     * that customer's next order forever unless it is taken back off.
     *
     * The counters are INT UNSIGNED. A plain `col - 1` on a zero column is an
     * out-of-range ERROR under MySQL strict mode, not a clamp to zero, so the
     * decrement is floored. Reputation is a signed FLOAT and needs no such
     * guard.
     *
     * @since   1.9.5
     *
     * @param   int     $order_id
     * @param   string  $outcome    The outcome being taken back.
     * @return  int     Rows affected.
     */
    public static function reverse_outcome( $order_id, $outcome ) {

        global $wpdb;

        if( ! isset( self::OUTCOME_WEIGHTS[ $outcome ] ) ) return 0;

        $order_id = (int) $order_id;
        if( $order_id <= 0 ) return 0;

        $column = [
            'approved'   => 'approved_count',
            'denied'     => 'denied_count',
            'refunded'   => 'refund_count',
            'chargeback' => 'chargeback_count',
        ][ $outcome ];

        $delta = (float) self::OUTCOME_WEIGHTS[ $outcome ];

        // Clamped on the way back too, so a reversal cannot push an identity
        // past the ceiling and mint trust out of an undone penalty.
        return (int) $wpdb->query( $wpdb->prepare(
            "UPDATE {$wpdb->prefix}mshield_entities e
             INNER JOIN {$wpdb->prefix}mshield_entity_links l ON l.entity_id = e.id
             SET e.{$column} = GREATEST( e.{$column}, 1 ) - 1,
                 e.reputation = GREATEST(%f, LEAST(%f, e.reputation - %f))
             WHERE l.order_id = %d",
            self::REPUTATION_FLOOR,
            self::REPUTATION_CEILING,
            $delta,
            $order_id
        ) );

    }

    /**
     * Identities precise enough to be a person.
     *
     * An identity is only as good as the number of people it covers. An email, a
     * normalised email root and a card fingerprint each name roughly one buyer.
     * A /24 names a few hundred households on a residential ISP or a carrier
     * NAT, and an address names everyone who lives there.
     *
     * That distinction was not being made, and it had teeth in both directions:
     *
     * - One disputed order marked its whole /24. entity_chargeback floors to
     *   BANNED, so the next unrelated shopper on that network was refused
     *   outright AND had their own address written to the permanent blocklist.
     *   Self-amplifying, and cheap to start deliberately against a network
     *   somebody wanted poisoned.
     * - The same breadth granted trust. Three cheap completed orders from one
     *   /24 earned entity_trusted, worth -40, for every later order from those
     *   few hundred households under any email and any card.
     *
     * So the broad identities still carry history -- they are genuinely useful
     * evidence, and entity_linked_bad still costs trust -- but they may no
     * longer decide an order on their own, in either direction.
     *
     * @since   2.1.1
     */
    const PRECISE_IDENTITIES = [ 'email', 'email_root', 'card_fp' ];

    /**
     * Whether an identity names a person rather than a network or a household.
     *
     * @since   2.1.1
     *
     * @param   string  $type
     * @return  bool
     */
    public static function is_precise( $type ) {

        return \in_array( $type, self::PRECISE_IDENTITIES, true );

    }

    /**
     * Assess an identity set and emit the matching signals.
     *
     * @since   1.9.0
     *
     * @param   array   $set    type => normalized value.
     * @return  array   The rows that were found, keyed by type.
     */
    public static function assess( $set ) {

        $rows = self::get_many( $set );
        if( empty( $rows ) ) return [];

        $worst_bad     = null;
        $has_denial    = false;
        $has_chargeback = false;
        $trusted        = false;

        foreach( $rows as $type => $row ) {

            $reputation = (float) $row['reputation'];
            $orders     = (int) $row['order_count'];

            if( (int) $row['chargeback_count'] > 0 ) {

                // A chargeback on a /24 or a shared address is history worth
                // knowing, not grounds to ban the next stranger who uses it.
                if( self::is_precise( $type ) ) {
                    $has_chargeback = true;
                } else {
                    $has_denial = true;
                }

                $worst_bad = $worst_bad ?? $type;

            }

            if( (int) $row['denied_count'] > 0 ) {
                $has_denial = true;
                $worst_bad  = $worst_bad ?? $type;
            }

            if( $reputation <= self::BAD_REPUTATION && $worst_bad === null ) {
                $worst_bad = $type;
            }

            // Trust has to be earned by something that names a buyer. A
            // network cannot vouch for the next person on it.
            if( self::is_precise( $type )
                && $reputation >= self::GOOD_REPUTATION
                && $orders >= self::TRUST_MIN_ORDERS ) {
                $trusted = true;
            }

        }

        if( $has_chargeback ) {
            risk_context::add(
                'entity_chargeback',
                sprintf( 'The %s on this order is linked to a previous chargeback', self::type_label( $worst_bad ) )
            );
        } elseif( $has_denial ) {
            risk_context::add(
                'entity_denied',
                sprintf( 'The %s on this order was denied in a previous review', self::type_label( $worst_bad ) )
            );
        } elseif( $worst_bad !== null ) {
            risk_context::add(
                'entity_linked_bad',
                sprintf( 'The %s on this order has a poor history', self::type_label( $worst_bad ) )
            );
        }

        // Trust is only meaningful in the absence of a bad mark. An identity
        // with both a clean streak and a chargeback is not a trusted customer.
        if( $trusted && $worst_bad === null ) {
            risk_context::add( 'entity_trusted', 'Returning customer with a clean order history' );
        }

        return $rows;

    }

    /**
     * Human-readable label for an entity type.
     *
     * @since   1.9.0
     *
     * @param   string|null $type
     * @return  string
     */
    public static function type_label( $type ) {

        if( $type === null ) return 'identity';

        return isset( self::TYPES[ $type ] ) ? strtolower( self::TYPES[ $type ] ) : $type;

    }

}
