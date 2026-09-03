<?php
/**
 * Database.
 *
 * Custom table creation and query methods.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Includes;
class db {

    /**
     * Schema version.
     *
     * Tracked separately from MSHIELD_VERSION, and bumped whenever any table
     * definition in create_tables() changes.
     *
     * The plugin version cannot do this job: maybe_upgrade() stamps it as soon
     * as it runs, so a schema change made after that point — a column added in
     * a patch release, or any change during development on an install that has
     * already loaded the new version — would never be applied, leaving the code
     * writing to columns that do not exist. Gating on a dedicated counter makes
     * the schema converge no matter what order things happened in.
     *
     * @since   1.9.0
     */
    const SCHEMA_VERSION = 7;

    /**
     * Bring the schema up to date if it is behind.
     *
     * Safe to call on every load: it is one autoloaded option read in the
     * common case, and dbDelta only runs when the stored version is behind.
     *
     * @since   1.9.0
     */
    public static function maybe_upgrade_schema() {

        global $wpdb;

        $installed = (int) get_option( 'mshield_db_version', 0 );

        if( $installed >= self::SCHEMA_VERSION ) return;

        self::create_tables();

        // Schema 3 renamed mshield_risk.score to trust when the rating was
        // inverted (1-100, higher is better). dbDelta adds the new column but
        // cannot rename, so the old one has to be dropped explicitly — leaving
        // both would be genuinely dangerous here: a stale "score" of 15 reads
        // as low risk under the old scale and as nearly-worst under the new one.
        if( $installed > 0 && $installed < 3 ) {

            $table = $wpdb->prefix . 'mshield_risk';

            $has_score = $wpdb->get_var( $wpdb->prepare(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = 'score'",
                $table
            ) );

            if( $has_score ) {
                // Carry any existing values across before dropping, inverting
                // them onto the new scale so historic rows stay comparable.
                $wpdb->query( "UPDATE {$table} SET trust = GREATEST(1, 100 - score) WHERE trust = 0" );
                $wpdb->query( "ALTER TABLE {$table} DROP COLUMN score" );
            }

        }

        // Schema 5 renamed mshield_risk.band to risk_level, and band_source to
        // risk_level_source. "Band" was borrowed from tax and credit-score
        // bands and meant nothing to the people reading these screens. dbDelta
        // has already added the new columns, empty, so copy the values across
        // before dropping the old ones. Dropping band takes idx_band with it.
        //
        // 1.9.0 is unreleased, so this only ever runs on a development install
        // carrying the older build -- it is not load-bearing for any shipped
        // site, and can be deleted once no sandbox is on the old schema.
        //
        // Unlike the score -> trust rename this is purely a name change, so
        // there is nothing to convert and an interrupted upgrade is safe to
        // repeat: the guard is the column's existence, not the version.
        if( $installed > 0 && $installed < 5 ) {

            $table = $wpdb->prefix . 'mshield_risk';

            // Literal legacy names. These are historical strings, not the
            // current vocabulary -- a global rename that rewrites the left-hand
            // side here turns the loop into "copy risk_level onto itself, then
            // drop it", which destroys the column it was meant to create.
            $renames = [ 'band' => 'risk_level', 'band_source' => 'risk_level_source' ];

            foreach( $renames as $from => $to ) {

                // Belt and braces against exactly that: never drop a column
                // that is its own rename target.
                if( $from === $to ) continue;

                $has_old = $wpdb->get_var( $wpdb->prepare(
                    "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s",
                    $table,
                    $from
                ) );

                if( ! $has_old ) continue;

                $wpdb->query( "UPDATE {$table} SET {$to} = {$from} WHERE {$to} = ''" );
                $wpdb->query( "ALTER TABLE {$table} DROP COLUMN {$from}" );

            }

        }

        // Schema 6 renamed the three configurable risk levels once their action
        // became a setting: a level called "detained" that had been configured
        // only to flag was lying about itself. monitored -> low,
        // challenged -> elevated, detained -> high. trusted, rejected and
        // banned are unchanged.
        //
        // Same rule as above: these left-hand strings are historical. A global
        // rename that rewrites them turns each pair into a self-map, and the
        // guard inside rename_levels() is then the only thing between this and
        // a no-op that looks like it worked.
        if( $installed > 0 && $installed < 6 ) {

            self::rename_levels( [ 'monitored' => 'low', 'challenged' => 'elevated', 'detained' => 'high' ] );

        }

        // Schema 7 added mshield_risk.rated_by, telling a rating scored at
        // checkout apart from one a reviewer asked for later. The two are not
        // the same statement: the manual one cannot replay the bot, timing or
        // device layers, so it is partial by construction. dbDelta adds the
        // column; existing rows keep the '' default, which is correct — every
        // row that predates this was scored at checkout.

        update_option( 'mshield_db_version', self::SCHEMA_VERSION, true );

    }

    /**
     * Rewrite stored risk-level keys after a rename.
     *
     * Four places hold a level key: the risk table's column, the mirror on the
     * order, the per-level threshold option NAMES, and the per-signal floor
     * option VALUES. Missing any one leaves a store half-renamed — thresholds
     * silently falling back to defaults, or a signal floor pointing at a level
     * that no longer exists.
     *
     * @since   1.9.1
     *
     * @param   array   $levels     old key => new key.
     */
    private static function rename_levels( $levels ) {

        global $wpdb;

        $table = $wpdb->prefix . 'mshield_risk';

        foreach( $levels as $from => $to ) {

            // A self-map would rewrite a column onto itself and rename an
            // option to the name it already has.
            if( $from === $to ) continue;

            $wpdb->query( $wpdb->prepare(
                "UPDATE {$table} SET risk_level = %s WHERE risk_level = %s",
                $to,
                $from
            ) );

            $wpdb->query( $wpdb->prepare(
                "UPDATE {$wpdb->postmeta} SET meta_value = %s
                 WHERE meta_key = '_mshield_risk_level' AND meta_value = %s",
                $to,
                $from
            ) );

            // HPOS keeps order meta in its own table when it is in use.
            $hpos = $wpdb->prefix . 'wc_orders_meta';
            if( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $hpos ) ) === $hpos ) {
                $wpdb->query( $wpdb->prepare(
                    "UPDATE {$hpos} SET meta_value = %s
                     WHERE meta_key = '_mshield_risk_level' AND meta_value = %s",
                    $to,
                    $from
                ) );
            }

            $old_opt = 'mshield_level_' . $from . '_threshold';
            $stored  = get_option( $old_opt, null );

            if( $stored !== null ) {
                update_option( 'mshield_level_' . $to . '_threshold', $stored );
                delete_option( $old_opt );
            }

            $wpdb->query( $wpdb->prepare(
                "UPDATE {$wpdb->options} SET option_value = %s
                 WHERE option_name LIKE %s AND option_value = %s",
                $to,
                'mshield\\_sig\\_%\\_floor',
                $from
            ) );

        }

        wp_cache_flush();

    }

    /**
     * Create tables.
     *
     * dbDelta is idempotent — it adds missing tables and columns and leaves
     * existing data alone — so this doubles as the migration path.
     *
     * @since   1.0.0
     */
    public static function create_tables() {

        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        // Log table.
        $log_table = $wpdb->prefix . 'mshield_log';
        $sql_log = "CREATE TABLE {$log_table} (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            ip VARCHAR(45) NOT NULL DEFAULT '',
            endpoint VARCHAR(255) NOT NULL DEFAULT '',
            action VARCHAR(50) NOT NULL DEFAULT '',
            reason VARCHAR(255) NOT NULL DEFAULT '',
            request_data TEXT,
            order_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            trust FLOAT NULL DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ip (ip),
            INDEX idx_action (action),
            INDEX idx_order (order_id),
            INDEX idx_created (created_at)
        ) {$charset_collate};";

        // Rate limits table.
        $rate_table = $wpdb->prefix . 'mshield_rate_limits';
        $sql_rate = "CREATE TABLE {$rate_table} (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            identifier VARCHAR(255) NOT NULL DEFAULT '',
            action_type VARCHAR(50) NOT NULL DEFAULT '',
            count INT UNSIGNED NOT NULL DEFAULT 0,
            window_start DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            window_end DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE INDEX idx_identifier_action (identifier, action_type),
            INDEX idx_window_end (window_end)
        ) {$charset_collate};";

        // IP geolocation data cache.
        $ipdata_table = $wpdb->prefix . 'mshield_ip_data';
        $sql_ipdata = "CREATE TABLE {$ipdata_table} (
            ip VARCHAR(45) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT '',
            city VARCHAR(100) NOT NULL DEFAULT '',
            region VARCHAR(100) NOT NULL DEFAULT '',
            country VARCHAR(10) NOT NULL DEFAULT '',
            org VARCHAR(191) NOT NULL DEFAULT '',
            asname VARCHAR(191) NOT NULL DEFAULT '',
            proxy TINYINT NOT NULL DEFAULT -1,
            hosting TINYINT NOT NULL DEFAULT -1,
            mobile TINYINT NOT NULL DEFAULT -1,
            fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ip)
        ) {$charset_collate};";

        // Per-order risk verdicts. Separate from the log because a log row is
        // an event and this is a decision — one row per order, queryable by
        // risk level and outcome so the review queue and the tuning reports can be
        // built on it.
        $risk_table = $wpdb->prefix . 'mshield_risk';
        $sql_risk = "CREATE TABLE {$risk_table} (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            order_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            trust FLOAT NOT NULL DEFAULT 0,
            risk_level VARCHAR(20) NOT NULL DEFAULT '',
            risk_level_source VARCHAR(64) NOT NULL DEFAULT '',
            action_taken VARCHAR(32) NOT NULL DEFAULT '',
            signals TEXT,
            ai_rating TINYINT UNSIGNED NULL DEFAULT NULL,
            ai_verdict VARCHAR(20) NOT NULL DEFAULT '',
            outcome VARCHAR(20) NOT NULL DEFAULT '',
            rated_by VARCHAR(16) NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE INDEX idx_order (order_id),
            INDEX idx_risk_level (risk_level),
            INDEX idx_outcome (outcome),
            INDEX idx_created (created_at)
        ) {$charset_collate};";

        // Identity graph. Values are HMAC-hashed before they get here, so this
        // table holds no readable PII.
        $entities_table = $wpdb->prefix . 'mshield_entities';
        $sql_entities = "CREATE TABLE {$entities_table} (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            entity_type VARCHAR(20) NOT NULL DEFAULT '',
            entity_hash CHAR(64) NOT NULL DEFAULT '',
            first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            order_count INT UNSIGNED NOT NULL DEFAULT 0,
            approved_count INT UNSIGNED NOT NULL DEFAULT 0,
            denied_count INT UNSIGNED NOT NULL DEFAULT 0,
            refund_count INT UNSIGNED NOT NULL DEFAULT 0,
            chargeback_count INT UNSIGNED NOT NULL DEFAULT 0,
            reputation FLOAT NOT NULL DEFAULT 0,
            UNIQUE INDEX idx_type_hash (entity_type, entity_hash),
            INDEX idx_hash (entity_hash),
            INDEX idx_reputation (reputation)
        ) {$charset_collate};";

        // Identity-to-order links. This is what makes "a different email, but
        // the same device as two denied orders" answerable.
        $links_table = $wpdb->prefix . 'mshield_entity_links';
        $sql_links = "CREATE TABLE {$links_table} (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            entity_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            order_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE INDEX idx_entity_order (entity_id, order_id),
            INDEX idx_order (order_id)
        ) {$charset_collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql_log );
        dbDelta( $sql_rate );
        dbDelta( $sql_ipdata );
        dbDelta( $sql_risk );
        dbDelta( $sql_entities );
        dbDelta( $sql_links );

    }

    /**
     * Store the risk verdict for an order.
     *
     * One row per order, keyed by the UNIQUE index on order_id.
     *
     * ⚠ This is a REPLACE, not an UPDATE. MySQL deletes the conflicting row and
     * inserts a new one, so EVERY column not present in $verdict reverts to its
     * default — a re-rate that omits `outcome` erases a recorded chargeback, one
     * that omits `created_at` moves the row into today's statistics window, and
     * one that omits `ai_rating` nulls it. Any caller re-rating an existing
     * order must read get_risk() first and carry those forward; see
     * rescore::persist() for the pattern.
     *
     * @since   1.9.0
     *
     * @param   int     $order_id   Order ID.
     * @param   array   $verdict    Keys: trust, risk_level, risk_level_source,
     *                              action_taken, signals, ai_rating, ai_verdict,
     *                              outcome, rated_by, created_at.
     */
    public static function save_risk( $order_id, $verdict ) {

        global $wpdb;

        $order_id = (int) $order_id;
        if( $order_id <= 0 ) return;

        $signals = isset( $verdict['signals'] ) ? $verdict['signals'] : [];
        if( is_array( $signals ) ) $signals = (string) wp_json_encode( $signals );

        // These match the column names, so a row written here reads back
        // through get_risk() under exactly the same keys.
        $level  = $verdict['risk_level']        ?? '';
        $source = $verdict['risk_level_source'] ?? '';

        $data = [
            'order_id'          => $order_id,
            'trust'             => (float) ( $verdict['trust'] ?? 0 ),
            'risk_level'        => substr( sanitize_text_field( $level ), 0, 20 ),
            'risk_level_source' => substr( sanitize_text_field( $source ), 0, 64 ),
            'action_taken'      => substr( sanitize_text_field( $verdict['action_taken'] ?? '' ), 0, 32 ),
            'signals'           => $signals,
            'ai_verdict'        => substr( sanitize_text_field( $verdict['ai_verdict'] ?? '' ), 0, 20 ),
            'outcome'           => substr( sanitize_text_field( $verdict['outcome'] ?? '' ), 0, 20 ),
            'rated_by'          => substr( sanitize_text_field( $verdict['rated_by'] ?? '' ), 0, 16 ),
            // Supplied by a caller re-rating an existing order, so the row keeps
            // its place in the statistics windows. See the REPLACE warning above.
            'created_at'        => ! empty( $verdict['created_at'] )
                ? substr( sanitize_text_field( $verdict['created_at'] ), 0, 19 )
                : gmdate( 'Y-m-d H:i:s' ),
        ];

        $format = [ '%d', '%f', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ];

        // Nullable: an unrated order must store NULL, not 0, or "0/10" would
        // read as the most fraudulent rating possible.
        if( isset( $verdict['ai_rating'] ) && $verdict['ai_rating'] !== null ) {
            $data['ai_rating'] = (int) $verdict['ai_rating'];
            $format[]          = '%d';
        }

        $wpdb->replace( $wpdb->prefix . 'mshield_risk', $data, $format );

    }

    /**
     * Read the stored risk verdict for an order.
     *
     * @since   1.9.0
     *
     * @param   int     $order_id
     * @return  array|null
     */
    public static function get_risk( $order_id ) {

        global $wpdb;

        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}mshield_risk WHERE order_id = %d",
            (int) $order_id
        ), ARRAY_A );

        return $row ?: null;

    }

    /**
     * Record the final outcome of an order against its risk row.
     *
     * @since   1.9.0
     *
     * @param   int     $order_id
     * @param   string  $outcome    approved | denied | refunded | chargeback.
     */
    public static function set_risk_outcome( $order_id, $outcome ) {

        global $wpdb;

        $wpdb->update(
            $wpdb->prefix . 'mshield_risk',
            [ 'outcome' => substr( sanitize_text_field( $outcome ), 0, 20 ) ],
            [ 'order_id' => (int) $order_id ],
            [ '%s' ],
            [ '%d' ]
        );

    }

    /**
     * How often each signal actually fired, over a period.
     *
     * This is what turns tuning from guesswork into data: a weight is only
     * defensible next to the rate at which the signal trips and what those
     * orders turned out to be.
     *
     * Tallied in PHP rather than SQL. The signals column is TEXT holding JSON,
     * and JSON_EXTRACT over a TEXT column is both non-portable across the MySQL
     * and MariaDB versions stores actually run, and unindexable — so it would
     * be a full scan either way. Capping the row count keeps an admin screen
     * responsive on a busy store.
     *
     * @since   1.9.0
     *
     * @param   int     $days   Days to look back.
     * @param   int     $limit  Maximum rows to sample.
     * @return  array   [ signal_key => [ 'count' => int, 'levels' => [ level => int ] ] ]
     */
    public static function get_signal_stats( $days = 30, $limit = 2000 ) {

        global $wpdb;

        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT risk_level, signals FROM {$wpdb->prefix}mshield_risk
             WHERE created_at >= DATE_SUB( %s, INTERVAL %d DAY )
             ORDER BY id DESC
             LIMIT %d",
            gmdate( 'Y-m-d H:i:s' ),
            max( 1, (int) $days ),
            max( 1, (int) $limit )
        ), ARRAY_A );

        $out = [];

        foreach( $rows as $row ) {

            $signals = json_decode( (string) $row['signals'], true );
            if( ! is_array( $signals ) ) continue;

            foreach( $signals as $signal ) {

                $key = is_array( $signal ) ? ( $signal['key'] ?? '' ) : '';
                if( $key === '' ) continue;

                if( ! isset( $out[ $key ] ) ) {
                    $out[ $key ] = [ 'count' => 0, 'levels' => [] ];
                }

                $out[ $key ]['count']++;

                $level = (string) $row['risk_level'];
                $out[ $key ]['levels'][ $level ] = ( $out[ $key ]['levels'][ $level ] ?? 0 ) + 1;

            }

        }

        uasort( $out, function( $a, $b ) { return $b['count'] <=> $a['count']; } );

        return $out;

    }

    /**
     * Total risk rows in a period, so trip rates have a denominator.
     *
     * @since   1.9.0
     *
     * @param   int     $days
     * @return  int
     */
    public static function get_risk_count( $days = 30 ) {

        global $wpdb;

        return (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}mshield_risk
             WHERE created_at >= DATE_SUB( %s, INTERVAL %d DAY )",
            gmdate( 'Y-m-d H:i:s' ),
            max( 1, (int) $days )
        ) );

    }

    /**
     * Count orders per risk level over a period, with how each was resolved.
     *
     * Drives the tuning report — a fraud tool that cannot show its own
     * false-positive rate cannot be tuned.
     *
     * @since   1.9.0
     *
     * @param   int     $days   Days to look back.
     * @return  array   Rows of risk_level, outcome, total.
     */
    public static function get_risk_level_stats( $days = 30 ) {

        global $wpdb;

        return $wpdb->get_results( $wpdb->prepare(
            "SELECT risk_level, outcome, COUNT(*) as total
             FROM {$wpdb->prefix}mshield_risk
             WHERE created_at >= DATE_SUB( %s, INTERVAL %d DAY )
             GROUP BY risk_level, outcome",
            gmdate( 'Y-m-d H:i:s' ),
            max( 1, (int) $days )
        ), ARRAY_A );

    }

    /**
     * Log an event.
     *
     * @since   1.0.0
     *
     * @param   string  $ip         Client IP.
     * @param   string  $endpoint   Route or endpoint identifier.
     * @param   string  $action     Action taken (blocked, rate_limited, flagged).
     * @param   string  $reason     Reason for the action.
     * @param   int     $order_id   Order this event belongs to, when known.
     * @param   float   $trust      Trust rating at the time, when known.
     * @param   string  $data       Optional request data. When empty, a compact
     *                              JSON forensics blob (user agent, billing
     *                              email, request URI) is captured automatically.
     */
    public static function log_event( $ip, $endpoint, $action, $reason = '', $data = '', $order_id = 0, $trust = null ) {

        global $wpdb;

        // Auto-capture lightweight forensics when no explicit data was passed.
        // The log table historically stored nothing here, which made spam
        // analysis (email/user-agent correlation) impossible after the fact.
        if( $data === '' ) {
            $data = self::capture_forensics();
        }

        $wpdb->insert(
            $wpdb->prefix . 'mshield_log',
            [
                'ip'           => sanitize_text_field( $ip ),
                'endpoint'     => sanitize_text_field( substr( $endpoint, 0, 255 ) ),
                'action'       => sanitize_text_field( $action ),
                'reason'       => sanitize_text_field( substr( $reason, 0, 255 ) ),
                'request_data' => sanitize_textarea_field( $data ),
                // Recorded so a log row can be tied back to the order it
                // belongs to. Without it, investigating an incident meant
                // matching on IP and timestamp by eye.
                'order_id'     => (int) $order_id,
                'created_at'   => gmdate( 'Y-m-d H:i:s' ),
            ],
            [ '%s', '%s', '%s', '%s', '%s', '%d', '%s' ]
        );

        // Nullable on purpose: a row with no rating stores NULL, not 0, since
        // 0 would read as the worst possible rating rather than "not rated".
        if( $trust !== null ) {
            $wpdb->update(
                $wpdb->prefix . 'mshield_log',
                [ 'trust' => (float) $trust ],
                [ 'id' => (int) $wpdb->insert_id ],
                [ '%f' ],
                [ '%d' ]
            );
        }

    }

    /**
     * Capture a compact forensics blob for a logged event.
     *
     * Records the user agent, billing email (if present in the request) and
     * request URI — the fields most useful for correlating spam-order clusters
     * after the fact. Returns a JSON string capped to fit the TEXT column.
     *
     * @since   1.3.0
     *
     * @return  string  JSON-encoded forensics data (may be empty).
     */
    private static function capture_forensics() {

        $forensics = [];

        if( ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $forensics['ua'] = substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 );
        }

        if( ! empty( $_POST['billing_email'] ) ) {
            $forensics['email'] = sanitize_email( wp_unslash( $_POST['billing_email'] ) );
        }

        if( ! empty( $_SERVER['REQUEST_URI'] ) ) {
            $forensics['uri'] = substr( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), 0, 255 );
        }

        // Capture the logged-in customer's WP user ID so a log row can be
        // whitelisted by user later.
        $uid = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
        if( $uid > 0 ) {
            $forensics['user_id'] = $uid;
        }

        if( empty( $forensics ) ) return '';

        return (string) wp_json_encode( $forensics );

    }

    /**
     * Increment a rate limit counter.
     *
     * Uses INSERT ... ON DUPLICATE KEY UPDATE for atomic operation.
     *
     * @since   1.0.0
     *
     * @param   string  $identifier     Hashed identifier (IP + action).
     * @param   string  $action_type    Type of action being limited.
     * @param   int     $window         Window size in seconds.
     * @return  int     Current count within the window.
     */
    public static function increment_rate_limit( $identifier, $action_type, $window ) {

        global $wpdb;

        $table = $wpdb->prefix . 'mshield_rate_limits';
        $now   = gmdate( 'Y-m-d H:i:s' );
        $end   = gmdate( 'Y-m-d H:i:s', time() + $window );

        // Atomic upsert: insert new record or increment/reset existing.
        $wpdb->query( $wpdb->prepare(
            "INSERT INTO {$table} (identifier, action_type, count, window_start, window_end)
            VALUES (%s, %s, 1, %s, %s)
            ON DUPLICATE KEY UPDATE
                count = IF(window_end < %s, 1, count + 1),
                window_start = IF(window_end < %s, %s, window_start),
                window_end = IF(window_end < %s, %s, window_end)",
            $identifier,
            $action_type,
            $now,
            $end,
            $now,
            $now,
            $now,
            $now,
            $end
        ) );

        // Read back the current count.
        $count = $wpdb->get_var( $wpdb->prepare(
            "SELECT count FROM {$table} WHERE identifier = %s AND action_type = %s",
            $identifier,
            $action_type
        ) );

        return (int) $count;

    }

    /**
     * Check rate limit count without incrementing.
     *
     * @since   1.0.0
     *
     * @param   string  $identifier     Hashed identifier.
     * @param   string  $action_type    Type of action.
     * @return  int     Current count, or 0 if no record/expired.
     */
    public static function check_rate_limit( $identifier, $action_type ) {

        global $wpdb;

        $table = $wpdb->prefix . 'mshield_rate_limits';
        $now   = gmdate( 'Y-m-d H:i:s' );

        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT count, window_end FROM {$table} WHERE identifier = %s AND action_type = %s",
            $identifier,
            $action_type
        ) );

        if( ! $row || strtotime( $row->window_end ) < strtotime( $now ) ) {
            return 0;
        }

        return (int) $row->count;

    }

    /**
     * Get logs with optional filtering.
     *
     * @since   1.0.0
     *
     * @param   array   $args   Query arguments.
     * @return  array
     */
    public static function get_logs( $args = [] ) {

        global $wpdb;

        $defaults = [
            'action'   => '',
            'ip'       => '',
            'order_id' => 0,
            'search'   => '',
            'days'     => 0,
            'per_page' => 50,
            'page'     => 1,
            'orderby'  => 'created_at',
            'order'    => 'DESC',
        ];

        $args  = wp_parse_args( $args, $defaults );
        $table = $wpdb->prefix . 'mshield_log';

        list( $where_sql, $values ) = self::build_log_where( $args );

        // Sanitize orderby.
        $allowed_orderby = [ 'id', 'ip', 'endpoint', 'action', 'order_id', 'trust', 'created_at' ];
        $orderby = in_array( $args['orderby'], $allowed_orderby, true ) ? $args['orderby'] : 'created_at';
        $order   = strtoupper( $args['order'] ) === 'ASC' ? 'ASC' : 'DESC';

        $offset = ( max( 1, (int) $args['page'] ) - 1 ) * (int) $args['per_page'];

        $query = "SELECT * FROM {$table} {$where_sql} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d";
        $values[] = (int) $args['per_page'];
        $values[] = $offset;

        return $wpdb->get_results( $wpdb->prepare( $query, $values ) );

    }

    /**
     * Get total log count with optional filtering.
     *
     * @since   1.0.0
     *
     * @param   array   $args   Filter arguments.
     * @return  int
     */
    public static function get_log_count( $args = [] ) {

        global $wpdb;

        $table = $wpdb->prefix . 'mshield_log';

        list( $where_sql, $values ) = self::build_log_where( $args );

        if( ! empty( $values ) ) {
            return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} {$where_sql}", $values ) );
        }

        return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

    }

    /**
     * Build the shared WHERE clause and prepared values for log queries.
     *
     * @since   1.5.0
     *
     * @param   array   $args   Filter arguments (action, ip, search, days).
     * @return  array   [ string $where_sql, array $values ]
     */
    private static function build_log_where( $args ) {

        global $wpdb;

        $where  = [];
        $values = [];

        if( ! empty( $args['action'] ) ) {
            $where[]  = 'action = %s';
            $values[] = $args['action'];
        }

        if( ! empty( $args['order_id'] ) ) {
            $where[]  = 'order_id = %d';
            $values[] = (int) $args['order_id'];
        }

        if( ! empty( $args['ip'] ) ) {
            $where[]  = 'ip = %s';
            $values[] = $args['ip'];
        }

        if( ! empty( $args['search'] ) ) {
            $like     = '%' . $wpdb->esc_like( $args['search'] ) . '%';
            $where[]  = '( ip LIKE %s OR reason LIKE %s OR request_data LIKE %s )';
            $values[] = $like;
            $values[] = $like;
            $values[] = $like;
        }

        if( ! empty( $args['days'] ) ) {
            $where[]  = 'created_at >= DATE_SUB( %s, INTERVAL %d DAY )';
            $values[] = gmdate( 'Y-m-d H:i:s' );
            $values[] = (int) $args['days'];
        }

        $where_sql = ! empty( $where ) ? 'WHERE ' . implode( ' AND ', $where ) : '';

        return [ $where_sql, $values ];

    }

    /**
     * Delete specific log entries by ID.
     *
     * @since   1.5.0
     *
     * @param   int[]   $ids    Log row IDs.
     * @return  int     Rows deleted.
     */
    public static function delete_logs_by_ids( $ids ) {

        global $wpdb;

        $ids = array_filter( array_map( 'absint', (array) $ids ) );
        if( empty( $ids ) ) return 0;

        $table        = $wpdb->prefix . 'mshield_log';
        $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );

        return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id IN ({$placeholders})", $ids ) );

    }

    /**
     * Get per-day event counts for the last N days, split by action.
     *
     * @since   1.5.0
     *
     * @param   int     $days   Number of days (including today).
     * @return  array   Ordered oldest-first: [ [ 'date' => 'Y-m-d', 'blocked' => int, 'rate_limited' => int, 'flagged' => int, 'total' => int ], ... ]
     */
    public static function get_daily_stats( $days = 7 ) {

        global $wpdb;

        $days  = max( 1, (int) $days );
        $table = $wpdb->prefix . 'mshield_log';

        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT DATE(created_at) as d, action, COUNT(*) as total
             FROM {$table}
             WHERE created_at >= DATE_SUB( %s, INTERVAL %d DAY )
             GROUP BY DATE(created_at), action",
            gmdate( 'Y-m-d H:i:s' ),
            $days - 1
        ) );

        // Seed each day with zeros so the chart always has a full series.
        $series = [];
        for( $i = $days - 1; $i >= 0; $i-- ) {
            $date = gmdate( 'Y-m-d', time() - ( $i * DAY_IN_SECONDS ) );
            $series[ $date ] = [ 'date' => $date, 'blocked' => 0, 'rate_limited' => 0, 'flagged' => 0, 'total' => 0 ];
        }

        foreach( $rows as $row ) {
            if( ! isset( $series[ $row->d ] ) ) continue;
            $count = (int) $row->total;
            if( isset( $series[ $row->d ][ $row->action ] ) ) {
                $series[ $row->d ][ $row->action ] = $count;
            }
            $series[ $row->d ]['total'] += $count;
        }

        return array_values( $series );

    }

    /**
     * Get stats for a given time period.
     *
     * @since   1.0.0
     *
     * @param   string  $period     'day', 'week', 'month'.
     * @return  array
     */
    public static function get_stats( $period = 'day' ) {

        global $wpdb;

        $table = $wpdb->prefix . 'mshield_log';

        switch( $period ) {
            case 'week':
                $interval = '7 DAY';
                break;
            case 'month':
                $interval = '30 DAY';
                break;
            default:
                $interval = '1 DAY';
                break;
        }

        $results = $wpdb->get_results( $wpdb->prepare(
            "SELECT action, COUNT(*) as total FROM {$table} WHERE created_at >= DATE_SUB(%s, INTERVAL {$interval}) GROUP BY action",
            gmdate( 'Y-m-d H:i:s' )
        ) );

        $stats = [
            'blocked'      => 0,
            'rate_limited' => 0,
            'flagged'      => 0,
            'total'        => 0,
        ];

        foreach( $results as $row ) {
            $stats[ $row->action ] = (int) $row->total;
            $stats['total'] += (int) $row->total;
        }

        return $stats;

    }

    /**
     * Get top blocked IPs.
     *
     * @since   1.0.0
     *
     * @param   int     $limit  Number of IPs to return.
     * @param   string  $period 'day', 'week', 'month'.
     * @return  array
     */
    public static function get_top_blocked_ips( $limit = 10, $period = 'week' ) {

        global $wpdb;

        $table = $wpdb->prefix . 'mshield_log';

        switch( $period ) {
            case 'week':
                $interval = '7 DAY';
                break;
            case 'month':
                $interval = '30 DAY';
                break;
            default:
                $interval = '1 DAY';
                break;
        }

        return $wpdb->get_results( $wpdb->prepare(
            "SELECT ip, COUNT(*) as total FROM {$table} WHERE action = 'blocked' AND created_at >= DATE_SUB(%s, INTERVAL {$interval}) GROUP BY ip ORDER BY total DESC LIMIT %d",
            gmdate( 'Y-m-d H:i:s' ),
            $limit
        ) );

    }

    /**
     * Get per-hour event counts for the last N hours, split by action.
     *
     * @since   1.6.0
     *
     * @param   int     $hours  Number of hours (including the current one).
     * @return  array   Ordered oldest-first, each: [ 'label' => 'H:00', 'blocked' => int, 'rate_limited' => int, 'flagged' => int, 'total' => int ]
     */
    public static function get_hourly_stats( $hours = 24 ) {

        global $wpdb;

        $hours = max( 1, (int) $hours );
        $table = $wpdb->prefix . 'mshield_log';

        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H') as h, action, COUNT(*) as total
             FROM {$table}
             WHERE created_at >= DATE_SUB( %s, INTERVAL %d HOUR )
             GROUP BY DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H'), action",
            gmdate( 'Y-m-d H:i:s' ),
            $hours - 1
        ) );

        $series = [];
        for( $i = $hours - 1; $i >= 0; $i-- ) {
            $ts  = time() - ( $i * HOUR_IN_SECONDS );
            $key = gmdate( 'Y-m-d H', $ts );
            $series[ $key ] = [ 'label' => gmdate( 'H:00', $ts ), 'blocked' => 0, 'rate_limited' => 0, 'flagged' => 0, 'total' => 0 ];
        }

        foreach( $rows as $row ) {
            if( ! isset( $series[ $row->h ] ) ) continue;
            $count = (int) $row->total;
            if( isset( $series[ $row->h ][ $row->action ] ) ) {
                $series[ $row->h ][ $row->action ] = $count;
            }
            $series[ $row->h ]['total'] += $count;
        }

        return array_values( $series );

    }

    /**
     * Get cached geolocation data for one IP.
     *
     * @since   1.6.0
     *
     * @param   string  $ip     IP address.
     * @return  array|null       Row as array, or null if not cached.
     */
    public static function get_ip_data( $ip ) {

        global $wpdb;

        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}mshield_ip_data WHERE ip = %s",
            $ip
        ), ARRAY_A );

        return $row ?: null;

    }

    /**
     * Get cached geolocation data for a set of IPs, keyed by IP.
     *
     * @since   1.6.0
     *
     * @param   string[]    $ips    IP addresses.
     * @return  array       ip => row (array).
     */
    public static function get_ip_data_map( $ips ) {

        global $wpdb;

        $ips = array_values( array_unique( array_filter( (array) $ips ) ) );
        if( empty( $ips ) ) return [];

        $placeholders = implode( ',', array_fill( 0, count( $ips ), '%s' ) );
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}mshield_ip_data WHERE ip IN ({$placeholders})",
            $ips
        ), ARRAY_A );

        $map = [];
        foreach( $rows as $row ) {
            $map[ $row['ip'] ] = $row;
        }

        return $map;

    }

    /**
     * Store (upsert) geolocation data for an IP.
     *
     * @since   1.6.0
     *
     * @param   string  $ip     IP address.
     * @param   array   $data   Keys: status, city, region, country, org.
     */
    public static function save_ip_data( $ip, $data ) {

        global $wpdb;

        $wpdb->replace(
            $wpdb->prefix . 'mshield_ip_data',
            [
                'ip'         => sanitize_text_field( $ip ),
                'status'     => substr( sanitize_text_field( $data['status'] ?? '' ), 0, 20 ),
                'city'       => substr( sanitize_text_field( $data['city'] ?? '' ), 0, 100 ),
                'region'     => substr( sanitize_text_field( $data['region'] ?? '' ), 0, 100 ),
                'country'    => substr( sanitize_text_field( $data['country'] ?? '' ), 0, 10 ),
                'org'        => substr( sanitize_text_field( $data['org'] ?? '' ), 0, 191 ),
                'asname'     => substr( sanitize_text_field( $data['asname'] ?? '' ), 0, 191 ),
                // -1 means "the provider did not report this", which is
                // distinct from 0 ("reported, and it is not a proxy").
                'proxy'      => isset( $data['proxy'] ) ? (int) $data['proxy'] : -1,
                'hosting'    => isset( $data['hosting'] ) ? (int) $data['hosting'] : -1,
                'mobile'     => isset( $data['mobile'] ) ? (int) $data['mobile'] : -1,
                'fetched_at' => gmdate( 'Y-m-d H:i:s' ),
            ],
            [ '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%s' ]
        );

    }

    /**
     * Cleanup expired data.
     *
     * @since   1.0.0
     */
    public static function cleanup() {

        global $wpdb;

        $retention_days = (int) get_option( 'mshield_log_retention_days', 30 );
        if( $retention_days < 1 ) $retention_days = 30;

        $now = gmdate( 'Y-m-d H:i:s' );

        // Clean old logs in batches to avoid table locks.
        do {
            $deleted = $wpdb->query( $wpdb->prepare(
                "DELETE FROM {$wpdb->prefix}mshield_log WHERE created_at < DATE_SUB(%s, INTERVAL %d DAY) LIMIT 5000",
                $now,
                $retention_days
            ) );
        } while( $deleted >= 5000 );

        // Clean expired rate limits.
        $wpdb->query( $wpdb->prepare(
            "DELETE FROM {$wpdb->prefix}mshield_rate_limits WHERE window_end < %s",
            $now
        ) );

        // Drop cached IP data for IPs no longer present in the log.
        $wpdb->query(
            "DELETE d FROM {$wpdb->prefix}mshield_ip_data d
             LEFT JOIN {$wpdb->prefix}mshield_log l ON l.ip = d.ip
             WHERE l.ip IS NULL"
        );

    }

}
