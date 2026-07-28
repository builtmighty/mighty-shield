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
     * Create tables.
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
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ip (ip),
            INDEX idx_action (action),
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

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql_log );
        dbDelta( $sql_rate );

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
     * @param   string  $data       Optional request data. When empty, a compact
     *                              JSON forensics blob (user agent, billing
     *                              email, request URI) is captured automatically.
     */
    public static function log_event( $ip, $endpoint, $action, $reason = '', $data = '' ) {

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
                'created_at'   => gmdate( 'Y-m-d H:i:s' ),
            ],
            [ '%s', '%s', '%s', '%s', '%s', '%s' ]
        );

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
        $allowed_orderby = [ 'id', 'ip', 'endpoint', 'action', 'created_at' ];
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

    }

}
