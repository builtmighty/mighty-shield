<?php
/**
 * Logs view.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\db;
use MightyShield\Includes\settings;

// Filters.
$filter_action = isset( $_GET['filter_action'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_action'] ) ) : '';
$filter_ip     = isset( $_GET['filter_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_ip'] ) ) : '';
$search        = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
$range         = isset( $_GET['range'] ) ? (int) $_GET['range'] : 0;
$paged         = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
$per_page      = 50;

$args = [
    'action'   => $filter_action,
    'ip'       => $filter_ip,
    'search'   => $search,
    'days'     => $range,
    'per_page' => $per_page,
    'page'     => $paged,
];

$logs        = db::get_logs( $args );
$total       = db::get_log_count( $args );
$total_pages = max( 1, (int) ceil( $total / $per_page ) );

$retention = (int) settings::get( 'mshield_log_retention_days' );

$pill_class = [
    'blocked'      => 'is-blocked',
    'rate_limited' => 'is-rate',
    'flagged'      => 'is-flag',
    'exempt'       => 'is-exempt',
];
$action_labels = [
    'blocked'      => __( 'Blocked', 'mighty-shield' ),
    'rate_limited' => __( 'Rate-limited', 'mighty-shield' ),
    'flagged'      => __( 'Flagged', 'mighty-shield' ),
    'exempt'       => __( 'Exempt', 'mighty-shield' ),
    'degraded'     => __( 'Degraded', 'mighty-shield' ),
];

$export_url = wp_nonce_url( admin_url( 'admin.php?page=mighty-shield&tab=logs&mshield_export_logs=1' ), 'mshield_export_logs' );
?>

<div class="mshield-stack">

    <!-- Retention banner -->
    <div class="mshield-banner">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="var(--brand)" stroke-width="2" style="margin-top:1px;flex:none"><circle cx="12" cy="12" r="9"></circle><path d="M12 11v5M12 8h.01"></path></svg>
        <div>
            <?php printf( esc_html__( 'Log entries are retained for %d days.', 'mighty-shield' ), $retention ); ?>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=firewall' ) ); ?>" style="font-weight:600"><?php esc_html_e( 'Change retention', 'mighty-shield' ); ?></a>
            <?php esc_html_e( 'or', 'mighty-shield' ); ?>
            <a href="<?php echo esc_url( $export_url ); ?>" style="font-weight:600"><?php esc_html_e( 'export as CSV', 'mighty-shield' ); ?></a>.
        </div>
    </div>

    <!-- Filters -->
    <form method="get" class="mshield-filters">
        <input type="hidden" name="page" value="mighty-shield" />
        <input type="hidden" name="tab" value="logs" />
        <?php if( $filter_ip ) : ?><input type="hidden" name="filter_ip" value="<?php echo esc_attr( $filter_ip ); ?>" /><?php endif; ?>

        <div class="mshield-search">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--fg-3)" stroke-width="2"><circle cx="11" cy="11" r="7"></circle><path d="M20 20l-4-4"></path></svg>
            <input type="text" name="s" value="<?php echo esc_attr( $search ); ?>" class="mshield-input" placeholder="<?php esc_attr_e( 'Search IP, email, or reason', 'mighty-shield' ); ?>" />
        </div>

        <select name="range" class="mshield-select">
            <option value="0" <?php selected( $range, 0 ); ?>><?php esc_html_e( 'All time', 'mighty-shield' ); ?></option>
            <option value="1" <?php selected( $range, 1 ); ?>><?php esc_html_e( 'Last 24 hours', 'mighty-shield' ); ?></option>
            <option value="7" <?php selected( $range, 7 ); ?>><?php esc_html_e( 'Last 7 days', 'mighty-shield' ); ?></option>
            <option value="30" <?php selected( $range, 30 ); ?>><?php esc_html_e( 'Last 30 days', 'mighty-shield' ); ?></option>
        </select>

        <select name="filter_action" class="mshield-select">
            <option value=""><?php esc_html_e( 'All actions', 'mighty-shield' ); ?></option>
            <option value="blocked" <?php selected( $filter_action, 'blocked' ); ?>><?php esc_html_e( 'Blocked', 'mighty-shield' ); ?></option>
            <option value="rate_limited" <?php selected( $filter_action, 'rate_limited' ); ?>><?php esc_html_e( 'Rate-limited', 'mighty-shield' ); ?></option>
            <option value="flagged" <?php selected( $filter_action, 'flagged' ); ?>><?php esc_html_e( 'Flagged', 'mighty-shield' ); ?></option>
            <option value="exempt" <?php selected( $filter_action, 'exempt' ); ?>><?php esc_html_e( 'Exempt (whitelisted)', 'mighty-shield' ); ?></option>
        </select>

        <button type="submit" class="mshield-btn"><?php esc_html_e( 'Filter', 'mighty-shield' ); ?></button>
        <?php if( $filter_action || $filter_ip || $search || $range ) : ?>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=logs' ) ); ?>" class="mshield-btn"><?php esc_html_e( 'Clear', 'mighty-shield' ); ?></a>
        <?php endif; ?>
        <span class="mshield-spacer"></span>
        <a href="<?php echo esc_url( $export_url ); ?>" class="mshield-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12M7 10l5 5 5-5M4 20h16"></path></svg><?php esc_html_e( 'Export', 'mighty-shield' ); ?>
        </a>
    </form>

    <?php if( empty( $logs ) ) : ?>
        <div class="mshield-card"><p style="margin:0;color:var(--fg-2)"><?php esc_html_e( 'No log entries found.', 'mighty-shield' ); ?></p></div>
    <?php else : ?>

    <!-- Bulk form + table -->
    <form method="post">
        <?php wp_nonce_field( 'mshield_logs_bulk_action' ); ?>
        <div class="mshield-card is-flush mshield-loglist">

            <div class="mshield-bulkbar">
                <span id="mshield-sel-count" style="font-size:12.5px;font-weight:600;color:var(--fg-2)">0 <?php esc_html_e( 'selected', 'mighty-shield' ); ?></span>
                <select name="mshield_bulk_action" class="mshield-select" style="padding:6px 10px;font-size:12.5px">
                    <option value=""><?php esc_html_e( 'Bulk actions', 'mighty-shield' ); ?></option>
                    <option value="block_ip"><?php esc_html_e( 'Block IP permanently', 'mighty-shield' ); ?></option>
                    <option value="whitelist_ip"><?php esc_html_e( 'Add IP to whitelist', 'mighty-shield' ); ?></option>
                    <option value="delete"><?php esc_html_e( 'Delete entries', 'mighty-shield' ); ?></option>
                </select>
                <button type="submit" name="mshield_logs_bulk" value="1" class="mshield-btn is-small"><?php esc_html_e( 'Apply', 'mighty-shield' ); ?></button>
                <span class="mshield-spacer"></span>
                <span class="mshield-mono" style="font-size:12.5px;color:var(--fg-3)"><?php printf( esc_html__( '%s entries', 'mighty-shield' ), esc_html( number_format_i18n( $total ) ) ); ?></span>
            </div>

            <div class="mshield-logrow is-head">
                <input type="checkbox" id="mshield-check-all" />
                <span><?php esc_html_e( 'Time', 'mighty-shield' ); ?></span>
                <span><?php esc_html_e( 'IP address', 'mighty-shield' ); ?></span>
                <span><?php esc_html_e( 'Endpoint', 'mighty-shield' ); ?></span>
                <span><?php esc_html_e( 'Reason', 'mighty-shield' ); ?></span>
                <span><?php esc_html_e( 'Action', 'mighty-shield' ); ?></span>
                <span></span>
            </div>

            <?php foreach( $logs as $log ) :
                $details = ! empty( $log->request_data ) ? json_decode( $log->request_data, true ) : [];
                if( ! is_array( $details ) ) $details = [];

                if( ! empty( $details['user_id'] ) ) {
                    $u = get_userdata( (int) $details['user_id'] );
                    if( $u ) $details['user_label'] = $u->user_login;
                }

                $wl_url = wp_nonce_url( admin_url( 'admin.php?page=mighty-shield&mshield_whitelist_ip=' . urlencode( $log->ip ) ), 'mshield_whitelist_ip' );
                $bl_url = wp_nonce_url( admin_url( 'admin.php?page=mighty-shield&mshield_block_ip=' . urlencode( $log->ip ) ), 'mshield_block_ip' );

                $event = [
                    'time'        => date_i18n( 'M j, H:i:s', strtotime( $log->created_at ) ),
                    'ip'          => $log->ip,
                    'action'      => $log->action,
                    'actionLabel' => isset( $action_labels[ $log->action ] ) ? $action_labels[ $log->action ] : $log->action,
                    'endpoint'    => $log->endpoint,
                    'reason'      => $log->reason,
                    'details'     => $details,
                    'wlUrl'       => $wl_url,
                    'blockUrl'    => $bl_url,
                ];
                $pc = isset( $pill_class[ $log->action ] ) ? $pill_class[ $log->action ] : '';
                $al = isset( $action_labels[ $log->action ] ) ? $action_labels[ $log->action ] : $log->action;
            ?>
            <div class="mshield-logrow is-clickable" data-event="<?php echo esc_attr( wp_json_encode( $event ) ); ?>">
                <input type="checkbox" class="mshield-logcheck" name="log_ids[]" value="<?php echo esc_attr( (int) $log->id ); ?>" />
                <span class="mshield-mono" style="font-size:12.5px;color:var(--fg-2)"><?php echo esc_html( date_i18n( 'H:i:s', strtotime( $log->created_at ) ) ); ?></span>
                <span class="mshield-mono" style="font-size:12.5px"><?php echo esc_html( $log->ip ); ?></span>
                <span class="mshield-mono" style="font-size:12px;color:var(--fg-2)"><?php echo esc_html( $log->endpoint ); ?></span>
                <span><?php echo esc_html( $log->reason ); ?></span>
                <span class="mshield-pill mshield-tag-pill <?php echo esc_attr( $pc ); ?>" style="justify-self:start"><?php echo esc_html( $al ); ?></span>
                <span class="details-link"><?php esc_html_e( 'Details', 'mighty-shield' ); ?></span>
            </div>
            <?php endforeach; ?>

            <div class="mshield-logfoot">
                <span><?php printf( esc_html__( 'Showing %1$d of %2$s', 'mighty-shield' ), count( $logs ), esc_html( number_format_i18n( $total ) ) ); ?></span>
                <span class="mshield-spacer"></span>
                <?php
                $base_url = admin_url( 'admin.php?page=mighty-shield&tab=logs' );
                if( $filter_action ) $base_url .= '&filter_action=' . urlencode( $filter_action );
                if( $filter_ip )     $base_url .= '&filter_ip=' . urlencode( $filter_ip );
                if( $search )        $base_url .= '&s=' . urlencode( $search );
                if( $range )         $base_url .= '&range=' . (int) $range;
                if( $paged > 1 ) : ?>
                    <a class="mshield-btn is-small" href="<?php echo esc_url( $base_url . '&paged=' . ( $paged - 1 ) ); ?>"><?php esc_html_e( 'Previous', 'mighty-shield' ); ?></a>
                <?php endif; ?>
                <span class="mshield-mono"><?php printf( esc_html__( '%1$d / %2$d', 'mighty-shield' ), $paged, $total_pages ); ?></span>
                <?php if( $paged < $total_pages ) : ?>
                    <a class="mshield-btn is-small" href="<?php echo esc_url( $base_url . '&paged=' . ( $paged + 1 ) ); ?>"><?php esc_html_e( 'Next', 'mighty-shield' ); ?></a>
                <?php endif; ?>
            </div>
        </div>
    </form>

    <?php endif; ?>

    <!-- Maintenance -->
    <div class="mshield-card">
        <div class="mshield-card-title" style="margin-bottom:6px"><?php esc_html_e( 'Maintenance', 'mighty-shield' ); ?></div>
        <p style="margin:0 0 12px;color:var(--fg-2);font-size:13px"><?php esc_html_e( 'Clear all log entries. This action cannot be undone.', 'mighty-shield' ); ?></p>
        <form method="post">
            <?php wp_nonce_field( 'mshield_clear_logs_action' ); ?>
            <button type="submit" name="mshield_clear_logs" value="1" class="mshield-btn is-danger" onclick="return confirm('<?php echo esc_js( __( 'Are you sure? This will delete all log entries.', 'mighty-shield' ) ); ?>');"><?php esc_html_e( 'Clear All Logs', 'mighty-shield' ); ?></button>
        </form>
    </div>

</div>
