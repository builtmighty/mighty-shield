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
//
// Read to decide what to display, never to act on, and the screen is
// already behind manage_woocommerce. A nonce on a filter link would mean
// a bookmarked or shared log view stopped working.
// phpcs:disable WordPress.Security.NonceVerification.Recommended
$filter_action = isset( $_GET['filter_action'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_action'] ) ) : '';
$filter_ip     = isset( $_GET['filter_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_ip'] ) ) : '';
$search        = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
$range         = isset( $_GET['range'] ) ? (int) $_GET['range'] : 0;
$paged         = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
$per_page      = 50;
// phpcs:enable WordPress.Security.NonceVerification.Recommended

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

// Cached IP data for the IPs on this page (one query), for the detail drawer.
$page_ips    = array_map( function( $l ) { return $l->ip; }, $logs );
$ip_data_map = db::get_ip_data_map( $page_ips );

$retention = (int) settings::get( 'mshield_log_retention_days' );

$pill_class = [
    'blocked'      => 'is-blocked',
    'rate_limited' => 'is-rate',
    'flagged'      => 'is-flag',
    'exempt'       => 'is-exempt',
    // Not a verdict on the request -- a layer stood down. Quiet on purpose,
    // rather than falling through to an unstyled pill.
    'degraded'     => 'is-muted',
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
            <?php printf( esc_html__( 'Log entries are retained for %d days.', 'mighty-shield' ), (int) $retention ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- format is escaped and %d forces an integer ?>
            <a href="#mshield-log-settings" style="font-weight:600"><?php esc_html_e( 'Change retention', 'mighty-shield' ); ?></a>
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
            <option value="exempt" <?php selected( $filter_action, 'exempt' ); ?>><?php esc_html_e( 'Exempt (allowlisted)', 'mighty-shield' ); ?></option>
            <?php /* 'degraded' is how MightyShield records its own problems -- a
                     service that stopped answering, a challenge that is switched
                     on but never reaching the form. It was the one class of event
                     with a colour and a label but no way to filter for it, which
                     made the plugin's own diagnostics the hardest thing to find
                     in its own log. */ ?>
            <option value="degraded" <?php selected( $filter_action, 'degraded' ); ?>><?php esc_html_e( 'Needs attention', 'mighty-shield' ); ?></option>
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
                    <option value="whitelist_ip"><?php esc_html_e( 'Add IP to allowlist', 'mighty-shield' ); ?></option>
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

                $ip_info = null;
                if( isset( $ip_data_map[ $log->ip ] ) ) {
                    $d = $ip_data_map[ $log->ip ];
                    $ip_info = [
                        'status'  => $d['status'],
                        'city'    => $d['city'],
                        'region'  => $d['region'],
                        'country' => $d['country'],
                        'org'     => $d['org'],
                    ];
                }

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
                    'ipData'      => $ip_info,
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
                <span class="mshield-pill <?php echo esc_attr( $pc ); ?>" style="justify-self:start"><span class="dot"></span><?php echo esc_html( $al ); ?></span>
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
                <span class="mshield-mono"><?php printf( esc_html__( '%1$d / %2$d', 'mighty-shield' ), (int) $paged, (int) $total_pages ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- format is escaped and %d forces an integer ?></span>
                <?php if( $paged < $total_pages ) : ?>
                    <a class="mshield-btn is-small" href="<?php echo esc_url( $base_url . '&paged=' . ( $paged + 1 ) ); ?>"><?php esc_html_e( 'Next', 'mighty-shield' ); ?></a>
                <?php endif; ?>
            </div>
        </div>
    </form>

    <?php endif; ?>

    <!-- Rate past orders -->
    <?php
    $mshield_bf     = \MightyShield\Includes\backfill::state();
    $mshield_bf_run = 'running' === $mshield_bf['status'];
    ?>
    <div class="mshield-card">
        <div class="mshield-card-title" style="margin-bottom:6px"><?php esc_html_e( 'Rate past orders', 'mighty-shield' ); ?></div>

        <?php if( $mshield_bf_run ) : ?>

            <p style="margin:0 0 12px;color:var(--fg-2);font-size:13px">
                <?php
                printf(
                    /* translators: 1: orders rated so far, 2: total orders. */
                    esc_html__( 'Rating your past orders: %1$s of %2$s done. This continues in the background, so you can leave this page.', 'mighty-shield' ),
                    esc_html( number_format_i18n( (int) $mshield_bf['done'] ) ),
                    esc_html( number_format_i18n( (int) $mshield_bf['total'] ) )
                );
                ?>
            </p>
            <form method="post">
                <?php wp_nonce_field( 'mshield_backfill_action' ); ?>
                <button type="submit" name="mshield_backfill_cancel" value="1" class="mshield-btn"><?php esc_html_e( 'Stop', 'mighty-shield' ); ?></button>
            </form>

        <?php else : ?>

            <p style="margin:0 0 12px;color:var(--fg-2);font-size:13px">
                <?php esc_html_e( 'MightyShield only knows the customers it has seen since you installed it, so on a new install nobody has a history and nobody earns trust. Rating your past orders fills that in, and the next real order is judged against what your store already knows instead of against nothing.', 'mighty-shield' ); ?>
            </p>
            <p style="margin:0 0 12px;color:var(--fg-2);font-size:13px">
                <?php esc_html_e( 'Nothing is done to any order — no holds, no cancellations, no emails. Ratings from past orders are partial, because the bot, timing and device checks measure the checkout as it happens and that moment has gone.', 'mighty-shield' ); ?>
            </p>

            <?php if( 'complete' === $mshield_bf['status'] || 'cancelled' === $mshield_bf['status'] ) : ?>
                <p style="margin:0 0 12px;color:var(--fg-2);font-size:13px">
                    <strong>
                        <?php
                        printf(
                            /* translators: 1: orders rated, 2: orders skipped. */
                            esc_html__( 'Last run: %1$s rated, %2$s skipped.', 'mighty-shield' ),
                            esc_html( number_format_i18n( (int) $mshield_bf['done'] ) ),
                            esc_html( number_format_i18n( (int) $mshield_bf['failed'] ) )
                        );
                        ?>
                    </strong>
                </p>
            <?php endif; ?>

            <form method="post">
                <?php wp_nonce_field( 'mshield_backfill_action' ); ?>
                <label style="font-size:13px">
                    <?php esc_html_e( 'How far back', 'mighty-shield' ); ?>
                    <select name="mshield_backfill_days">
                        <option value="90"><?php esc_html_e( '90 days', 'mighty-shield' ); ?></option>
                        <option value="365" selected><?php esc_html_e( '1 year', 'mighty-shield' ); ?></option>
                        <option value="1095"><?php esc_html_e( '3 years', 'mighty-shield' ); ?></option>
                        <option value="0"><?php esc_html_e( 'Everything', 'mighty-shield' ); ?></option>
                    </select>
                </label>
                <button type="submit" name="mshield_backfill_start" value="1" class="mshield-btn"><?php esc_html_e( 'Rate past orders', 'mighty-shield' ); ?></button>
            </form>

        <?php endif; ?>
    </div>

    <!-- Chargeback import -->
    <?php $mshield_dis = get_transient( 'mshield_disputes_preview' ); ?>
    <div class="mshield-card">
        <div class="mshield-card-title" style="margin-bottom:6px"><?php esc_html_e( 'Import chargebacks', 'mighty-shield' ); ?></div>

        <?php if( is_array( $mshield_dis ) ) : ?>

            <?php if( (int) $mshield_dis['matched'] === 0 ) : ?>

                <p style="margin:0 0 12px;color:var(--fg-2);font-size:13px">
                    <?php esc_html_e( 'None of the columns in that file matched an order. Dispute reports identify a payment the way your processor knows it, so the file needs to contain either the transaction reference stored on the order or the order number itself.', 'mighty-shield' ); ?>
                </p>

            <?php else : ?>

                <p style="margin:0 0 12px;font-size:13px">
                    <strong>
                        <?php
                        printf(
                            /* translators: 1: column name, 2: rows matched, 3: rows sampled. */
                            esc_html__( 'The column "%1$s" matched %2$s of the first %3$s rows.', 'mighty-shield' ),
                            esc_html( $mshield_dis['label'] ),
                            esc_html( number_format_i18n( (int) $mshield_dis['matched'] ) ),
                            esc_html( number_format_i18n( (int) $mshield_dis['sampled'] ) )
                        );
                        ?>
                    </strong>
                </p>

                <?php if( ! empty( $mshield_dis['examples'] ) ) : ?>
                    <table class="mshield-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'Value in the file', 'mighty-shield' ); ?></th>
                                <th style="width:120px;"><?php esc_html_e( 'Order', 'mighty-shield' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach( $mshield_dis['examples'] as $mshield_eg ) : ?>
                                <tr>
                                    <td><code><?php echo esc_html( $mshield_eg['value'] ); ?></code></td>
                                    <td>#<?php echo esc_html( (int) $mshield_eg['order'] ); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>

                <p class="mshield-hint" style="margin-top:10px">
                    <?php
                    printf(
                        /* translators: %s: total rows in the file. */
                        esc_html__( 'Applying will record a chargeback against every order the whole file matches, %s rows in all. Orders MightyShield already knows were charged back are left alone.', 'mighty-shield' ),
                        esc_html( number_format_i18n( (int) $mshield_dis['total'] ) )
                    );
                    ?>
                </p>

            <?php endif; ?>

            <form method="post">
                <?php wp_nonce_field( 'mshield_disputes_action' ); ?>
                <?php if( (int) $mshield_dis['matched'] > 0 ) : ?>
                    <button type="submit" name="mshield_disputes_apply" value="1" class="mshield-btn"><?php esc_html_e( 'Record these chargebacks', 'mighty-shield' ); ?></button>
                <?php endif; ?>
                <button type="submit" name="mshield_disputes_cancel" value="1" class="mshield-btn"><?php esc_html_e( 'Discard the file', 'mighty-shield' ); ?></button>
            </form>

        <?php else : ?>

            <p style="margin:0 0 12px;color:var(--fg-2);font-size:13px">
                <?php esc_html_e( 'MightyShield learns from chargebacks automatically on Stripe, which tells it when one happens. Every other processor disputes into a dashboard it cannot see — so on those, the strongest signal there is never reaches the scoring.', 'mighty-shield' ); ?>
            </p>
            <p style="margin:0 0 12px;color:var(--fg-2);font-size:13px">
                <?php esc_html_e( 'Export your dispute report as CSV and upload it here. Nothing is recorded until you have seen which column it matched on and said so. The file is read once and deleted.', 'mighty-shield' ); ?>
            </p>

            <form method="post" enctype="multipart/form-data">
                <?php wp_nonce_field( 'mshield_disputes_action' ); ?>
                <input type="file" name="mshield_disputes_file" accept=".csv,text/csv,text/plain" />
                <button type="submit" name="mshield_disputes_preview" value="1" class="mshield-btn"><?php esc_html_e( 'Look at the file', 'mighty-shield' ); ?></button>
            </form>

        <?php endif; ?>
    </div>

    <!-- Maintenance -->
    <div class="mshield-card">
        <div class="mshield-card-title" style="margin-bottom:6px"><?php esc_html_e( 'Maintenance', 'mighty-shield' ); ?></div>
        <p style="margin:0 0 12px;color:var(--fg-2);font-size:13px"><?php esc_html_e( 'Clear all log entries. This action cannot be undone.', 'mighty-shield' ); ?></p>
        <form method="post">
            <?php wp_nonce_field( 'mshield_clear_logs_action' ); ?>
            <button type="submit" name="mshield_clear_logs" value="1" class="mshield-btn is-danger" onclick="return confirm('<?php echo esc_js( __( 'Are you sure? This will delete all log entries.', 'mighty-shield' ) ); ?>');"><?php esc_html_e( 'Clear All Logs', 'mighty-shield' ); ?></button>
        </form>
    </div>

    <!-- Log Settings -->
    <?php /* Moved here from the Access tab in 1.9.3, next to the logs it governs.
             This is the only Settings API form on the page, so it carries its own
             group -- registering an option to a group with no field submitting it
             makes options.php write null over it on every save of that group. */ ?>
    <div class="mshield-card" id="mshield-log-settings">
        <div class="mshield-card-title" style="margin-bottom:6px"><?php esc_html_e( 'Log Settings', 'mighty-shield' ); ?></div>
        <form method="post" action="options.php">
            <?php settings_fields( 'mshield_logs' ); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><?php esc_html_e( 'Log Retention', 'mighty-shield' ); ?></th>
                    <td>
                        <input type="number" name="mshield_log_retention_days" value="<?php echo esc_attr( settings::get( 'mshield_log_retention_days' ) ); ?>" min="1" max="365" class="small-text" />
                        <?php esc_html_e( 'days', 'mighty-shield' ); ?>
                        <p class="description"><?php esc_html_e( 'Entries older than this are cleaned up daily.', 'mighty-shield' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e( 'Customer History', 'mighty-shield' ); ?></th>
                    <td>
                        <input type="number" name="mshield_entity_retention_days" value="<?php echo esc_attr( settings::get( 'mshield_entity_retention_days' ) ); ?>" min="0" max="3650" class="small-text" />
                        <?php esc_html_e( 'days', 'mighty-shield' ); ?>
                        <p class="description">
                            <?php esc_html_e( 'How long MightyShield remembers the customers, addresses, cards and networks behind past orders. This is the memory the scoring reads, so it is kept far longer than the log.', 'mighty-shield' ); ?>
                        </p>
                        <p class="description">
                            <?php esc_html_e( 'A chargeback, a refund, a fraud verdict or a refused checkout is never forgotten while the record is still in use — only quiet, clean records that nothing links to any more are cleared out. Set to 0 to keep everything.', 'mighty-shield' ); ?>
                        </p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>

</div>
