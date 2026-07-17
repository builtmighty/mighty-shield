<?php
/**
 * Logs view.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\db;

// Get filters.
$filter_action = isset( $_GET['filter_action'] ) ? sanitize_text_field( $_GET['filter_action'] ) : '';
$filter_ip     = isset( $_GET['filter_ip'] ) ? sanitize_text_field( $_GET['filter_ip'] ) : '';
$paged         = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
$per_page      = 50;

$args = [
    'action'   => $filter_action,
    'ip'       => $filter_ip,
    'per_page' => $per_page,
    'page'     => $paged,
];

$logs       = db::get_logs( $args );
$total      = db::get_log_count( $args );
$total_pages = ceil( $total / $per_page );
?>

<div class="mshield-section">
    <h2><?php esc_html_e( 'Event Logs', 'mighty-shield' ); ?></h2>

    <!-- Filters -->
    <form method="get" style="margin-bottom: 15px;">
        <input type="hidden" name="page" value="mighty-shield" />
        <input type="hidden" name="tab" value="logs" />

        <label><?php esc_html_e( 'Action:', 'mighty-shield' ); ?>
            <select name="filter_action">
                <option value=""><?php esc_html_e( 'All', 'mighty-shield' ); ?></option>
                <option value="blocked" <?php selected( $filter_action, 'blocked' ); ?>><?php esc_html_e( 'Blocked', 'mighty-shield' ); ?></option>
                <option value="rate_limited" <?php selected( $filter_action, 'rate_limited' ); ?>><?php esc_html_e( 'Rate Limited', 'mighty-shield' ); ?></option>
                <option value="flagged" <?php selected( $filter_action, 'flagged' ); ?>><?php esc_html_e( 'Flagged', 'mighty-shield' ); ?></option>
            </select>
        </label>

        <label style="margin-left: 10px;"><?php esc_html_e( 'IP:', 'mighty-shield' ); ?>
            <input type="text" name="filter_ip" value="<?php echo esc_attr( $filter_ip ); ?>" placeholder="<?php esc_attr_e( 'Filter by IP', 'mighty-shield' ); ?>" class="regular-text" />
        </label>

        <input type="submit" class="button" value="<?php esc_attr_e( 'Filter', 'mighty-shield' ); ?>" />

        <?php if( $filter_action || $filter_ip ) : ?>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=logs' ) ); ?>" class="button"><?php esc_html_e( 'Clear Filters', 'mighty-shield' ); ?></a>
        <?php endif; ?>
    </form>

    <p class="description">
        <?php printf( esc_html__( 'Showing %1$d of %2$d total events.', 'mighty-shield' ), count( $logs ), $total ); ?>
    </p>

    <?php if( empty( $logs ) ) : ?>
        <p><?php esc_html_e( 'No log entries found.', 'mighty-shield' ); ?></p>
    <?php else : ?>
        <table class="mshield-table">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Time', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'IP', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Action', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Endpoint', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Reason', 'mighty-shield' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach( $logs as $log ) : ?>
                <tr>
                    <td><?php echo esc_html( date_i18n( 'Y-m-d H:i:s', strtotime( $log->created_at ) ) ); ?></td>
                    <td>
                        <code><?php echo esc_html( $log->ip ); ?></code>
                        <br>
                        <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=logs&filter_ip=' . urlencode( $log->ip ) ) ); ?>" style="font-size: 12px;"><?php esc_html_e( 'filter', 'mighty-shield' ); ?></a>
                        <?php
                        $block_url = wp_nonce_url(
                            admin_url( 'admin.php?page=mighty-shield&mshield_block_ip=' . urlencode( $log->ip ) ),
                            'mshield_block_ip'
                        );
                        ?>
                        &nbsp;|&nbsp;
                        <a href="<?php echo esc_url( $block_url ); ?>" style="font-size: 12px; color: #d63638;" onclick="return confirm('<?php echo esc_js( sprintf( __( 'Add %s to the blocklist?', 'mighty-shield' ), $log->ip ) ); ?>');"><?php esc_html_e( 'block', 'mighty-shield' ); ?></a>
                    </td>
                    <td>
                        <?php
                        $action_colors = [
                            'blocked'      => '#d63638',
                            'rate_limited' => '#dba617',
                            'flagged'      => '#2271b1',
                        ];
                        $color = isset( $action_colors[ $log->action ] ) ? $action_colors[ $log->action ] : '#50575e';
                        ?>
                        <span style="color: <?php echo esc_attr( $color ); ?>; font-weight: 600;"><?php echo esc_html( $log->action ); ?></span>
                    </td>
                    <td><code style="font-size: 12px;"><?php echo esc_html( $log->endpoint ); ?></code></td>
                    <td style="font-size: 13px;"><?php echo esc_html( $log->reason ); ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <!-- Pagination -->
        <?php if( $total_pages > 1 ) : ?>
        <div style="margin-top: 15px;">
            <?php
            $base_url = admin_url( 'admin.php?page=mighty-shield&tab=logs' );
            if( $filter_action ) $base_url .= '&filter_action=' . urlencode( $filter_action );
            if( $filter_ip ) $base_url .= '&filter_ip=' . urlencode( $filter_ip );

            echo paginate_links( [
                'base'    => $base_url . '%_%',
                'format'  => '&paged=%#%',
                'current' => $paged,
                'total'   => $total_pages,
            ] );
            ?>
        </div>
        <?php endif; ?>

    <?php endif; ?>
</div>

<!-- Clear Logs -->
<div class="mshield-section">
    <h2><?php esc_html_e( 'Maintenance', 'mighty-shield' ); ?></h2>
    <form method="post">
        <?php wp_nonce_field( 'mshield_clear_logs_action' ); ?>
        <p><?php esc_html_e( 'Clear all log entries. This action cannot be undone.', 'mighty-shield' ); ?></p>
        <input type="submit" name="mshield_clear_logs" class="button" value="<?php esc_attr_e( 'Clear All Logs', 'mighty-shield' ); ?>" onclick="return confirm('<?php esc_attr_e( 'Are you sure? This will delete all log entries.', 'mighty-shield' ); ?>');" />
    </form>
</div>
