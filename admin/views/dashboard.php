<?php
/**
 * Dashboard view.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\db;
use MightyShield\Includes\settings;

$stats_day   = db::get_stats( 'day' );
$stats_week  = db::get_stats( 'week' );
$stats_month = db::get_stats( 'month' );
$top_ips     = db::get_top_blocked_ips( 10, 'week' );
?>

<div class="mshield-section">
    <h2><?php esc_html_e( 'Protection Status', 'mighty-shield' ); ?></h2>
    <p>
        <?php if( settings::get( 'mshield_enabled' ) === 'yes' ) : ?>
            <span style="color: #00a32a; font-weight: 600;">&#9679; <?php esc_html_e( 'MightyShield is active and protecting your store.', 'mighty-shield' ); ?></span>
        <?php else : ?>
            <span style="color: #d63638; font-weight: 600;">&#9679; <?php esc_html_e( 'MightyShield is currently disabled.', 'mighty-shield' ); ?></span>
        <?php endif; ?>
    </p>
</div>

<h2><?php esc_html_e( 'Last 24 Hours', 'mighty-shield' ); ?></h2>
<div class="mshield-stats">
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Total Events', 'mighty-shield' ); ?></h3>
        <div class="number"><?php echo esc_html( $stats_day['total'] ); ?></div>
    </div>
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Blocked', 'mighty-shield' ); ?></h3>
        <div class="number blocked"><?php echo esc_html( $stats_day['blocked'] ); ?></div>
    </div>
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Rate Limited', 'mighty-shield' ); ?></h3>
        <div class="number limited"><?php echo esc_html( $stats_day['rate_limited'] ); ?></div>
    </div>
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Flagged', 'mighty-shield' ); ?></h3>
        <div class="number flagged"><?php echo esc_html( $stats_day['flagged'] ); ?></div>
    </div>
</div>

<h2><?php esc_html_e( 'Last 7 Days', 'mighty-shield' ); ?></h2>
<div class="mshield-stats">
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Total Events', 'mighty-shield' ); ?></h3>
        <div class="number"><?php echo esc_html( $stats_week['total'] ); ?></div>
    </div>
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Blocked', 'mighty-shield' ); ?></h3>
        <div class="number blocked"><?php echo esc_html( $stats_week['blocked'] ); ?></div>
    </div>
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Rate Limited', 'mighty-shield' ); ?></h3>
        <div class="number limited"><?php echo esc_html( $stats_week['rate_limited'] ); ?></div>
    </div>
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Flagged', 'mighty-shield' ); ?></h3>
        <div class="number flagged"><?php echo esc_html( $stats_week['flagged'] ); ?></div>
    </div>
</div>

<h2><?php esc_html_e( 'Last 30 Days', 'mighty-shield' ); ?></h2>
<div class="mshield-stats">
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Total Events', 'mighty-shield' ); ?></h3>
        <div class="number"><?php echo esc_html( $stats_month['total'] ); ?></div>
    </div>
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Blocked', 'mighty-shield' ); ?></h3>
        <div class="number blocked"><?php echo esc_html( $stats_month['blocked'] ); ?></div>
    </div>
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Rate Limited', 'mighty-shield' ); ?></h3>
        <div class="number limited"><?php echo esc_html( $stats_month['rate_limited'] ); ?></div>
    </div>
    <div class="mshield-stat">
        <h3><?php esc_html_e( 'Flagged', 'mighty-shield' ); ?></h3>
        <div class="number flagged"><?php echo esc_html( $stats_month['flagged'] ); ?></div>
    </div>
</div>

<?php if( ! empty( $top_ips ) ) : ?>
<div class="mshield-section">
    <h2><?php esc_html_e( 'Top Blocked IPs (7 Days)', 'mighty-shield' ); ?></h2>
    <table class="mshield-table">
        <thead>
            <tr>
                <th><?php esc_html_e( 'IP Address', 'mighty-shield' ); ?></th>
                <th><?php esc_html_e( 'Blocked Count', 'mighty-shield' ); ?></th>
                <th><?php esc_html_e( 'Actions', 'mighty-shield' ); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach( $top_ips as $row ) : ?>
            <tr>
                <td><code><?php echo esc_html( $row->ip ); ?></code></td>
                <td><?php echo esc_html( $row->total ); ?></td>
                <td>
                    <?php
                    $whitelist_url = wp_nonce_url(
                        admin_url( 'admin.php?page=mighty-shield&tab=whitelist&mshield_auto_add=' . urlencode( $row->ip ) ),
                        'mshield_auto_add_ip'
                    );
                    ?>
                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=logs&filter_ip=' . urlencode( $row->ip ) ) ); ?>"><?php esc_html_e( 'View Logs', 'mighty-shield' ); ?></a>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php endif; ?>
