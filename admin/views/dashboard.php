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
use MightyShield\Includes\response;
use MightyShield\Includes\ip_data;
use MightyShield\Admin\admin_page;

$stats_day   = db::get_stats( 'day' );
$stats_week  = db::get_stats( 'week' );
$stats_month = db::get_stats( 'month' );
$top_ips     = db::get_top_blocked_ips( 10, 'week' );

// Enrich the top blocked IPs with geolocation data. This only makes a network
// call for IPs not already cached, so repeat loads stay fast.
$top_ip_list = array_map( function( $r ) { return $r->ip; }, $top_ips );
if( ! empty( $top_ip_list ) ) {
    ip_data::enrich( $top_ip_list );
}
$ip_map = db::get_ip_data_map( $top_ip_list );

// Initial chart series (defaults to 30 days; not persisted per user).
$chart_series = admin_page::chart_series( '30d' );

// The hero itself is drawn by the shell now, on every tab. What is still needed
// here is the state, which several panels below read to decide their wording.
$now       = admin_page::protection_state();
$enabled   = $now['enabled'];
$enforcing = $now['enforcing'];
$observing = $now['observing'];
?>

<div class="mshield-stack">

    <?php /* Only while setup is unfinished, and never once it has been skipped
             deliberately -- see setup_wizard::render_entry_notice() for why. */ ?>
    <?php if( \MightyShield\Admin\setup_wizard::is_pending() ) : ?>
        <div class="mshield-banner ms-degraded">
            <div>
                <strong><?php esc_html_e( 'Setup is not finished.', 'mighty-shield' ); ?></strong>
                <?php esc_html_e( 'A couple of minutes now, and MightyShield will be doing what you actually want rather than what it defaults to.', 'mighty-shield' ); ?>
            </div>
            <a class="mshield-btn is-primary is-small" href="<?php echo esc_url( \MightyShield\Admin\setup_wizard::url() ); ?>">
                <?php esc_html_e( 'Finish setup', 'mighty-shield' ); ?>
            </a>
        </div>
    <?php endif; ?>


    <!-- Interactive events trend chart -->
    <div class="mshield-card">
        <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:10px">
            <div>
                <div class="mshield-card-title" id="mshield-chart-title"><?php esc_html_e( 'Events over the past 30 days', 'mighty-shield' ); ?></div>
                <div class="mshield-card-sub" id="mshield-chart-sub"></div>
            </div>
            <span class="mshield-spacer"></span>
            <div class="mshield-legend">
                <span><i style="background:#d63638"></i><?php esc_html_e( 'Blocked', 'mighty-shield' ); ?></span>
                <span><i style="background:#dba617"></i><?php esc_html_e( 'Rate-limited', 'mighty-shield' ); ?></span>
                <span><i style="background:#8c5ce6"></i><?php esc_html_e( 'Flagged', 'mighty-shield' ); ?></span>
            </div>
        </div>
        <div class="mshield-range" id="mshield-chart-range">
            <button type="button" class="mshield-range-btn is-active" data-range="30d"><?php esc_html_e( '30 days', 'mighty-shield' ); ?></button>
            <button type="button" class="mshield-range-btn" data-range="7d"><?php esc_html_e( '7 days', 'mighty-shield' ); ?></button>
            <button type="button" class="mshield-range-btn" data-range="24h"><?php esc_html_e( '24 hours', 'mighty-shield' ); ?></button>
        </div>
        <div id="mshield-chart" class="mshield-chartbox"></div>
        <script type="application/json" id="mshield-chart-data"><?php echo wp_json_encode( $chart_series ); ?></script>
    </div>

    <!-- Stat cards -->
    <div class="mshield-grid">
        <?php
        $cards = [
            [ 'key' => 'total',        'label' => __( 'Total events', 'mighty-shield' ), 'class' => '' ],
            [ 'key' => 'blocked',      'label' => __( 'Blocked', 'mighty-shield' ),      'class' => 'is-blocked' ],
            [ 'key' => 'rate_limited', 'label' => __( 'Rate-limited', 'mighty-shield' ), 'class' => 'is-rate' ],
            [ 'key' => 'flagged',      'label' => __( 'Flagged', 'mighty-shield' ),      'class' => 'is-flag' ],
        ];
        foreach( $cards as $card ) :
            $k = $card['key'];
            ?>
            <div class="mshield-statcard <?php echo esc_attr( $card['class'] ); ?>">
                <div class="ms-label"><?php echo esc_html( $card['label'] ); ?></div>
                <div class="ms-big"><span class="n"><?php echo esc_html( number_format_i18n( (int) $stats_day[ $k ] ) ); ?></span><span class="u"><?php esc_html_e( 'last 24h', 'mighty-shield' ); ?></span></div>
                <div class="ms-row"><span><?php esc_html_e( '7 days', 'mighty-shield' ); ?></span><span class="v"><?php echo esc_html( number_format_i18n( (int) $stats_week[ $k ] ) ); ?></span></div>
                <div class="ms-row"><span><?php esc_html_e( '30 days', 'mighty-shield' ); ?></span><span class="v"><?php echo esc_html( number_format_i18n( (int) $stats_month[ $k ] ) ); ?></span></div>
            </div>
        <?php endforeach; ?>
    </div>

    <!-- Top blocked IPs -->
    <?php if( ! empty( $top_ips ) ) :
        $ip_max = 1;
        foreach( $top_ips as $row ) { $ip_max = max( $ip_max, (int) $row->total ); }
    ?>
    <div class="mshield-card is-flush">
        <div class="mshield-card-head">
            <div>
                <div class="mshield-card-title"><?php esc_html_e( 'Top Blocked IPs', 'mighty-shield' ); ?></div>
                <div class="mshield-card-sub"><?php esc_html_e( 'Past 7 days', 'mighty-shield' ); ?></div>
            </div>
            <span class="mshield-spacer"></span>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=logs' ) ); ?>" style="font-size:13px;font-weight:600;color:var(--brand)"><?php esc_html_e( 'View all logs →', 'mighty-shield' ); ?></a>
        </div>
        <?php foreach( $top_ips as $row ) :
            $pct = round( (int) $row->total / $ip_max * 100 );
            $logs_url = admin_url( 'admin.php?page=mighty-shield&tab=logs&filter_ip=' . urlencode( $row->ip ) );

            // Build a location string from cached IP data, if present.
            $info = isset( $ip_map[ $row->ip ] ) ? $ip_map[ $row->ip ] : null;
            $loc  = '';
            if( $info && $info['status'] === 'success' ) {
                $bits = array_filter( [ $info['city'], $info['region'], $info['country'] ] );
                $loc  = implode( ', ', $bits );
            }
        ?>
        <div class="mshield-iprow">
            <div class="ipmeta">
                <span class="ip mshield-mono"><?php echo esc_html( $row->ip ); ?></span>
                <?php if( $loc !== '' || ( $info && ! empty( $info['org'] ) ) ) : ?>
                    <span class="loc">
                        <?php echo esc_html( $loc ); ?>
                        <?php if( $info && ! empty( $info['org'] ) ) : ?><span class="org">· <?php echo esc_html( $info['org'] ); ?></span><?php endif; ?>
                    </span>
                <?php endif; ?>
            </div>
            <div class="bar"><span style="width:<?php echo esc_attr( $pct ); ?>%"></span></div>
            <span class="count"><?php echo esc_html( number_format_i18n( (int) $row->total ) ); ?></span>
            <a href="<?php echo esc_url( $logs_url ); ?>" class="ip-logs"><?php esc_html_e( 'Logs', 'mighty-shield' ); ?></a>
        </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

</div>
