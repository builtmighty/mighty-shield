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

// The state, its icon, its wording and its colours all come from one place —
// the WordPress dashboard widget draws the same stripe from the same call, and
// two copies of "what does Observing look like" is how they would drift.
$now       = admin_page::protection_state();
$states    = admin_page::protection_states();
$state_now = $now['key'];
$enabled   = $now['enabled'];
$enforcing = $now['enforcing'];
$observing = $now['observing'];
?>

<div class="mshield-stack">

    <!-- Protection status hero -->
    <div class="mshield-hero <?php echo esc_attr( $now['hero'] ); ?>">
        <span class="ms-accent"></span>
        <?php /* Same icon as the selected segment of the control on the right, drawn
                 from the same $states map so the two can never drift apart. */ ?>
        <span class="ms-ico">
            <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <?php echo $states[ $state_now ]['icon']; // phpcs:ignore WordPress.Security.EscapeOutput -- static markup from the map above. ?>
            </svg>
        </span>
        <div style="min-width:0">
            <div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap">
                <span class="mshield-hero-title"><?php echo esc_html( $now['title'] ); ?></span>
                <span class="mshield-pill <?php echo esc_attr( $now['pill'] ); ?>"><span class="dot"></span><?php echo esc_html( $now['label'] ); ?></span>
            </div>
            <?php /* No call to action here — the control to the right is the way
                     to change it. */ ?>
            <div class="mshield-hero-meta"><?php echo esc_html( $now['meta'] ); ?></div>
        </div>
        <span class="mshield-spacer"></span>
        <div style="display:flex;align-items:center;gap:11px">
            <span style="font-size:13px;color:var(--fg-2)"><?php esc_html_e( 'Protection', 'mighty-shield' ); ?></span>

            <?php /* A radiogroup rather than a switch: aria-checked is binary, so a
                     three-state control described as a switch would be unreadable to
                     a screen reader. Each option is a real link, so it is reachable
                     and operable by keyboard with no script at all. */ ?>
            <div class="mshield-tri at-<?php echo esc_attr( $state_now ); ?>"
                 role="radiogroup" aria-label="<?php esc_attr_e( 'Protection state', 'mighty-shield' ); ?>">
                <span class="ms-knob" aria-hidden="true"></span>
                <?php foreach( $states as $key => $state ) :
                    $is_now = $key === $state_now;
                    $url    = wp_nonce_url(
                        admin_url( 'admin.php?page=mighty-shield&mshield_set_state=' . $key ),
                        'mshield_set_state_' . $key
                    );
                    ?>
                    <a href="<?php echo esc_url( $url ); ?>"
                       class="ms-opt<?php echo $is_now ? ' is-now' : ''; ?>"
                       role="radio"
                       aria-checked="<?php echo $is_now ? 'true' : 'false'; ?>"
                       aria-label="<?php echo esc_attr( $state['hint'] ); ?>"
                       title="<?php echo esc_attr( $state['hint'] ); ?>">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                             stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                            <?php echo $state['icon']; // phpcs:ignore WordPress.Security.EscapeOutput -- static markup from the map above. ?>
                        </svg>
                    </a>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

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
