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

$enabled = settings::get( 'mshield_enabled' ) === 'yes';

// The 12 protection layers. Always-on modules count as enabled; the rest
// reflect their individual setting.
$layers = [
    true,                                                          // Rate limiting.
    true,                                                          // Velocity detection.
    true,                                                          // Failed-payment tracking.
    true,                                                          // Disposable email blocking.
    (float) settings::get( 'mshield_min_order_amount' ) > 0,       // Order-amount validation.
    true,                                                          // Address validation.
    settings::get( 'mshield_zip_state_enabled' ) === 'yes',        // ZIP/State mismatch.
    settings::get( 'mshield_smarty_enabled' ) === 'yes',           // Smarty verification.
    settings::get( 'mshield_honeypot_enabled' ) === 'yes',         // Honeypot.
    settings::get( 'mshield_timing_enabled' ) === 'yes',           // Checkout timing.
    settings::get( 'mshield_fingerprint_enabled' ) === 'yes',      // Device fingerprinting.
    settings::get( 'mshield_captcha_provider' ) !== 'off',         // Bot challenge (CAPTCHA).
];
$layers_on    = count( array_filter( $layers ) );
$layers_total = count( $layers );

$toggle_url = wp_nonce_url(
    admin_url( 'admin.php?page=mighty-shield&mshield_toggle_protection=1' ),
    'mshield_toggle_protection'
);
?>

<div class="mshield-stack">

    <!-- Protection status hero -->
    <div class="mshield-hero <?php echo $enabled ? '' : 'is-off'; ?>">
        <span class="ms-accent"></span>
        <span class="ms-ico">
            <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 4.6-3.2 8.4-8 9.6C7.2 20.4 4 16.6 4 12V6z"></path><path d="M9 12l2 2 4-4"></path></svg>
        </span>
        <div style="min-width:0">
            <div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap">
                <span class="mshield-hero-title">
                    <?php echo $enabled
                        ? esc_html__( 'MightyShield is actively protecting your store', 'mighty-shield' )
                        : esc_html__( 'MightyShield protection is turned off', 'mighty-shield' ); ?>
                </span>
                <?php if( $enabled ) : ?>
                    <span class="mshield-pill is-ok"><span class="dot"></span><?php esc_html_e( 'Active', 'mighty-shield' ); ?></span>
                <?php else : ?>
                    <span class="mshield-pill is-blocked"><span class="dot"></span><?php esc_html_e( 'Disabled', 'mighty-shield' ); ?></span>
                <?php endif; ?>
            </div>
            <div class="mshield-hero-meta">
                <?php printf( esc_html__( '%1$d of %2$d layers enabled', 'mighty-shield' ), (int) $layers_on, (int) $layers_total ); ?>
            </div>
        </div>
        <span class="mshield-spacer"></span>
        <div style="display:flex;align-items:center;gap:11px">
            <span style="font-size:13px;color:var(--fg-2)"><?php esc_html_e( 'Protection', 'mighty-shield' ); ?></span>
            <a href="<?php echo esc_url( $toggle_url ); ?>" class="mshield-toggle <?php echo $enabled ? 'is-on' : ''; ?>" role="switch" aria-checked="<?php echo $enabled ? 'true' : 'false'; ?>" aria-label="<?php esc_attr_e( 'Toggle protection', 'mighty-shield' ); ?>"><span class="knob"></span></a>
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
