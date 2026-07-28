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
$daily       = db::get_daily_stats( 7 );

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

    <!-- 7-day trend chart -->
    <?php
    $max = 1;
    foreach( $daily as $d ) {
        $max = max( $max, (int) $d['blocked'], (int) $d['rate_limited'], (int) $d['flagged'] );
    }
    $n     = max( 1, count( $daily ) );
    $x0    = 44; $x1 = 680; $yTop = 30; $yBot = 190;
    $stepX = $n > 1 ? ( $x1 - $x0 ) / ( $n - 1 ) : 0;
    $py    = function( $v ) use ( $max, $yTop, $yBot ) { return $yBot - ( $v / $max ) * ( $yBot - $yTop ); };
    $pts   = function( $key ) use ( $daily, $x0, $stepX, $py ) {
        $out = [];
        foreach( array_values( $daily ) as $i => $d ) {
            $out[] = round( $x0 + $i * $stepX, 1 ) . ',' . round( $py( (int) $d[ $key ] ), 1 );
        }
        return implode( ' ', $out );
    };
    $week_total   = (int) $stats_week['total'];
    $week_blocked = (int) $stats_week['blocked'];
    $week_pct     = $week_total > 0 ? round( $week_blocked / $week_total * 100 ) : 0;
    ?>
    <div class="mshield-card">
        <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:6px">
            <div>
                <div class="mshield-card-title"><?php esc_html_e( 'Events over the past 7 days', 'mighty-shield' ); ?></div>
                <div class="mshield-card-sub"><?php printf( esc_html__( '%1$s events processed · %2$d%% blocked', 'mighty-shield' ), esc_html( number_format_i18n( $week_total ) ), (int) $week_pct ); ?></div>
            </div>
            <span class="mshield-spacer"></span>
            <div class="mshield-legend">
                <span><i style="background:#d63638"></i><?php esc_html_e( 'Blocked', 'mighty-shield' ); ?></span>
                <span><i style="background:#dba617"></i><?php esc_html_e( 'Rate-limited', 'mighty-shield' ); ?></span>
                <span><i style="background:#8c5ce6"></i><?php esc_html_e( 'Flagged', 'mighty-shield' ); ?></span>
            </div>
        </div>
        <svg viewBox="0 0 724 214" class="mshield-chart">
            <g stroke="var(--line-2)" stroke-width="1">
                <line x1="34" y1="30" x2="712" y2="30"></line>
                <line x1="34" y1="70" x2="712" y2="70"></line>
                <line x1="34" y1="110" x2="712" y2="110"></line>
                <line x1="34" y1="150" x2="712" y2="150"></line>
                <line x1="34" y1="190" x2="712" y2="190"></line>
            </g>
            <g fill="var(--fg-3)" font-size="10.5" font-family="JetBrains Mono, monospace" text-anchor="end">
                <text x="26" y="34"><?php echo esc_html( $max ); ?></text>
                <text x="26" y="114"><?php echo esc_html( round( $max / 2 ) ); ?></text>
                <text x="26" y="194">0</text>
            </g>
            <polyline points="<?php echo esc_attr( $pts( 'blocked' ) ); ?>" fill="none" stroke="#d63638" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"></polyline>
            <polyline points="<?php echo esc_attr( $pts( 'rate_limited' ) ); ?>" fill="none" stroke="#dba617" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"></polyline>
            <polyline points="<?php echo esc_attr( $pts( 'flagged' ) ); ?>" fill="none" stroke="#8c5ce6" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"></polyline>
            <g fill="var(--fg-3)" font-size="11" font-family="Public Sans, sans-serif" text-anchor="middle">
                <?php foreach( array_values( $daily ) as $i => $d ) : ?>
                    <text x="<?php echo esc_attr( round( $x0 + $i * $stepX, 1 ) ); ?>" y="209"><?php echo esc_html( date_i18n( 'M j', strtotime( $d['date'] ) ) ); ?></text>
                <?php endforeach; ?>
            </g>
        </svg>
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
                <div class="mshield-card-title"><?php esc_html_e( 'Top blocked IPs', 'mighty-shield' ); ?></div>
                <div class="mshield-card-sub"><?php esc_html_e( 'Past 7 days', 'mighty-shield' ); ?></div>
            </div>
            <span class="mshield-spacer"></span>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=logs' ) ); ?>" style="font-size:13px;font-weight:600;color:var(--brand)"><?php esc_html_e( 'View all logs →', 'mighty-shield' ); ?></a>
        </div>
        <?php foreach( $top_ips as $row ) :
            $pct = round( (int) $row->total / $ip_max * 100 );
            $logs_url = admin_url( 'admin.php?page=mighty-shield&tab=logs&filter_ip=' . urlencode( $row->ip ) );
        ?>
        <div class="mshield-iprow">
            <span class="ip"><?php echo esc_html( $row->ip ); ?></span>
            <div class="bar"><span style="width:<?php echo esc_attr( $pct ); ?>%"></span></div>
            <span class="count"><?php echo esc_html( number_format_i18n( (int) $row->total ) ); ?></span>
            <a href="<?php echo esc_url( $logs_url ); ?>" style="font-size:12.5px;color:var(--brand);font-weight:600"><?php esc_html_e( 'Logs', 'mighty-shield' ); ?></a>
        </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

</div>
