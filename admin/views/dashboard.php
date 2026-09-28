<?php
/**
 * Dashboard view.
 *
 * The chart first, because it is the one visual signal of what has been
 * happening; then the three things that ask for a decision (orders waiting,
 * what enforcing would do, what the store's own orders say about the
 * weights); then the counters and the busiest addresses.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\ip_data;
use MightyShield\Includes\signals;
use MightyShield\Includes\actions;
use MightyShield\Admin\admin_page;

$stats_day   = db::get_stats( 'day' );
$stats_week  = db::get_stats( 'week' );
$stats_month = db::get_stats( 'month' );
$top_ips     = db::get_top_blocked_ips( 10, 'week' );

// Enrich the top blocked IPs with location. Only a lookup for addresses not
// already cached, so repeat loads stay fast.
$top_ip_list = array_map( function( $r ) { return $r->ip; }, $top_ips );
if( ! empty( $top_ip_list ) ) {
    ip_data::enrich( $top_ip_list );
}
$ip_map = db::get_ip_data_map( $top_ip_list );

// Initial chart series (defaults to 30 days; not persisted per user).
$chart_series = admin_page::chart_series( '30d' );

// The work: what is waiting, what enforcing would do, what the weights cost.
$mshield_waiting = \MightyShield\Admin\fraud_review::pending_count();
$mshield_queue   = admin_url( 'admin.php?page=mshield-fraud-review' );

$mshield_fc  = \MightyShield\Includes\forecast::run( 30 );
$mshield_say = \MightyShield\Includes\forecast::summary( $mshield_fc );
$mshield_ref = $mshield_fc['actions'][ actions::REJECT ] ?? null;

$mshield_rep = \MightyShield\Includes\signal_report::analyse( 90 );
$mshield_fp  = array_slice( \MightyShield\Includes\signal_report::false_positives( $mshield_rep ), 0, 2, true );
$mshield_ov  = array_slice( \MightyShield\Includes\signal_report::overlaps( $mshield_rep ), 0, 2 );
$mshield_scoring_url = admin_url( 'admin.php?page=mighty-shield&tab=scoring' );
?>

<div class="mshield-stack">

    <?php /* Only while setup is unfinished, and never once it has been skipped
             deliberately -- see setup_wizard::render_entry_notice() for why.
             A plain banner: an unfinished setup is not an outage. */ ?>
    <?php if( \MightyShield\Admin\setup_wizard::is_pending() ) : ?>
        <div class="mshield-banner">
            <div>
                <strong><?php esc_html_e( 'Setup is not finished.', 'mighty-shield' ); ?></strong>
                <?php esc_html_e( 'A couple of minutes now, and MightyShield will be doing what you actually want rather than what it defaults to.', 'mighty-shield' ); ?>
            </div>
            <a class="mshield-btn is-primary is-small" href="<?php echo esc_url( \MightyShield\Admin\setup_wizard::url() ); ?>">
                <?php esc_html_e( 'Finish setup', 'mighty-shield' ); ?>
            </a>
        </div>
    <?php endif; ?>

    <?php /* AI review switched on with nothing behind it. Only this case: a
             store that never turned AI on is not misconfigured, but "switched
             on and silently reviewing nothing" reads as switched on. */ ?>
    <?php if( settings::get( 'mshield_ai_enabled' ) === 'yes' && ! \MightyShield\Includes\ai_client::is_ready() ) : ?>
        <div class="mshield-banner is-warning">
            <div>
                <strong><?php esc_html_e( 'AI review is switched on but has no provider.', 'mighty-shield' ); ?></strong>
                <?php esc_html_e( 'No order is reviewed until an API key is saved. Every other check is still running.', 'mighty-shield' ); ?>
            </div>
            <a class="mshield-btn is-primary is-small" href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=ai' ) ); ?>">
                <?php esc_html_e( 'Add a key', 'mighty-shield' ); ?>
            </a>
        </div>
    <?php endif; ?>

    <!-- Events chart -->
    <div class="mshield-card">
        <div class="mshield-chart-head">
            <div>
                <h2 class="mshield-card-title" id="mshield-chart-title"><?php esc_html_e( 'Events over the past 30 days', 'mighty-shield' ); ?></h2>
                <div class="mshield-card-sub" id="mshield-chart-sub"></div>
            </div>
            <span class="mshield-spacer"></span>
            <div class="mshield-legend">
                <span><i class="is-blocked"></i><?php esc_html_e( 'Blocked', 'mighty-shield' ); ?></span>
                <span><i class="is-rate"></i><?php esc_html_e( 'Rate-limited', 'mighty-shield' ); ?></span>
                <span><i class="is-flag"></i><?php esc_html_e( 'Flagged', 'mighty-shield' ); ?></span>
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

    <!-- The work -->
    <div class="mshield-work">

        <div class="mshield-card mshield-workcard">
            <h2 class="mshield-card-title"><?php esc_html_e( 'Waiting for You', 'mighty-shield' ); ?></h2>
            <?php if( $mshield_waiting > 0 ) : ?>
                <div class="ms-work-big">
                    <span class="n"><?php echo esc_html( number_format_i18n( $mshield_waiting ) ); ?></span>
                    <span class="u"><?php echo esc_html( _n( 'order held or flagged', 'orders held or flagged', $mshield_waiting, 'mighty-shield' ) ); ?></span>
                </div>
                <a class="mshield-btn is-primary is-small" href="<?php echo esc_url( $mshield_queue ); ?>"><?php esc_html_e( 'Open queue', 'mighty-shield' ); ?></a>
            <?php else : ?>
                <p class="mshield-empty"><?php esc_html_e( 'Nothing waiting.', 'mighty-shield' ); ?></p>
                <a class="mshield-card-link" href="<?php echo esc_url( $mshield_queue ); ?>"><?php esc_html_e( 'Open queue', 'mighty-shield' ); ?> &rarr;</a>
            <?php endif; ?>
        </div>

        <div class="mshield-card mshield-workcard">
            <h2 class="mshield-card-title"><?php esc_html_e( 'Enforcement Audit', 'mighty-shield' ); ?></h2>
            <?php if( '' === $mshield_say ) : ?>
                <p class="mshield-empty">
                    <?php
                    printf(
                        /* translators: %s: number of orders rated so far. */
                        esc_html__( 'Needs 20 rated orders; %s so far.', 'mighty-shield' ),
                        esc_html( number_format_i18n( (int) $mshield_fc['rated'] ) )
                    );
                    ?>
                </p>
            <?php else : ?>
                <div class="ms-work-figures">
                    <span class="ms-work-figure">
                        <span class="n"><?php echo esc_html( number_format_i18n( (int) ( $mshield_ref['total'] ?? 0 ) ) ); ?></span>
                        <span class="u"><?php esc_html_e( 'refused', 'mighty-shield' ); ?></span>
                    </span>
                    <span class="ms-work-figure is-bad">
                        <span class="n"><?php echo esc_html( number_format_i18n( (int) ( $mshield_ref['bad'] ?? 0 ) ) ); ?></span>
                        <span class="u"><?php esc_html_e( 'were fraud', 'mighty-shield' ); ?></span>
                    </span>
                    <span class="ms-work-figure is-lost">
                        <span class="n"><?php echo esc_html( number_format_i18n( (int) ( $mshield_ref['good'] ?? 0 ) ) ); ?></span>
                        <span class="u"><?php esc_html_e( 'real customers', 'mighty-shield' ); ?></span>
                    </span>
                </div>
                <p class="description"><?php esc_html_e( 'Of the last 30 days of orders, re-rated against the thresholds on Shielding.', 'mighty-shield' ); ?></p>
                <a class="mshield-card-link" href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=blocking' ) ); ?>"><?php esc_html_e( 'Shielding', 'mighty-shield' ); ?> &rarr;</a>
            <?php endif; ?>
        </div>

        <div class="mshield-card mshield-workcard">
            <h2 class="mshield-card-title"><?php esc_html_e( 'What your orders say', 'mighty-shield' ); ?></h2>
            <?php if( ! $mshield_fp && ! $mshield_ov ) : ?>
                <p class="mshield-empty"><?php esc_html_e( 'Nothing yet.', 'mighty-shield' ); ?></p>
            <?php else : ?>
                <ul class="ms-work-list">
                    <?php foreach( $mshield_fp as $mshield_key => $mshield_row ) : ?>
                        <li>
                            <span>
                                <?php
                                printf(
                                    /* translators: 1: check name, 2: number of orders. */
                                    esc_html__( '%1$s fired on %2$s orders you approved.', 'mighty-shield' ),
                                    '<strong>' . esc_html( signals::label( $mshield_key ) ) . '</strong>',
                                    esc_html( number_format_i18n( $mshield_row['good'] ) )
                                );
                                ?>
                            </span>
                            <a class="mshield-card-link" href="<?php echo esc_url( $mshield_scoring_url . '#mshield-sig-' . $mshield_key ); ?>"><?php esc_html_e( 'Adjust', 'mighty-shield' ); ?> &rarr;</a>
                        </li>
                    <?php endforeach; ?>
                    <?php foreach( $mshield_ov as $mshield_pair ) : ?>
                        <li>
                            <span>
                                <?php
                                printf(
                                    /* translators: 1: check name, 2: check name, 3: number of orders. */
                                    esc_html__( '%1$s and %2$s fire together on %3$s orders.', 'mighty-shield' ),
                                    '<strong>' . esc_html( signals::label( $mshield_pair['a'] ) ) . '</strong>',
                                    '<strong>' . esc_html( signals::label( $mshield_pair['b'] ) ) . '</strong>',
                                    esc_html( number_format_i18n( $mshield_pair['together'] ) )
                                );
                                ?>
                            </span>
                            <a class="mshield-card-link" href="<?php echo esc_url( $mshield_scoring_url . '#mshield-sig-' . $mshield_pair['a'] ); ?>"><?php esc_html_e( 'Adjust', 'mighty-shield' ); ?> &rarr;</a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>

    </div>

    <!-- Counters -->
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

    <!-- Top blocked addresses -->
    <div class="mshield-card is-flush">
        <div class="mshield-card-head">
            <div>
                <h2 class="mshield-card-title"><?php esc_html_e( 'Top Blocked Addresses', 'mighty-shield' ); ?></h2>
                <div class="mshield-card-sub"><?php esc_html_e( 'Past 7 days', 'mighty-shield' ); ?></div>
            </div>
            <span class="mshield-spacer"></span>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=logs' ) ); ?>" class="mshield-card-link"><?php esc_html_e( 'All logs', 'mighty-shield' ); ?> &rarr;</a>
        </div>
        <?php if( empty( $top_ips ) ) : ?>
            <p class="mshield-empty is-padded"><?php esc_html_e( 'Nothing blocked in the past 7 days.', 'mighty-shield' ); ?></p>
        <?php else :
            $ip_max = 1;
            foreach( $top_ips as $row ) { $ip_max = max( $ip_max, (int) $row->total ); }
            foreach( $top_ips as $row ) :
                $pct = round( (int) $row->total / $ip_max * 100 );
                $logs_url = admin_url( 'admin.php?page=mighty-shield&tab=logs&filter_ip=' . urlencode( $row->ip ) );

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
        <?php endif; ?>
    </div>

</div>
