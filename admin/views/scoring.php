<?php
/**
 * Scoring tab.
 *
 * Every check on one grid, grouped: whether it is on, what it costs, whether
 * it can force a risk level on its own, and how often it has actually fired
 * on real traffic. Every score is visible and editable at once; only a
 * check's extra fields fold away under its row.
 *
 * Uses .mshield-section and the app's own components so it inherits the
 * palette and reads in dark mode.
 *
 * @package MightyShield
 * @since   1.9.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\signals;
use MightyShield\Includes\risk_levels;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\trust_badge;
use MightyShield\Admin\admin_page;
use MightyShield\Includes\scoring_profiles;

// Force-level choices, least to most severe. Trusted is deliberately absent:
// a signal may make an order look worse, never vouch for it.
$floor_choices = [ 'none' => __( 'Scoring only', 'mighty-shield' ) ];

foreach( risk_levels::LADDER as $level_key => $level ) {
    if( $level_key === risk_levels::TRUSTED ) continue;
    $floor_choices[ $level_key ] = risk_levels::label( $level_key );
}

$days    = 30;
$stats   = db::get_signal_stats( $days );
$total   = db::get_risk_count( $days );
$sampled = $total > 0;

// What the store's own history says about these weights: which checks keep
// firing on orders that turned out fine, and which pairs fire together. Both
// are said under the check's name, and the chips above can show only those.
$mshield_rep = \MightyShield\Includes\signal_report::analyse( 90 );
$mshield_fp  = \MightyShield\Includes\signal_report::false_positives( $mshield_rep );
$mshield_ov  = \MightyShield\Includes\signal_report::overlaps( $mshield_rep );

$mshield_pairs = [];
foreach( $mshield_ov as $mshield_pair ) {
    $mshield_pairs[ $mshield_pair['a'] ][] = $mshield_pair + [ 'other' => $mshield_pair['b'] ];
    $mshield_pairs[ $mshield_pair['b'] ][] = $mshield_pair + [ 'other' => $mshield_pair['a'] ];
}

$mshield_all_keys = [];
foreach( signals::groups() as $mshield_gk => $mshield_gl ) {
    foreach( signals::in_group( $mshield_gk ) as $mshield_k ) $mshield_all_keys[] = $mshield_k;
}
$mshield_off = count( array_filter( $mshield_all_keys, function( $k ) { return ! signals::is_enabled( $k ); } ) );
?>

<?php
// The profile switcher sits outside the settings form, deliberately. Picking a
// profile rewrites every trust cost at once, so it is an action that applies
// on click; the script asks first when the form below has unsaved changes.
$mshield_now   = scoring_profiles::current();
$mshield_copy  = scoring_profiles::copy();
$mshield_tuned = $mshield_now === 'custom';

// How many rows this merchant has tuned by hand. Switching overwrites them, so
// the links carry the count and the confirm dialog uses it. Zero unless Custom.
$mshield_dirty = scoring_profiles::hand_tuned_count();
?>

<div class="mshield-section">

    <h2><?php esc_html_e( 'Scoring Profile', 'mighty-shield' ); ?></h2>

    <?php /* The same sliding switch the hero uses for protection state,
             widened to four text labels. The knob carries the colour of what
             the profile does, borrowed from the risk levels. */ ?>
    <div class="mshield-tri is-full at-<?php echo esc_attr( $mshield_now ); ?>"
         role="radiogroup" aria-label="<?php esc_attr_e( 'Scoring Profile', 'mighty-shield' ); ?>">

        <span class="ms-knob" aria-hidden="true"></span>

        <?php foreach( scoring_profiles::PROFILES as $mshield_key => $mshield_spec ) :

            $mshield_is = ( $mshield_now === $mshield_key );

            $mshield_url = wp_nonce_url(
                admin_url( 'admin.php?page=mighty-shield&tab=scoring&mshield_set_profile=' . $mshield_key ),
                'mshield_set_profile_' . $mshield_key
            );
            ?>
            <a href="<?php echo esc_url( $mshield_url ); ?>"
               class="ms-opt<?php echo $mshield_is ? ' is-now' : ''; ?>"
               role="radio"
               aria-checked="<?php echo $mshield_is ? 'true' : 'false'; ?>"
               data-tone="<?php echo esc_attr( $mshield_key ); ?>"
               title="<?php echo esc_attr( $mshield_copy[ $mshield_key ]['blurb'] ); ?>"
               <?php /* Read by initScoringProfile(), which asks before overwriting hand-tuned rows. */ ?>
               data-mshield-profile="<?php echo esc_attr( $mshield_copy[ $mshield_key ]['label'] ); ?>"
               data-mshield-changes="<?php echo esc_attr( $mshield_dirty ); ?>">
                <?php echo esc_html( $mshield_copy[ $mshield_key ]['label'] ); ?>
            </a>
        <?php endforeach; ?>

        <?php
        /* Custom is a state, not a destination. It lights up on its own the
           moment a row stops matching the active profile, so it is a span with
           nothing to click rather than a fourth choice. */
        ?>
        <span class="ms-opt is-static<?php echo $mshield_tuned ? ' is-now' : ''; ?>"
              role="radio" aria-checked="<?php echo $mshield_tuned ? 'true' : 'false'; ?>"
              aria-disabled="true" data-tone="custom"
              title="<?php echo esc_attr( $mshield_copy['custom']['blurb'] ); ?>">
            <?php echo esc_html( $mshield_copy['custom']['label'] ); ?>
        </span>

    </div>

    <p class="mshield-hint">
        <?php echo esc_html( $mshield_copy[ $mshield_now ]['blurb'] ); ?>
        <?php esc_html_e( 'Applies at once.', 'mighty-shield' ); ?>
    </p>

</div>

<div class="mshield-section">

    <h2><?php esc_html_e( 'Trust Rating', 'mighty-shield' ); ?></h2>

    <p class="description">
        <?php esc_html_e( 'Every order is rated from 1 to 100.', 'mighty-shield' ); ?>
        <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=documentation#scoring' ) ); ?>">
            <?php esc_html_e( 'How this works', 'mighty-shield' ); ?> &rarr;
        </a>
    </p>

    <?php
    // Built from the ladder and the CONFIGURED thresholds, not from literals,
    // through trust_badge, so the order panel's dial and this scale cannot
    // drift apart.
    $span = trust_badge::spans();
    ?>

    <div class="mshield-scale">
        <?php foreach( array_reverse( risk_levels::LADDER, true ) as $lk => $level ) :

            $has  = isset( $span[ $lk ] );
            $from = $has ? $span[ $lk ][0] : null;
            $to   = $has ? $span[ $lk ][1] : null;
            ?>
            <span class="<?php echo esc_attr( trust_badge::level_class( $lk ) ); ?>">

                <?php
                // Escaped inside trust_badge::span().
                echo trust_badge::span( $lk, $from, $to ); // phpcs:ignore WordPress.Security.EscapeOutput
                ?>

                <?php echo esc_html( risk_levels::label( $lk ) ); ?>

                <?php if( ! ( $has && $to >= $from ) ) : ?>
                    <b><?php esc_html_e( 'signal only', 'mighty-shield' ); ?></b>
                <?php endif; ?>
            </span>
        <?php endforeach; ?>
    </div>

</div>

<form method="post" action="options.php" class="mshield-checks-form" id="mshield-checks-form">
    <?php settings_fields( 'mshield_scoring' ); ?>

    <div class="mshield-checks" id="mshield-checks">

        <div class="mshield-section mshield-checks-tools">
            <input type="search" class="mshield-input" data-checks-find
                   placeholder="<?php esc_attr_e( 'Find a check', 'mighty-shield' ); ?>"
                   aria-label="<?php esc_attr_e( 'Find a check', 'mighty-shield' ); ?>" />
            <div class="mshield-checks-chips" role="group" aria-label="<?php esc_attr_e( 'Show', 'mighty-shield' ); ?>">
                <button type="button" class="mshield-chipbtn is-on" data-checks-filter="all">
                    <?php
                    /* translators: %s: number of checks. */
                    printf( esc_html__( 'All %s', 'mighty-shield' ), esc_html( number_format_i18n( count( $mshield_all_keys ) ) ) );
                    ?>
                </button>
                <?php if( $mshield_fp ) : ?>
                    <button type="button" class="mshield-chipbtn" data-checks-filter="fp">
                        <?php
                        /* translators: %s: number of checks. */
                        printf( esc_html__( 'Costing you customers %s', 'mighty-shield' ), esc_html( number_format_i18n( count( $mshield_fp ) ) ) );
                        ?>
                    </button>
                <?php endif; ?>
                <?php if( $mshield_pairs ) : ?>
                    <button type="button" class="mshield-chipbtn" data-checks-filter="ov">
                        <?php
                        /* translators: %s: number of checks. */
                        printf( esc_html__( 'Firing together %s', 'mighty-shield' ), esc_html( number_format_i18n( count( $mshield_pairs ) ) ) );
                        ?>
                    </button>
                <?php endif; ?>
                <?php if( $mshield_off ) : ?>
                    <button type="button" class="mshield-chipbtn" data-checks-filter="off">
                        <?php
                        /* translators: %s: number of checks. */
                        printf( esc_html__( 'Off %s', 'mighty-shield' ), esc_html( number_format_i18n( $mshield_off ) ) );
                        ?>
                    </button>
                <?php endif; ?>
            </div>
        </div>

        <?php foreach( signals::groups() as $group_key => $group_label ) : ?>

            <div class="mshield-section mshield-checkgroup" data-group="<?php echo esc_attr( $group_key ); ?>">

                <h2><?php echo esc_html( $group_label ); ?></h2>

                <div class="mshield-checkgrid" role="table">
                    <div class="mshield-checkrow is-head" role="row">
                        <span role="columnheader"><?php esc_html_e( 'On', 'mighty-shield' ); ?></span>
                        <span role="columnheader"><?php esc_html_e( 'Check', 'mighty-shield' ); ?></span>
                        <span role="columnheader"><?php esc_html_e( 'Trust cost', 'mighty-shield' ); ?></span>
                        <span role="columnheader"><?php esc_html_e( 'Force level', 'mighty-shield' ); ?></span>
                        <span role="columnheader"><?php esc_html_e( 'Fires', 'mighty-shield' ); ?></span>
                        <span role="columnheader"></span>
                    </div>

                    <?php foreach( signals::in_group( $group_key ) as $key ) :

                        $weight  = signals::weight( $key );
                        $floor   = signals::floor( $key );
                        $enabled = signals::is_enabled( $key );
                        $desc    = signals::description( $key );
                        $fields  = signals::fields( $key );

                        $fired = isset( $stats[ $key ] ) ? (int) $stats[ $key ]['count'] : 0;
                        $rate  = $total > 0 ? ( $fired / $total ) * 100 : 0;

                        $keys = array_keys( $floor_choices );
                        $at   = array_search( $floor, $keys, true );
                        if( $at === false ) $at = 0;

                        $flags = [];
                        if( isset( $mshield_fp[ $key ] ) )    $flags[] = 'fp';
                        if( isset( $mshield_pairs[ $key ] ) ) $flags[] = 'ov';
                        if( ! $enabled )                      $flags[] = 'off';
                        ?>

                        <?php /* The order screen's "Adjust setting" link lands on this id. */ ?>
                        <div class="mshield-checkrow<?php echo $enabled ? '' : ' is-off'; ?>" role="row"
                             id="mshield-sig-<?php echo esc_attr( $key ); ?>"
                             data-key="<?php echo esc_attr( $key ); ?>"
                             data-label="<?php echo esc_attr( strtolower( signals::label( $key ) ) ); ?>"
                             data-flags="<?php echo esc_attr( implode( ' ', $flags ) ); ?>">

                            <span class="ms-cell ms-cell-on" role="cell">
                                <input type="checkbox"
                                       name="mshield_sig_<?php echo esc_attr( $key ); ?>_enabled"
                                       value="yes" <?php checked( $enabled ); ?> data-check-on
                                       aria-label="<?php echo esc_attr( sprintf(
                                           /* translators: %s: check name. */
                                           __( '%s on', 'mighty-shield' ),
                                           signals::label( $key )
                                       ) ); ?>" />
                            </span>

                            <span class="ms-cell ms-cell-name" role="cell">
                                <span class="ms-name-line">
                                    <span class="mshield-sig-name"><?php echo esc_html( signals::label( $key ) ); ?></span>
                                    <?php if( $desc !== '' ) : ?>
                                        <span class="mshield-tip" tabindex="0" role="note"
                                              aria-label="<?php echo esc_attr( $desc ); ?>"
                                              data-tip="<?php echo esc_attr( $desc ); ?>">?</span>
                                    <?php endif; ?>
                                </span>
                                <?php if( isset( $mshield_fp[ $key ] ) ) : ?>
                                    <span class="mshield-hint">
                                        <?php
                                        printf(
                                            /* translators: 1: orders that turned out fine, 2: orders that turned out bad. */
                                            esc_html__( 'Fired on %1$s orders you approved and %2$s that went bad, in 90 days.', 'mighty-shield' ),
                                            esc_html( number_format_i18n( $mshield_fp[ $key ]['good'] ) ),
                                            esc_html( number_format_i18n( $mshield_fp[ $key ]['bad'] ) )
                                        );
                                        ?>
                                    </span>
                                <?php endif; ?>
                                <?php if( isset( $mshield_pairs[ $key ] ) ) : ?>
                                    <?php foreach( $mshield_pairs[ $key ] as $mshield_pair ) : ?>
                                        <span class="mshield-hint">
                                            <?php
                                            printf(
                                                /* translators: 1: the other check's name, 2: number of orders. */
                                                esc_html__( 'Fires with %1$s on %2$s orders: one fact counted twice.', 'mighty-shield' ),
                                                '<a href="#mshield-sig-' . esc_attr( $mshield_pair['other'] ) . '">' . esc_html( signals::label( $mshield_pair['other'] ) ) . '</a>',
                                                esc_html( number_format_i18n( $mshield_pair['together'] ) )
                                            );
                                            ?>
                                        </span>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </span>

                            <span class="ms-cell ms-cell-cost" role="cell">
                                <input type="number" step="1" min="-100" max="100"
                                       name="mshield_sig_<?php echo esc_attr( $key ); ?>_weight"
                                       value="<?php echo esc_attr( $weight ); ?>" data-check-cost
                                       aria-label="<?php echo esc_attr( sprintf(
                                           /* translators: %s: check name. */
                                           __( 'Trust cost for %s', 'mighty-shield' ),
                                           signals::label( $key )
                                       ) ); ?>" />
                                <?php /* What the number does, in the number's own words. The
                                         script keeps this in step as the value is typed. */ ?>
                                <span class="mshield-hint" data-check-effect><?php
                                    if( $weight < 0 ) {
                                        esc_html_e( 'earns trust back', 'mighty-shield' );
                                    } elseif( (float) $weight === 0.0 ) {
                                        esc_html_e( 'no rating', 'mighty-shield' );
                                    } else {
                                        esc_html_e( 'loses trust', 'mighty-shield' );
                                    }
                                ?></span>
                            </span>

                            <span class="ms-cell ms-cell-floor" role="cell">
                                <?php /* A stepper rather than a select, so the value can carry
                                         its level's colour. The hidden input is what posts, so a
                                         browser with no script still saves what was stored. The
                                         arrows are real buttons and the value is aria-live.
                                         Stepping clamps at both ends rather than wrapping. */ ?>
                                <div class="mshield-stepper" role="group"
                                     aria-label="<?php echo esc_attr( sprintf(
                                         /* translators: %s: signal name. */
                                         __( 'Force level for %s', 'mighty-shield' ),
                                         signals::label( $key )
                                     ) ); ?>"
                                     data-choices="<?php echo esc_attr( wp_json_encode( $floor_choices ) ); ?>">

                                    <button type="button" class="ms-step is-down"
                                            aria-label="<?php esc_attr_e( 'Less severe', 'mighty-shield' ); ?>"
                                            <?php disabled( $at === 0 ); ?>>
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                                             stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                            <path d="M15 6l-6 6 6 6"></path>
                                        </svg>
                                    </button>

                                    <span class="ms-value s-<?php echo esc_attr( $floor ); ?>" aria-live="polite">
                                        <?php echo esc_html( $floor_choices[ $floor ] ?? $floor_choices['none'] ); ?>
                                    </span>

                                    <button type="button" class="ms-step is-up"
                                            aria-label="<?php esc_attr_e( 'More severe', 'mighty-shield' ); ?>"
                                            <?php disabled( $at === count( $keys ) - 1 ); ?>>
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                                             stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                            <path d="M9 6l6 6-6 6"></path>
                                        </svg>
                                    </button>

                                    <input type="hidden" name="mshield_sig_<?php echo esc_attr( $key ); ?>_floor"
                                           value="<?php echo esc_attr( $floor ); ?>" />
                                </div>
                            </span>

                            <span class="ms-cell ms-cell-rate" role="cell">
                                <?php if( ! $sampled ) : ?>
                                    <span class="mshield-readout" title="<?php esc_attr_e( 'No rated orders in the last 30 days', 'mighty-shield' ); ?>">&mdash;</span>
                                <?php elseif( $fired === 0 ) : ?>
                                    <span class="mshield-readout" title="<?php esc_attr_e( 'Has not fired in the last 30 days', 'mighty-shield' ); ?>"><?php esc_html_e( 'never', 'mighty-shield' ); ?></span>
                                <?php else :
                                    $tone  = $rate >= 50 ? 'is-danger' : ( $rate >= 15 ? 'is-warn' : '' );
                                    $title = sprintf(
                                        /* translators: 1: number of orders it fired on, 2: number of orders rated. */
                                        __( 'Fired on %1$s of the %2$s orders rated in the last 30 days', 'mighty-shield' ),
                                        number_format_i18n( $fired ),
                                        number_format_i18n( $total )
                                    );
                                    if( $rate >= 50 ) $title .= '. ' . __( 'Fires on most orders, so probably too noisy to be worth its cost.', 'mighty-shield' );
                                    ?>
                                    <span class="mshield-readout <?php echo esc_attr( $tone ); ?>" title="<?php echo esc_attr( $title ); ?>">
                                        <?php echo esc_html( number_format_i18n( $rate, 1 ) ); ?>%
                                        <?php if( $rate >= 50 ) : ?><b class="ms-noisy" aria-hidden="true">!</b><?php endif; ?>
                                    </span>
                                <?php endif; ?>
                            </span>

                            <span class="ms-cell ms-cell-more" role="cell">
                                <?php if( ! empty( $fields ) ) : ?>
                                    <button type="button" class="ms-caret" data-check-more aria-expanded="false"
                                            aria-label="<?php echo esc_attr( sprintf(
                                                /* translators: %s: check name. */
                                                __( 'More settings for %s', 'mighty-shield' ),
                                                signals::label( $key )
                                            ) ); ?>">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                                             stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                            <path d="M6 9l6 6 6-6"></path>
                                        </svg>
                                    </button>
                                <?php endif; ?>
                            </span>

                            <?php if( ! empty( $fields ) ) : ?>
                                <?php /* A native <details>, so it opens without script; the caret
                                         above toggles the same element when script is present. */ ?>
                                <details class="ms-row-more" data-check-details>
                                    <summary><?php esc_html_e( 'More settings', 'mighty-shield' ); ?></summary>
                                    <div class="mshield-sig-config">
                                        <?php foreach( $fields as $field ) :
                                            $opt = $field['option'];
                                            $val = settings::get( $opt );

                                            // radios() emits its own <label> per bubble, and a label
                                            // inside a label breaks click targeting, so that type gets
                                            // a div wrapper instead.
                                            $tag = $field['type'] === 'radios' ? 'div' : 'label';
                                            $cls = 'mshield-sig-field';
                                            if( $field['type'] === 'check' )  $cls .= ' is-toggle';
                                            if( $field['type'] === 'radios' ) $cls .= ' is-radios';
                                            if( ! empty( $field['stack'] ) ) $cls .= ' is-stacked';
                                            ?>
                                            <<?php echo $tag; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $tag is 'div' or 'label', set above ?> class="<?php echo esc_attr( $cls ); ?>">
                                                <span><?php echo esc_html( $field['label'] ); ?></span>

                                                <?php if( $field['type'] === 'radios' ) : ?>
                                                    <?php admin_page::radios( $opt, $field['choices'], $val ); ?>

                                                <?php elseif( $field['type'] === 'check' ) : ?>
                                                    <input type="checkbox" name="<?php echo esc_attr( $opt ); ?>" value="yes" <?php checked( $val === 'yes' ); ?> />

                                                <?php elseif( $field['type'] === 'number' ) : ?>
                                                    <input type="number" name="<?php echo esc_attr( $opt ); ?>"
                                                           value="<?php echo esc_attr( $val ); ?>"
                                                           min="<?php echo esc_attr( $field['min'] ?? 0 ); ?>"
                                                           max="<?php echo esc_attr( $field['max'] ?? 100000 ); ?>" />

                                                <?php elseif( $field['type'] === 'select' ) : ?>
                                                    <select name="<?php echo esc_attr( $opt ); ?>">
                                                        <?php foreach( $field['choices'] as $cv => $cl ) : ?>
                                                            <option value="<?php echo esc_attr( $cv ); ?>" <?php selected( $val, $cv ); ?>>
                                                                <?php echo esc_html( $cl ); ?>
                                                            </option>
                                                        <?php endforeach; ?>
                                                    </select>

                                                <?php elseif( $field['type'] === 'textarea' ) : ?>
                                                    <textarea name="<?php echo esc_attr( $opt ); ?>" rows="3"><?php echo esc_textarea( $val ); ?></textarea>

                                                <?php elseif( $field['type'] === 'password' ) : ?>
                                                    <input type="password" name="<?php echo esc_attr( $opt ); ?>" value=""
                                                           placeholder="<?php echo $val !== '' ? esc_attr__( 'saved, leave blank to keep', 'mighty-shield' ) : ''; ?>"
                                                           autocomplete="off" />

                                                <?php else : ?>
                                                    <input type="text" name="<?php echo esc_attr( $opt ); ?>" value="<?php echo esc_attr( $val ); ?>" />
                                                <?php endif; ?>
                                            </<?php echo $tag; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $tag is 'div' or 'label', set above ?>>
                                        <?php endforeach; ?>

                                        <?php /* An action, not a setting, so it is called here rather
                                                 than added to signals::SETTINGS, where the group save
                                                 would write null over it. */ ?>
                                        <?php if( $key === 'address_unverified' ) : ?>
                                            <div class="mshield-sig-action">
                                                <?php admin_page::test_button( 'smarty', __( 'Tests the saved Auth ID and token. Save first. Costs one lookup.', 'mighty-shield' ) ); ?>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </details>
                            <?php endif; ?>

                        </div>

                    <?php endforeach; ?>

                </div>

            </div>

        <?php endforeach; ?>

    </div>

    <?php /* The save bar: static at the foot of the form, and pinned to the
             bottom of the window by the script once something has changed. */ ?>
    <div class="mshield-savebar" id="mshield-savebar">
        <span class="ms-savebar-note" data-savebar-note aria-live="polite"></span>
        <span class="mshield-spacer"></span>
        <button type="submit" class="mshield-btn is-primary"><?php esc_html_e( 'Save', 'mighty-shield' ); ?></button>
    </div>

</form>
