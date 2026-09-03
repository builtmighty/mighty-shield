<?php
/**
 * Scoring tab.
 *
 * Every signal in one table: what it costs, whether it can force a risk level on its
 * own, and — the part that makes this tunable rather than guesswork — how often
 * it has actually fired on real traffic.
 *
 * Uses .mshield-section and .mshield-table so it inherits the app's own
 * palette. Core's .widefat paints its own greys and would read as a foreign
 * element here, and would be unreadable in dark mode.
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
    $floor_choices[ $level_key ] = $level['label'];
}

$days    = 30;
$stats   = db::get_signal_stats( $days );
$total   = db::get_risk_count( $days );
$sampled = $total > 0;
?>

<?php
// The profile switcher sits outside the settings form below, deliberately.
// Picking a profile rewrites every trust cost at once, so it is an action that
// applies on click, not a field that waits for Save at the bottom of a long
// page. Same pattern as the protection control on the Dashboard.
$mshield_now   = scoring_profiles::current();
$mshield_copy  = scoring_profiles::copy();
$mshield_tuned = $mshield_now === 'custom';

// How many rows this merchant has tuned by hand. Switching overwrites them, so
// the links carry the count and the confirm dialog uses it. Zero unless Custom.
$mshield_dirty = scoring_profiles::hand_tuned_count();
?>

<div class="mshield-section">

    <h2><?php esc_html_e( 'Scoring Profile', 'mighty-shield' ); ?></h2>

    <p class="description">
        <?php esc_html_e( 'Set every trust cost below at once. Pick the one that sounds like your store, then change any individual row that is catching customers you want to keep.', 'mighty-shield' ); ?>
    </p>

    <?php /* The same sliding switch the Dashboard uses for protection state,
             widened to four text labels. The knob carries the colour of what
             the profile does, borrowed from the risk levels. */ ?>
    <div class="mshield-tri is-full at-<?php echo esc_attr( $mshield_now ); ?>"
         role="radiogroup" aria-label="<?php esc_attr_e( 'Scoring profile', 'mighty-shield' ); ?>">

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
    // Built from the ladder and the CONFIGURED thresholds, not from literals.
    // These ranges were hardcoded strings that happened to match the defaults,
    // so the moment a threshold was edited on Blocking this scale lied; and the
    // labels still read Detained/Challenged/Monitored, retired two versions
    // ago, while Blocking printed High/Elevated/Low for the same levels.
    //
    // The geometry and the bounds both live on trust_badge now, so the order
    // panel draws its dial from the same code and the two cannot drift.
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

                <?php echo esc_html( $level['label'] ); ?>

                <?php
                /* The dial above already shows the range, so restating "of 100"
                   under every card is noise. Banned has no range at all -- it is
                   reachable only through a signal floor -- so that one still
                   needs saying. */
                if( ! ( $has && $to >= $from ) ) : ?>
                    <b><?php esc_html_e( 'signal only', 'mighty-shield' ); ?></b>
                <?php endif; ?>
            </span>
        <?php endforeach; ?>
    </div>

</div>

<form method="post" action="options.php">
    <?php settings_fields( 'mshield_scoring' ); ?>

    <?php foreach( signals::GROUPS as $group_key => $group_label ) : ?>

        <div class="mshield-section">

            <h2><?php echo esc_html( $group_label ); ?></h2>

            <table class="mshield-table">
                <thead>
                    <tr>
                        <th style="width:46px;"><?php esc_html_e( 'On', 'mighty-shield' ); ?></th>
                        <th><?php esc_html_e( 'Signal', 'mighty-shield' ); ?></th>
                        <th style="width:110px;"><?php esc_html_e( 'Trust cost', 'mighty-shield' ); ?></th>
                        <th style="width:165px;"><?php esc_html_e( 'Force level', 'mighty-shield' ); ?></th>
                        <th style="width:190px;"><?php esc_html_e( 'How often it fires', 'mighty-shield' ); ?></th>
                    </tr>
                </thead>
                <tbody>

                <?php foreach( signals::in_group( $group_key ) as $key ) :

                    $weight  = signals::weight( $key );
                    $floor   = signals::floor( $key );
                    $enabled = signals::is_enabled( $key );

                    $fired = isset( $stats[ $key ] ) ? (int) $stats[ $key ]['count'] : 0;
                    $rate  = $total > 0 ? ( $fired / $total ) * 100 : 0;
                    ?>

                    <?php /* The order screen links straight to a signal's row when it
                             fires, so a merchant who thinks it is catching real
                             customers can adjust it without going hunting. */ ?>
                    <tr id="mshield-sig-<?php echo esc_attr( $key ); ?>">
                        <td>
                            <input type="checkbox"
                                   name="mshield_sig_<?php echo esc_attr( $key ); ?>_enabled"
                                   value="yes" <?php checked( $enabled ); ?> />
                        </td>

                        <td>
                            <span class="mshield-sig-name"><?php echo esc_html( signals::label( $key ) ); ?></span>
                            <?php $desc = signals::description( $key ); ?>
                            <?php if( $desc !== '' ) : ?>
                                <?php /* tabindex + aria-label so this is reachable by keyboard and
                                          screen readers, not only by a mouse. */ ?>
                                <span class="mshield-tip" tabindex="0" role="note"
                                      aria-label="<?php echo esc_attr( $desc ); ?>"
                                      data-tip="<?php echo esc_attr( $desc ); ?>">?</span>
                            <?php endif; ?>

                            <?php $fields = signals::fields( $key ); ?>
                            <?php if( ! empty( $fields ) ) : ?>
                                <div class="mshield-sig-config">
                                    <?php foreach( $fields as $field ) :
                                        $opt = $field['option'];
                                        $val = settings::get( $opt );
                                        ?>
                                        <?php
                                        // radios() emits its own <label> per bubble, and a
                                        // label inside a label breaks click targeting -- so
                                        // that type gets a div wrapper instead.
                                        $tag = $field['type'] === 'radios' ? 'div' : 'label';
                                        $cls = 'mshield-sig-field';
                                        if( $field['type'] === 'check' )  $cls .= ' is-toggle';
                                        if( $field['type'] === 'radios' ) $cls .= ' is-radios';
                                        ?>
                                        <<?php echo $tag; ?> class="<?php echo esc_attr( $cls ); ?>">
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
                                                       placeholder="<?php echo $val !== '' ? esc_attr__( 'saved. Leave blank to keep', 'mighty-shield' ) : ''; ?>"
                                                       autocomplete="off" />

                                            <?php else : ?>
                                                <input type="text" name="<?php echo esc_attr( $opt ); ?>" value="<?php echo esc_attr( $val ); ?>" />
                                            <?php endif; ?>
                                        </<?php echo $tag; ?>>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </td>

                        <td>
                            <input type="number" step="1" min="-100" max="100"
                                   name="mshield_sig_<?php echo esc_attr( $key ); ?>_weight"
                                   value="<?php echo esc_attr( $weight ); ?>" />
                            <?php if( $weight < 0 ) : ?>
                                <span class="mshield-hint"><?php esc_html_e( 'earns trust back', 'mighty-shield' ); ?></span>
                            <?php endif; ?>
                        </td>

                        <td>
                            <?php
                            $keys = array_keys( $floor_choices );
                            $at   = array_search( $floor, $keys, true );
                            if( $at === false ) $at = 0;
                            ?>
                            <?php /* A stepper rather than a select, so the value can carry
                                     its level's colour. The hidden input is what actually
                                     posts, so a browser with no JS still saves whatever was
                                     stored -- it just cannot change it here.

                                     The arrows are real buttons, so they answer the keyboard,
                                     and the value is aria-live so a screen reader hears it
                                     change. Stepping CLAMPS at both ends rather than wrapping:
                                     wrapping would put "Banned" one keypress from "Scoring
                                     only", which is a long way to travel by accident. */ ?>
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
                        </td>

                        <td>
                            <?php if( ! $sampled ) : ?>
                                <span class="mshield-pill">&mdash;</span>
                            <?php elseif( $fired === 0 ) : ?>
                                <span class="mshield-pill"><?php esc_html_e( 'never', 'mighty-shield' ); ?></span>
                            <?php else :
                                $tone = $rate >= 50 ? 'is-danger' : ( $rate >= 15 ? 'is-warn' : 'is-ok' ); ?>
                                <span class="mshield-pill <?php echo esc_attr( $tone ); ?>">
                                    <?php echo esc_html( number_format_i18n( $rate, 1 ) ); ?>%
                                    (<?php echo esc_html( number_format_i18n( $fired ) ); ?>)
                                </span>
                                <?php if( $rate >= 50 ) : ?>
                                    <span class="mshield-hint">
                                        <?php esc_html_e( 'Fires on most orders, so probably too noisy to be worth its cost.', 'mighty-shield' ); ?>
                                    </span>
                                <?php endif; ?>
                            <?php endif; ?>
                        </td>
                    </tr>

                <?php endforeach; ?>

                </tbody>
            </table>

        </div>

    <?php endforeach; ?>

    <div class="mshield-section">
        <?php submit_button(); ?>
    </div>

</form>
