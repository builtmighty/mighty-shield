<?php
/**
 * The protection-state hero.
 *
 * Off, observing or active, and the control that changes it. Rendered directly
 * under the nav on every MightyShield tab by admin_page::shell_open(), because
 * whether the store is actually enforcing anything is the first thing somebody
 * needs to know on a page where they are about to change a setting -- not
 * something they have to go back to the Dashboard to check.
 *
 * Expects $now, $states, $state_now and $from, which render_hero() sets up.
 *
 * @package MightyShield
 * @since   2.0.1
 */

if( ! defined( 'WPINC' ) ) { die; }
?>

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
                    admin_url( 'admin.php?page=mighty-shield&mshield_set_state=' . $key
                        . ( ! empty( $from ) ? '&tab=' . $from : '' ) ),
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
