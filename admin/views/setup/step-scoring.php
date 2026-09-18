<?php
/**
 * Setup step: how strict the scoring should be.
 *
 * One choice that sets around forty individual trust costs, so a merchant who
 * does not want to make forty judgement calls does not have to make any.
 *
 * @package MightyShield
 * @since   2.0.2
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Admin\admin_page;
use MightyShield\Admin\setup_wizard;
use MightyShield\Includes\scoring_profiles;

$mshield_copy    = scoring_profiles::copy();
$mshield_current = scoring_profiles::current();

// A fresh install reads as Balanced, which is the intended landing place. The
// wizard is also reachable later, and a store that has hand-tuned rows since
// then must be warned before a profile overwrites them.
$mshield_tuned = scoring_profiles::hand_tuned_count();

$mshield_choices = [];
foreach( scoring_profiles::PROFILES as $mshield_key => $mshield_spec ) {
    $mshield_choices[ $mshield_key ] = $mshield_copy[ $mshield_key ]['label'];
}

setup_wizard::form_open( 'scoring' );
?>

<h1 class="mshield-setup-title"><?php esc_html_e( 'How strict should the scoring be?', 'mighty-shield' ); ?></h1>

<p class="mshield-setup-lede">
    <?php esc_html_e( 'Each check that trips takes a set number of points off an order. This picks all of those numbers at once. Pick whichever sounds like your store, and change any individual one later.', 'mighty-shield' ); ?>
</p>

<?php
// Real radio inputs, not the sliding switch used on the Scoring tab: that
// control is built from links, which cannot carry a value through a form post.
admin_page::radios( 'mshield_profile', $mshield_choices, $mshield_current );
?>

<div class="mshield-setup-blurbs">
    <?php foreach( $mshield_choices as $mshield_key => $mshield_label ) : ?>
        <p class="mshield-hint">
            <strong><?php echo esc_html( $mshield_label ); ?></strong>
            &mdash; <?php echo esc_html( $mshield_copy[ $mshield_key ]['blurb'] ); ?>
        </p>
    <?php endforeach; ?>
</div>

<?php if( $mshield_tuned > 0 ) : ?>
    <div class="mshield-banner is-danger">
        <div>
            <strong><?php esc_html_e( 'This will overwrite changes you have made.', 'mighty-shield' ); ?></strong>
            <?php
            printf(
                esc_html(
                    /* translators: %d: number of hand-tuned rows. */
                    _n(
                        'One trust cost on the Scoring tab has been changed by hand. Choosing a profile here replaces it.',
                        '%d trust costs on the Scoring tab have been changed by hand. Choosing a profile here replaces them.',
                        $mshield_tuned,
                        'mighty-shield'
                    )
                ),
                (int) $mshield_tuned
            );
            ?>
            <?php esc_html_e( 'Skip this step to leave them alone.', 'mighty-shield' ); ?>
        </div>
    </div>
<?php endif; ?>

<p class="mshield-hint">
    <?php esc_html_e( 'None of these refuse an order on their own. They decide how far an order falls, and what happens at each depth is the next thing you will see.', 'mighty-shield' ); ?>
</p>

<?php
setup_wizard::render_controls( 'scoring' );
echo '</form>';
