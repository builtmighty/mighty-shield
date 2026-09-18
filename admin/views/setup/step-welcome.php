<?php
/**
 * Setup step: how MightyShield works.
 *
 * Explains only. The one page in the plugin that assumes the reader knows none
 * of its vocabulary, so it introduces the three ideas everything else is built
 * from -- signals, a trust rating, and a level with an action attached -- and
 * says plainly that nothing is being acted on yet.
 *
 * @package MightyShield
 * @since   2.0.2
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Admin\setup_wizard;
use MightyShield\Includes\risk_levels;

setup_wizard::form_open( 'welcome' );
?>

<h1 class="mshield-setup-title"><?php esc_html_e( 'MightyShield reads every order before you do', 'mighty-shield' ); ?></h1>

<p class="mshield-setup-lede">
    <?php esc_html_e( 'It takes about two minutes to set up. Nothing you choose here is permanent, and every one of these settings has its own tab afterwards.', 'mighty-shield' ); ?>
</p>

<div class="mshield-setup-steps">

    <div class="mshield-setup-idea">
        <span class="ms-num">1</span>
        <div>
            <strong><?php esc_html_e( 'Checks look at each order', 'mighty-shield' ); ?></strong>
            <p><?php esc_html_e( 'Around forty of them. Does the billing address exist. Has this card been declined here before. Did the checkout form get filled in faster than a person can type. Each one that trips is called a signal.', 'mighty-shield' ); ?></p>
        </div>
    </div>

    <div class="mshield-setup-idea">
        <span class="ms-num">2</span>
        <div>
            <strong><?php esc_html_e( 'Signals subtract from a trust rating', 'mighty-shield' ); ?></strong>
            <p><?php esc_html_e( 'Every order starts at 100. Each signal takes points off, and how many is yours to set. An order nobody can fault keeps its 100.', 'mighty-shield' ); ?></p>
        </div>
    </div>

    <div class="mshield-setup-idea">
        <span class="ms-num">3</span>
        <div>
            <strong><?php esc_html_e( 'The rating decides what happens', 'mighty-shield' ); ?></strong>
            <p><?php esc_html_e( 'The score lands in one of six bands, and each band has an action you choose: let it through, add a note for you, ask the shopper for 3-D Secure, hold it for review, or refuse it.', 'mighty-shield' ); ?></p>
        </div>
    </div>

</div>

<?php
/* The six bands, coloured from the same severity ramp the rest of the plugin
   uses, so the colours mean the same thing here as on an order. */
$mshield_tone = [
    risk_levels::TRUSTED  => 'is-ok',
    risk_levels::LOW      => 'is-ok',
    risk_levels::ELEVATED => 'is-warn',
    risk_levels::HIGH     => 'is-warn',
    risk_levels::REJECTED => 'is-danger',
    risk_levels::BANNED   => 'is-danger',
];
?>
<div class="mshield-setup-ladder">
    <?php foreach( risk_levels::LADDER as $mshield_key => $mshield_level ) : ?>
        <span class="mshield-pill <?php echo esc_attr( $mshield_tone[ $mshield_key ] ?? 'is-muted' ); ?>">
            <span class="dot"></span><?php echo esc_html( risk_levels::label( $mshield_key ) ); ?>
        </span>
    <?php endforeach; ?>
</div>

<div class="mshield-banner">
    <div>
        <strong><?php esc_html_e( 'Nothing is being acted on yet.', 'mighty-shield' ); ?></strong>
        <?php esc_html_e( 'MightyShield starts in observing mode: it rates and records orders and changes none of them. The last step of this setup is where you decide whether to go further, and it is fine to leave it observing for a week first.', 'mighty-shield' ); ?>
    </div>
</div>

<p class="mshield-hint">
    <?php
    printf(
        /* translators: %s: link to the documentation. */
        esc_html__( 'There is a fuller explanation in the %s whenever you want it.', 'mighty-shield' ),
        '<a href="' . esc_url( admin_url( 'admin.php?page=mighty-shield&tab=documentation#lifecycle' ) ) . '">' . esc_html__( 'documentation', 'mighty-shield' ) . '</a>'
    );
    ?>
</p>

<?php
setup_wizard::render_controls( 'welcome', false );
echo '</form>';
