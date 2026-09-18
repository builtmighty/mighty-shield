<?php
/**
 * Setup step: observe or enforce.
 *
 * The decision the whole wizard has been building to, and the only one here that
 * can turn a real customer away. It is last on purpose, and it defaults to
 * observing on purpose.
 *
 * @package MightyShield
 * @since   2.0.2
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Admin\admin_page;
use MightyShield\Admin\setup_wizard;

$mshield_now      = admin_page::protection_state();
$mshield_states   = admin_page::protection_states();
$mshield_conflict = admin_page::checkout_conflict();

$mshield_choices = [
    'observing' => $mshield_states['observing']['label'],
    'active'    => $mshield_states['active']['label'],
    'disabled'  => $mshield_states['disabled']['label'],
];

setup_wizard::form_open( 'protection' );
?>

<h1 class="mshield-setup-title"><?php esc_html_e( 'Watch first, or act now?', 'mighty-shield' ); ?></h1>

<p class="mshield-setup-lede">
    <?php esc_html_e( 'Everything so far decides how orders are rated. This decides whether anything is done about the rating.', 'mighty-shield' ); ?>
</p>

<?php admin_page::radios( 'mshield_state', $mshield_choices, $mshield_now['key'] ); ?>

<div class="mshield-setup-blurbs">

    <p class="mshield-hint">
        <strong><?php echo esc_html( $mshield_states['observing']['label'] ); ?></strong>
        &mdash; <?php esc_html_e( 'Every order is rated, recorded and shown to you, and none of them are changed. Nothing a customer does is affected. This is where we suggest starting.', 'mighty-shield' ); ?>
    </p>

    <p class="mshield-hint">
        <strong><?php echo esc_html( $mshield_states['active']['label'] ); ?></strong>
        &mdash; <?php esc_html_e( 'The rating is acted on: risky orders are held for review, and the worst are refused at checkout. Real money and real customers are affected from the next order onwards.', 'mighty-shield' ); ?>
    </p>

    <p class="mshield-hint">
        <strong><?php echo esc_html( $mshield_states['disabled']['label'] ); ?></strong>
        &mdash; <?php esc_html_e( 'Nothing is checked at all.', 'mighty-shield' ); ?>
    </p>

</div>

<div class="mshield-banner">
    <div>
        <strong><?php esc_html_e( 'A week of observing costs nothing and tells you a lot.', 'mighty-shield' ); ?></strong>
        <?php esc_html_e( 'Let it watch your real orders, then look at the Dashboard and the Fraud Review queue. If the orders it would have held are the ones you would have held, switch it on. If it is flagging your regulars, lower the strictness first. That switch is on every MightyShield page.', 'mighty-shield' ); ?>
    </div>
</div>

<?php if( $mshield_conflict ) : ?>
    <div class="mshield-banner is-danger">
        <div>
            <strong><?php esc_html_e( 'Your checkout is currently closed to customers.', 'mighty-shield' ); ?></strong>
            <?php esc_html_e( 'MightyShield ships with its firewall set to allow only listed addresses, and the list holds your server and nothing else. On a store using the newer block checkout, that turns every shopper away before they can pay. Nothing you have chosen caused this; it is the default, and it is wrong for your store.', 'mighty-shield' ); ?>
            <p>
                <label>
                    <input type="checkbox" name="mshield_fix_checkout" value="yes" checked="checked" />
                    <strong><?php esc_html_e( 'Fix this: block only the addresses MightyShield has judged, and let everyone else through', 'mighty-shield' ); ?></strong>
                </label>
            </p>
        </div>
    </div>
<?php endif; ?>

<?php
setup_wizard::render_controls( 'protection' );
echo '</form>';
