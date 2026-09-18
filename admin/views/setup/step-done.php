<?php
/**
 * Setup step: what was set, and what deliberately was not.
 *
 * Reads the real settings back rather than remembering what the merchant was
 * shown, so it cannot claim something is on when the save did not take.
 *
 * @package MightyShield
 * @since   2.0.2
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Admin\admin_page;
use MightyShield\Admin\setup_wizard;
use MightyShield\Includes\settings;
use MightyShield\Includes\scoring_profiles;
use MightyShield\Protection\captcha;

$mshield_now     = admin_page::protection_state();
$mshield_profile = scoring_profiles::current();
$mshield_ready   = captcha::is_ready();

$mshield_rows = [
    [
        'label' => __( 'Protection', 'mighty-shield' ),
        'value' => $mshield_now['label'],
        'tone'  => $mshield_now['pill'],
        'where' => 'dashboard',
    ],
    [
        'label' => __( 'Scoring', 'mighty-shield' ),
        'value' => scoring_profiles::label( $mshield_profile ),
        'tone'  => 'is-muted',
        'where' => 'scoring',
    ],
    [
        'label' => __( 'Bot challenge', 'mighty-shield' ),
        'value' => $mshield_ready
            ? sprintf(
                /* translators: %s: provider name. */
                __( 'On, using %s', 'mighty-shield' ),
                settings::get( 'mshield_captcha_provider' ) === 'turnstile'
                    ? __( 'Cloudflare Turnstile', 'mighty-shield' )
                    : __( 'Google reCAPTCHA', 'mighty-shield' )
            )
            : __( 'Not set up', 'mighty-shield' ),
        'tone'  => $mshield_ready ? 'is-ok' : 'is-muted',
        'where' => 'blocking',
    ],
    [
        'label' => __( 'Alerts go to', 'mighty-shield' ),
        'value' => implode( ', ', settings::notification_recipients() ),
        'tone'  => 'is-muted',
        'where' => 'ai',
    ],
];

setup_wizard::form_open( 'done' );
?>

<h1 class="mshield-setup-title"><?php esc_html_e( 'That is everything', 'mighty-shield' ); ?></h1>

<p class="mshield-setup-lede">
    <?php esc_html_e( 'Here is where you have landed. Every line has a tab behind it, and none of it is permanent.', 'mighty-shield' ); ?>
</p>

<table class="mshield-table mshield-setup-summary">
    <tbody>
        <?php foreach( $mshield_rows as $mshield_row ) : ?>
            <tr>
                <th scope="row"><?php echo esc_html( $mshield_row['label'] ); ?></th>
                <td>
                    <span class="mshield-pill <?php echo esc_attr( $mshield_row['tone'] ); ?>">
                        <span class="dot"></span><?php echo esc_html( $mshield_row['value'] ); ?>
                    </span>
                </td>
                <td class="ms-where">
                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=' . $mshield_row['where'] ) ); ?>">
                        <?php esc_html_e( 'Change', 'mighty-shield' ); ?>
                    </a>
                </td>
            </tr>
        <?php endforeach; ?>
    </tbody>
</table>

<?php if( $mshield_ready ) : ?>
    <div class="mshield-section">
        <h2><?php esc_html_e( 'Check the bot challenge works', 'mighty-shield' ); ?></h2>
        <p class="description">
            <?php esc_html_e( 'Open your sign-in page in a private window and sign in. If it goes through, the keys are right. If it does not, the Logs tab will now say exactly what the provider objected to.', 'mighty-shield' ); ?>
        </p>
    </div>
<?php endif; ?>

<div class="mshield-section">

    <h2><?php esc_html_e( 'Two things this setup left alone', 'mighty-shield' ); ?></h2>

    <p class="description">
        <?php esc_html_e( 'Both are optional, both cost money with a third party, and neither is worth stalling a first run over. They are there when you want them.', 'mighty-shield' ); ?>
    </p>

    <ul class="mshield-setup-extras">
        <li>
            <strong><?php esc_html_e( 'Address verification', 'mighty-shield' ); ?></strong>
            &mdash; <?php esc_html_e( 'checks a US billing address against real postal data, so a made-up address is caught before the order is taken.', 'mighty-shield' ); ?>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=scoring' ) ); ?>"><?php esc_html_e( 'Scoring tab', 'mighty-shield' ); ?></a>
        </li>
        <li>
            <strong><?php esc_html_e( 'AI review', 'mighty-shield' ); ?></strong>
            &mdash; <?php esc_html_e( 'asks a language model for a second opinion on the orders you are least sure about.', 'mighty-shield' ); ?>
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=mighty-shield&tab=ai' ) ); ?>"><?php esc_html_e( 'AI tab', 'mighty-shield' ); ?></a>
        </li>
    </ul>

</div>

<p class="mshield-hint">
    <?php
    printf(
        /* translators: %s: link to the documentation. */
        esc_html__( 'Everything MightyShield does, setting by setting, is written up in the %s.', 'mighty-shield' ),
        '<a href="' . esc_url( admin_url( 'admin.php?page=mighty-shield&tab=documentation' ) ) . '">' . esc_html__( 'documentation', 'mighty-shield' ) . '</a>'
    );
    ?>
</p>

<?php
setup_wizard::render_controls( 'done', false );
echo '</form>';
