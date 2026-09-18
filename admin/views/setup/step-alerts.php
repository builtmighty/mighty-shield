<?php
/**
 * Setup step: where alerts go.
 *
 * Small, but it decides whether anyone finds out when a service MightyShield
 * depends on quietly stops working. Several of this plugin's worst failures were
 * only ever visible in an email nobody had configured a recipient for.
 *
 * @package MightyShield
 * @since   2.0.2
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Admin\setup_wizard;
use MightyShield\Includes\settings;

$mshield_notify = settings::get( 'mshield_ai_notify_admin' ) === 'yes';
$mshield_list   = settings::get( 'mshield_ai_notify_emails' );

setup_wizard::form_open( 'alerts' );
?>

<h1 class="mshield-setup-title"><?php esc_html_e( 'Who should hear about it?', 'mighty-shield' ); ?></h1>

<p class="mshield-setup-lede">
    <?php esc_html_e( 'MightyShield emails you when something needs a person: an order held for review, or one of the services it relies on failing. These are rare and they are not marketing.', 'mighty-shield' ); ?>
</p>

<table class="form-table" role="presentation">

    <tr>
        <th scope="row"><?php esc_html_e( 'Send alerts', 'mighty-shield' ); ?></th>
        <td>
            <label>
                <input type="hidden" name="mshield_ai_notify_admin" value="no" />
                <input type="checkbox" name="mshield_ai_notify_admin" value="yes" <?php checked( $mshield_notify ); ?> />
                <?php esc_html_e( 'Email me when MightyShield needs attention', 'mighty-shield' ); ?>
            </label>
        </td>
    </tr>

    <tr>
        <th scope="row"><?php esc_html_e( 'Send to', 'mighty-shield' ); ?></th>
        <td>
            <input type="text" name="mshield_ai_notify_emails" class="regular-text"
                   value="<?php echo esc_attr( $mshield_list ); ?>"
                   placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" />
            <p class="description">
                <?php
                printf(
                    /* translators: %s: the address alerts currently go to. */
                    esc_html__( 'Separate several with commas. Left empty, they go to %s, the site administrator address.', 'mighty-shield' ),
                    esc_html( get_option( 'admin_email' ) )
                );
                ?>
            </p>
        </td>
    </tr>

</table>

<div class="mshield-banner">
    <div>
        <strong><?php esc_html_e( 'What actually arrives:', 'mighty-shield' ); ?></strong>
        <?php esc_html_e( 'an order held for you to look at, an address-verification or AI service that has stopped responding, or a bot challenge that has started refusing everybody. Each of the last two is sent at most once a day.', 'mighty-shield' ); ?>
    </div>
</div>

<?php
setup_wizard::render_controls( 'alerts' );
echo '</form>';
