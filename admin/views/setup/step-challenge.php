<?php
/**
 * Setup step: the bot challenge.
 *
 * Optional, and skippable in one click. It needs an account with a third party,
 * which is more than a first run should insist on -- but it is also the cheapest
 * thing a store can do against card testing, so it is worth the page.
 *
 * @package MightyShield
 * @since   2.0.2
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Admin\admin_page;
use MightyShield\Admin\setup_wizard;
use MightyShield\Includes\settings;
use MightyShield\Protection\challenge;
use MightyShield\Protection\captcha;

$mshield_provider = settings::get( 'mshield_captcha_provider' );
$mshield_has_site = settings::get( 'mshield_captcha_site_key' ) !== '';
$mshield_has_sec  = settings::get( 'mshield_captcha_secret_key' ) !== '';

$mshield_labels = [
    'login'        => __( 'Signing in', 'mighty-shield' ),
    'register'     => __( 'Creating an account', 'mighty-shield' ),
    'lostpassword' => __( 'Resetting a password', 'mighty-shield' ),
    'comment'      => __( 'Leaving a comment', 'mighty-shield' ),
];

setup_wizard::form_open( 'challenge' );
?>

<h1 class="mshield-setup-title"><?php esc_html_e( 'Turn away the bots before they reach checkout', 'mighty-shield' ); ?></h1>

<p class="mshield-setup-lede">
    <?php esc_html_e( 'Card testing is someone running stolen card numbers through your checkout to find the ones that still work. It is automated, it is the most common thing that happens to a small store, and a bot challenge stops most of it for free.', 'mighty-shield' ); ?>
</p>

<p class="mshield-hint">
    <?php esc_html_e( 'You need a free account with Cloudflare or Google. If you would rather do this later, skip the step: everything else in MightyShield works without it.', 'mighty-shield' ); ?>
</p>

<table class="form-table" role="presentation">

    <tr>
        <th scope="row"><?php esc_html_e( 'Provider', 'mighty-shield' ); ?></th>
        <td>
            <?php
            admin_page::radios( 'mshield_captcha_provider', [
                'off'          => __( 'Not now', 'mighty-shield' ),
                'turnstile'    => __( 'Cloudflare Turnstile', 'mighty-shield' ),
                'recaptcha_v3' => __( 'Google reCAPTCHA v3', 'mighty-shield' ),
            ], $mshield_provider );
            ?>
            <p class="description">
                <?php esc_html_e( 'Both are free. Turnstile does not track visitors, which is the usual reason to prefer it.', 'mighty-shield' ); ?>
            </p>
        </td>
    </tr>

    <tr>
        <th scope="row"><?php esc_html_e( 'Site key', 'mighty-shield' ); ?></th>
        <td>
            <input type="text" name="mshield_captcha_site_key" class="regular-text" value=""
                   placeholder="<?php echo $mshield_has_site ? esc_attr__( 'saved — leave blank to keep', 'mighty-shield' ) : ''; ?>" />
            <p class="description">
                <?php esc_html_e( 'Turnstile: your Cloudflare dashboard. reCAPTCHA: the Google admin console, and it must be a v3 key.', 'mighty-shield' ); ?>
            </p>
        </td>
    </tr>

    <tr>
        <th scope="row"><?php esc_html_e( 'Secret key', 'mighty-shield' ); ?></th>
        <td>
            <input type="password" name="mshield_captcha_secret_key" class="regular-text" value="" autocomplete="off"
                   placeholder="<?php echo $mshield_has_sec ? esc_attr__( 'saved — leave blank to keep', 'mighty-shield' ) : ''; ?>" />
            <p class="description">
                <?php esc_html_e( 'From the same place, and from the same site as the key above. A key from one site with a secret from another is rejected on every request.', 'mighty-shield' ); ?>
            </p>
        </td>
    </tr>

    <tr>
        <th scope="row"><?php esc_html_e( 'Where to ask', 'mighty-shield' ); ?></th>
        <td>
            <?php /* Driven off the canonical map, so a surface added later turns up
                     here without anybody remembering to come back. */ ?>
            <?php foreach( challenge::SURFACES as $mshield_surface => $mshield_option ) : ?>
                <p>
                    <label>
                        <input type="hidden" name="<?php echo esc_attr( $mshield_option ); ?>" value="no" />
                        <input type="checkbox" name="<?php echo esc_attr( $mshield_option ); ?>" value="yes"
                               <?php checked( settings::get( $mshield_option ) === 'yes' ); ?> />
                        <?php echo esc_html( $mshield_labels[ $mshield_surface ] ?? $mshield_surface ); ?>
                    </label>
                </p>
            <?php endforeach; ?>

            <p class="description">
                <?php esc_html_e( 'Signing in is off by default, and it is worth leaving that way until you have seen the rest working. If a challenge ever fails to load on that form, everybody is locked out of the site including you.', 'mighty-shield' ); ?>
            </p>
        </td>
    </tr>

</table>

<div class="mshield-banner">
    <div>
        <?php esc_html_e( 'Checkout is always protected once a provider is set. These four are the account pages, which are separate because a mistake on them locks people out of their accounts rather than out of a purchase.', 'mighty-shield' ); ?>
    </div>
</div>

<?php
setup_wizard::render_controls( 'challenge' );
echo '</form>';
