<?php
/**
 * Firewall settings view.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\settings;
use MightyShield\Admin\admin_page;
?>

<form method="post" action="options.php">
    <?php settings_fields( 'mshield_firewall' ); ?>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'General', 'mighty-shield' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Enable MightyShield', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_enabled" value="no" />
                        <input type="checkbox" name="mshield_enabled" value="yes" <?php checked( settings::get( 'mshield_enabled' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Enable all MightyShield protections.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Store API Firewall', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Controls access to the WooCommerce Store API cart and checkout endpoints (/wc/store/v1/…). Choose the mode that matches your checkout.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Block Store API', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_block_store_api" value="no" />
                        <input type="checkbox" name="mshield_block_store_api" value="yes" <?php checked( settings::get( 'mshield_block_store_api' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Enable Store API access control.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Firewall Mode', 'mighty-shield' ); ?></th>
                <td>
                    <?php admin_page::radios( 'mshield_firewall_mode', [
                        'whitelist' => __( 'Classic checkout: block all non-allowlisted IPs', 'mighty-shield' ),
                        'blocklist' => __( 'Block/One-page checkout: allow shoppers, block only blocklisted IPs', 'mighty-shield' ),
                    ], settings::get( 'mshield_firewall_mode' ) ); ?>
                    <p class="description"><?php esc_html_e( 'Use "Classic checkout" only if real customers never use the Store API (shortcode/classic checkout). If your store uses the block-based Checkout, choose the block/one-page option so real shoppers are not blocked.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Block Checkout Protection', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Run the server-side fraud checks (email domain, order amount, address, ZIP/State, velocity, rate limit) on the block-based Checkout, which submits through the Store API. Front-end checks (honeypot, checkout timing, device fingerprint, CAPTCHA) still require classic/one-page checkout.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Enable Store API checks', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_store_api_checks" value="no" />
                        <input type="checkbox" name="mshield_store_api_checks" value="yes" <?php checked( settings::get( 'mshield_store_api_checks' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Apply the server-side fraud checks to block-based (Store API) checkout.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Log Settings', 'mighty-shield' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Log Retention', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_log_retention_days" value="<?php echo esc_attr( settings::get( 'mshield_log_retention_days' ) ); ?>" min="1" max="365" class="small-text" />
                    <?php esc_html_e( 'days', 'mighty-shield' ); ?>
                    <p class="description"><?php esc_html_e( 'Logs older than this will be automatically cleaned up daily.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <?php submit_button(); ?>
</form>
