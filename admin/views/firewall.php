<?php
/**
 * Firewall settings view.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\settings;
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
        <p class="description"><?php esc_html_e( 'Block non-whitelisted IPs from accessing WooCommerce Store API cart and checkout endpoints. Since this site uses classic checkout, real customers are not affected.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Block Store API', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_block_store_api" value="no" />
                        <input type="checkbox" name="mshield_block_store_api" value="yes" <?php checked( settings::get( 'mshield_block_store_api' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Block all non-whitelisted IP access to /wc/store/v1/cart and /wc/store/v1/checkout endpoints.', 'mighty-shield' ); ?>
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
