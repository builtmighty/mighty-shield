<?php
/**
 * Fraud Checks settings view.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\settings;
?>

<form method="post" action="options.php">
    <?php settings_fields( 'mshield_settings' ); ?>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Email Domain Blocking', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Block checkout attempts using disposable/temporary email services. A built-in list of ~160 domains is always active.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Additional Blocked Domains', 'mighty-shield' ); ?></th>
                <td>
                    <textarea name="mshield_blocked_email_domains" rows="10" class="large-text code"><?php echo esc_textarea( settings::get( 'mshield_blocked_email_domains' ) ); ?></textarea>
                    <p class="description"><?php esc_html_e( 'Enter one domain per line (e.g., spammer-domain.com). These are added to the built-in disposable email list.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Order Amount Validation', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Detect suspiciously small order amounts commonly used for card testing.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Minimum Order Amount', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_min_order_amount" value="<?php echo esc_attr( settings::get( 'mshield_min_order_amount' ) ); ?>" class="small-text" />
                    <p class="description"><?php esc_html_e( 'Orders below this amount will be flagged/blocked. Set to 0 to disable. Default: 1.00', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Action on Suspicious Amount', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_suspicious_amount_action">
                        <option value="flag" <?php selected( settings::get( 'mshield_suspicious_amount_action' ), 'flag' ); ?>><?php esc_html_e( 'Flag (add order note)', 'mighty-shield' ); ?></option>
                        <option value="block" <?php selected( settings::get( 'mshield_suspicious_amount_action' ), 'block' ); ?>><?php esc_html_e( 'Block (cancel order)', 'mighty-shield' ); ?></option>
                        <option value="notify" <?php selected( settings::get( 'mshield_suspicious_amount_action' ), 'notify' ); ?>><?php esc_html_e( 'Flag + notify admin via email', 'mighty-shield' ); ?></option>
                    </select>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Address Validation', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Score-based detection of fake or nonsensical billing addresses. Checks for single-character names, repeated-digit ZIPs, known fake patterns, etc.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Sensitivity', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_address_sensitivity">
                        <option value="low" <?php selected( settings::get( 'mshield_address_sensitivity' ), 'low' ); ?>><?php esc_html_e( 'Low (score >= 10 to block)', 'mighty-shield' ); ?></option>
                        <option value="medium" <?php selected( settings::get( 'mshield_address_sensitivity' ), 'medium' ); ?>><?php esc_html_e( 'Medium (score >= 7 to block)', 'mighty-shield' ); ?></option>
                        <option value="high" <?php selected( settings::get( 'mshield_address_sensitivity' ), 'high' ); ?>><?php esc_html_e( 'High (score >= 5 to block)', 'mighty-shield' ); ?></option>
                    </select>
                    <p class="description"><?php esc_html_e( 'Higher sensitivity catches more suspicious addresses but may increase false positives.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <?php submit_button(); ?>
</form>
