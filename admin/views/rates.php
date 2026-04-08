<?php
/**
 * Rate Limits settings view.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\settings;
?>

<form method="post" action="options.php">
    <?php settings_fields( 'mshield_rates' ); ?>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Checkout Rate Limiting', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Limit how many checkout attempts a single IP can make within a time window.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Max Checkout Attempts', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_rate_checkout_limit" value="<?php echo esc_attr( settings::get( 'mshield_rate_checkout_limit' ) ); ?>" min="1" max="100" class="small-text" />
                    <span><?php esc_html_e( 'attempts per window', 'mighty-shield' ); ?></span>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Time Window', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_rate_checkout_window" value="<?php echo esc_attr( settings::get( 'mshield_rate_checkout_window' ) ); ?>" min="60" max="86400" class="small-text" />
                    <span><?php esc_html_e( 'seconds', 'mighty-shield' ); ?></span>
                    <p class="description"><?php esc_html_e( 'Default: 3600 (1 hour). This means 5 checkout attempts per hour per IP.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Velocity Detection', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Detect rapid-fire patterns characteristic of card testing bots.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Unique Email Threshold', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_velocity_email_threshold" value="<?php echo esc_attr( settings::get( 'mshield_velocity_email_threshold' ) ); ?>" min="1" max="50" class="small-text" />
                    <span><?php esc_html_e( 'unique emails per IP per hour', 'mighty-shield' ); ?></span>
                    <p class="description"><?php esc_html_e( 'Block IPs that use more than this many different email addresses in 1 hour. Card testers often rotate emails.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Order Attempt Threshold', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_velocity_order_threshold" value="<?php echo esc_attr( settings::get( 'mshield_velocity_order_threshold' ) ); ?>" min="1" max="50" class="small-text" />
                    <span><?php esc_html_e( 'orders per IP per 15 minutes', 'mighty-shield' ); ?></span>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Failed Payment Tracking', 'mighty-shield' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Failed Payment Threshold', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_failed_payment_threshold" value="<?php echo esc_attr( settings::get( 'mshield_failed_payment_threshold' ) ); ?>" min="1" max="50" class="small-text" />
                    <span><?php esc_html_e( 'failed payments per IP per hour', 'mighty-shield' ); ?></span>
                    <p class="description"><?php esc_html_e( 'Temporarily block IPs that exceed this many failed payments in 1 hour.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Temporary Block Duration', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_temp_block_duration" value="<?php echo esc_attr( settings::get( 'mshield_temp_block_duration' ) ); ?>" min="3600" max="604800" class="small-text" />
                    <span><?php esc_html_e( 'seconds', 'mighty-shield' ); ?></span>
                    <p class="description"><?php esc_html_e( 'Default: 86400 (24 hours). How long to block an IP after it triggers velocity or failed payment thresholds.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <?php submit_button(); ?>
</form>
