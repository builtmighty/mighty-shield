<?php
/**
 * IP Whitelist management view.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Firewall\ip_whitelist;
use MightyShield\Includes\ip_utils;

$whitelist  = ip_whitelist::get_whitelist();
$current_ip = ip_utils::get_client_ip();
?>

<div class="mshield-section">
    <h2><?php esc_html_e( 'Add IP Address', 'mighty-shield' ); ?></h2>
    <form method="post">
        <?php wp_nonce_field( 'mshield_whitelist_action' ); ?>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'IP Address / CIDR', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_new_ip" value="" class="regular-text" placeholder="e.g., 192.168.1.1 or 10.0.0.0/8" />
                    <p class="description"><?php esc_html_e( 'Enter an IP address or CIDR range. Your current IP: ', 'mighty-shield' ); ?><code><?php echo esc_html( $current_ip ); ?></code></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Label', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_new_ip_label" value="" class="regular-text" placeholder="e.g., Office IP, CDN range" />
                </td>
            </tr>
        </table>
        <p>
            <input type="submit" name="mshield_add_ip" class="button button-primary" value="<?php esc_attr_e( 'Add to Whitelist', 'mighty-shield' ); ?>" />
        </p>
    </form>
</div>

<div class="mshield-section">
    <h2><?php esc_html_e( 'Whitelisted IPs', 'mighty-shield' ); ?></h2>
    <?php if( empty( $whitelist ) ) : ?>
        <p><?php esc_html_e( 'No IP addresses have been whitelisted yet.', 'mighty-shield' ); ?></p>
    <?php else : ?>
        <table class="mshield-table">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'IP Address', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Label', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Type', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Added', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Actions', 'mighty-shield' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach( $whitelist as $entry ) : ?>
                <tr>
                    <td><code><?php echo esc_html( $entry['ip'] ); ?></code></td>
                    <td><?php echo esc_html( $entry['label'] ); ?></td>
                    <td>
                        <?php if( ! empty( $entry['system'] ) ) : ?>
                            <span style="color: #2271b1;"><?php esc_html_e( 'System', 'mighty-shield' ); ?></span>
                        <?php else : ?>
                            <?php esc_html_e( 'Manual', 'mighty-shield' ); ?>
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html( ! empty( $entry['added'] ) ? date_i18n( get_option( 'date_format' ), $entry['added'] ) : '—' ); ?></td>
                    <td>
                        <?php
                        $remove_url = wp_nonce_url(
                            admin_url( 'admin.php?page=mighty-shield&tab=whitelist&mshield_remove_ip=' . urlencode( $entry['ip'] ) ),
                            'mshield_remove_ip'
                        );
                        ?>
                        <a href="<?php echo esc_url( $remove_url ); ?>" class="button button-small" onclick="return confirm('<?php esc_attr_e( 'Remove this IP from the whitelist?', 'mighty-shield' ); ?>');"><?php esc_html_e( 'Remove', 'mighty-shield' ); ?></a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>
