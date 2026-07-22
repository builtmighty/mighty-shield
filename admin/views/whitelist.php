<?php
/**
 * IP / User / Email Whitelist management view.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Firewall\ip_whitelist;
use MightyShield\Includes\ip_utils;

$whitelist  = ip_whitelist::get_whitelist();
$current_ip = ip_utils::get_client_ip();

$type_labels = [
    'ip'    => __( 'IP address', 'mighty-shield' ),
    'user'  => __( 'User', 'mighty-shield' ),
    'email' => __( 'Email', 'mighty-shield' ),
];
?>

<div class="mshield-section">
    <h2><?php esc_html_e( 'Add Whitelist Entry', 'mighty-shield' ); ?></h2>
    <p class="description"><?php esc_html_e( 'Whitelisted IPs, users, and email addresses bypass ALL MightyShield checks — no blocks, no flags. Use for trusted staff, offices, and known-good customers.', 'mighty-shield' ); ?></p>
    <form method="post">
        <?php wp_nonce_field( 'mshield_whitelist_action' ); ?>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Type', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_new_type">
                        <option value="ip"><?php esc_html_e( 'IP address / CIDR', 'mighty-shield' ); ?></option>
                        <option value="user"><?php esc_html_e( 'WordPress user', 'mighty-shield' ); ?></option>
                        <option value="email"><?php esc_html_e( 'Email address', 'mighty-shield' ); ?></option>
                    </select>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Value', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_new_value" value="" class="regular-text" placeholder="<?php esc_attr_e( 'IP/CIDR, username or email, or email address', 'mighty-shield' ); ?>" />
                    <p class="description">
                        <?php esc_html_e( 'IP: e.g. 192.168.1.1 or 10.0.0.0/8. User: a username, email, or user ID. Email: a full email address.', 'mighty-shield' ); ?>
                        <br><?php esc_html_e( 'Your current IP: ', 'mighty-shield' ); ?><code><?php echo esc_html( $current_ip ); ?></code>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Label', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_new_ip_label" value="" class="regular-text" placeholder="<?php esc_attr_e( 'e.g., Office IP, VIP customer', 'mighty-shield' ); ?>" />
                </td>
            </tr>
        </table>
        <p>
            <input type="submit" name="mshield_add_ip" class="button button-primary" value="<?php esc_attr_e( 'Add to Whitelist', 'mighty-shield' ); ?>" />
        </p>
    </form>
</div>

<div class="mshield-section">
    <h2><?php esc_html_e( 'Whitelisted Entries', 'mighty-shield' ); ?></h2>
    <?php if( empty( $whitelist ) ) : ?>
        <p><?php esc_html_e( 'No entries have been whitelisted yet.', 'mighty-shield' ); ?></p>
    <?php else : ?>
        <table class="mshield-table">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Type', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Value', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Label', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Source', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Added', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Actions', 'mighty-shield' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach( $whitelist as $entry ) : ?>
                <tr>
                    <td><?php echo esc_html( $type_labels[ $entry['type'] ] ?? $entry['type'] ); ?></td>
                    <td>
                        <?php
                        if( $entry['type'] === 'user' ) {
                            $wl_user = get_userdata( (int) $entry['value'] );
                            echo '<code>' . esc_html( $wl_user ? $wl_user->user_login : ( '#' . (int) $entry['value'] ) ) . '</code>';
                        } else {
                            echo '<code>' . esc_html( $entry['value'] ) . '</code>';
                        }
                        ?>
                    </td>
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
                            admin_url( 'admin.php?page=mighty-shield&tab=whitelist&wl_type=' . urlencode( $entry['type'] ) . '&mshield_remove_ip=' . urlencode( $entry['value'] ) ),
                            'mshield_remove_ip'
                        );
                        ?>
                        <a href="<?php echo esc_url( $remove_url ); ?>" class="button button-small" onclick="return confirm('<?php esc_attr_e( 'Remove this entry from the whitelist?', 'mighty-shield' ); ?>');"><?php esc_html_e( 'Remove', 'mighty-shield' ); ?></a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>
