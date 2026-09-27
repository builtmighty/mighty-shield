<?php
/**
 * IP Blocklist management view.
 *
 * @package MightyShield
 * @since   1.2.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Firewall\ip_blocklist;
use MightyShield\Includes\ip_utils;

$blocklist  = ip_blocklist::get_blocklist();
$current_ip = ip_utils::get_client_ip();
?>

<div class="mshield-section">
    <h2><?php esc_html_e( 'Blocklist', 'mighty-shield' ); ?></h2>
    <p class="description"><?php esc_html_e( 'Permanently bar something from checkout. An IP address or range is refused before the order is scored; everything else is matched against the order and carries the same weight. Entries never expire until you remove them, and anything on the allowlist is never blocked.', 'mighty-shield' ); ?></p>
    <form method="post">
        <?php wp_nonce_field( 'mshield_blocklist_action' ); ?>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Block by', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_block_new_type">
                        <option value="ip"><?php esc_html_e( 'IP address or CIDR range', 'mighty-shield' ); ?></option>
                        <option value="email"><?php esc_html_e( 'Email address', 'mighty-shield' ); ?></option>
                        <option value="phone"><?php esc_html_e( 'Phone number', 'mighty-shield' ); ?></option>
                        <option value="name"><?php esc_html_e( 'Name', 'mighty-shield' ); ?></option>
                        <option value="postcode"><?php esc_html_e( 'Postcode', 'mighty-shield' ); ?></option>
                        <option value="city"><?php esc_html_e( 'City', 'mighty-shield' ); ?></option>
                        <option value="country"><?php esc_html_e( 'Country (two-letter code)', 'mighty-shield' ); ?></option>
                    </select>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Value', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_block_new_ip" value="" class="regular-text" placeholder="e.g. 192.168.1.1, 10.0.0.0/8, someone@example.com" />
                    <p class="description"><?php esc_html_e( 'Your current IP address: ', 'mighty-shield' ); ?><code><?php echo esc_html( $current_ip ); ?></code></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Label', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_block_new_ip_label" value="" class="regular-text" placeholder="e.g., Card runner, Repeat fraud" />
                </td>
            </tr>
        </table>
        <p>
            <input type="submit" name="mshield_block_add_ip" class="mshield-btn is-primary" value="<?php esc_attr_e( 'Add to blocklist', 'mighty-shield' ); ?>" />
        </p>
    </form>

    <?php if( empty( $blocklist ) ) : ?>
        <p class="mshield-empty"><?php esc_html_e( 'Nothing has been blocked yet.', 'mighty-shield' ); ?></p>
    <?php else : ?>
        <?php
        // A blocklist row has held a type since 2.3.0; rows written before
        // that have only an 'ip' key. normalize_entry() reads both shapes, so
        // this table does not need to know which it is looking at.
        $mshield_type_labels = [
            'ip'       => __( 'IP address', 'mighty-shield' ),
            'email'    => __( 'Email', 'mighty-shield' ),
            'phone'    => __( 'Phone', 'mighty-shield' ),
            'name'     => __( 'Name', 'mighty-shield' ),
            'postcode' => __( 'Postcode', 'mighty-shield' ),
            'city'     => __( 'City', 'mighty-shield' ),
            'country'  => __( 'Country', 'mighty-shield' ),
        ];
        ?>
        <table class="mshield-table">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Type', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Value', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Label', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Reason', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Added', 'mighty-shield' ); ?></th>
                    <th><?php esc_html_e( 'Actions', 'mighty-shield' ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach( $blocklist as $mshield_raw ) : ?>
                <?php $entry = \MightyShield\Firewall\ip_blocklist::normalize_entry( $mshield_raw ); ?>
                <tr>
                    <td><?php echo esc_html( $mshield_type_labels[ $entry['type'] ] ?? $entry['type'] ); ?></td>
                    <td><code><?php echo esc_html( $entry['value'] ); ?></code></td>
                    <td><?php echo esc_html( $entry['label'] ); ?></td>
                    <td><?php echo esc_html( '' !== $entry['reason'] ? $entry['reason'] : '—' ); ?></td>
                    <td><?php echo esc_html( ! empty( $entry['added'] ) ? date_i18n( get_option( 'date_format' ), $entry['added'] ) : '—' ); ?></td>
                    <td>
                        <?php
                        $remove_url = wp_nonce_url(
                            admin_url( 'admin.php?page=mighty-shield&tab=blocklist'
                                . '&mshield_block_remove_type=' . urlencode( $entry['type'] )
                                . '&mshield_block_remove_ip=' . urlencode( $entry['value'] ) ),
                            'mshield_block_remove_ip'
                        );
                        ?>
                        <a href="<?php echo esc_url( $remove_url ); ?>" class="mshield-btn is-small" onclick="return confirm('<?php echo esc_js( __( 'Remove this from the blocklist?', 'mighty-shield' ) ); ?>');"><?php esc_html_e( 'Remove', 'mighty-shield' ); ?></a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>
