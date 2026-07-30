<?php
/**
 * Test Mode admin toolbar.
 *
 * Renders the MightyShield test-mode controls in the WordPress admin bar
 * (front end and admin) for shop managers/administrators, and handles toggling
 * via AJAX. State is per-user; see MightyShield\Includes\test_mode.
 *
 * @package MightyShield
 * @since   1.7.0
 */
namespace MightyShield\Admin;

use MightyShield\Includes\test_mode;

class test_mode_bar {

    /**
     * Human labels for each force-trip layer.
     *
     * @since   1.7.0
     */
    private const LAYER_LABELS = [
        'firewall'       => 'Store API firewall',
        'blocklist'      => 'IP blocklist',
        'rate_limit'     => 'Rate limit',
        'velocity'       => 'Velocity',
        'failed_payment' => 'Failed payment',
        'email_domain'   => 'Email domain',
        'order_amount'   => 'Order amount',
        'address'        => 'Address validation',
        'zip_state'      => 'ZIP/State mismatch',
        'smarty'         => 'Smarty verification',
        'honeypot'       => 'Honeypot',
        'timing'         => 'Checkout timing',
        'fingerprint'    => 'Device fingerprinting',
        'captcha'        => 'Bot challenge (CAPTCHA)',
    ];

    /**
     * Construct.
     *
     * @since   1.7.0
     */
    public function __construct() {

        add_action( 'admin_bar_menu', [ $this, 'toolbar' ], 100 );
        add_action( 'wp_enqueue_scripts', [ $this, 'enqueue' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue' ] );
        add_action( 'wp_ajax_mshield_test_toggle', [ $this, 'ajax_toggle' ] );

    }

    /**
     * Whether the current user may use test mode.
     *
     * @since   1.7.0
     *
     * @return  bool
     */
    private function can() {

        return is_user_logged_in() && current_user_can( 'manage_woocommerce' );

    }

    /**
     * Attach a small controller script to the always-present admin-bar handle.
     *
     * @since   1.7.0
     */
    public function enqueue() {

        if( ! $this->can() || ! is_admin_bar_showing() ) return;

        $data = 'window.mshieldTB=' . wp_json_encode( [
            'ajaxUrl' => admin_url( 'admin-ajax.php' ),
            'nonce'   => wp_create_nonce( 'mshield_test_toggle' ),
        ] ) . ';';
        wp_add_inline_script( 'admin-bar', $data, 'before' );

        $js = "document.addEventListener('click',function(e){"
            . "var a=e.target.closest('.mshield-tb-action');if(!a||!window.mshieldTB)return;"
            . "e.preventDefault();"
            . "var b=new URLSearchParams();b.set('action','mshield_test_toggle');b.set('nonce',mshieldTB.nonce);"
            . "b.set('do',a.getAttribute('data-do')||'');b.set('layer',a.getAttribute('data-layer')||'');"
            . "fetch(mshieldTB.ajaxUrl,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()})"
            . ".then(function(){location.reload();});"
            . "});";
        wp_add_inline_script( 'admin-bar', $js );

        wp_add_inline_style( 'admin-bar', '#wp-admin-bar-mshield-test.mshield-tb-on > .ab-item{background:#d63638!important;color:#fff!important}'
            . '#wp-admin-bar-mshield-test .mshield-tb-on-dot{color:#68de8a}'
            . '.mshield-tb-check{display:inline-block;width:1.4em}' );

    }

    /**
     * Build the toolbar nodes.
     *
     * @since   1.7.0
     *
     * @param   \WP_Admin_Bar   $bar    Toolbar instance.
     */
    public function toolbar( $bar ) {

        if( ! $this->can() ) return;

        $on       = test_mode::active();
        $simulate = test_mode::simulate();

        $bar->add_node( [
            'id'    => 'mshield-test',
            'title' => '🛡 ' . esc_html__( 'MightyShield', 'mighty-shield' ) . ' · ' . ( $on ? '<span class="mshield-tb-on-dot">●</span> ' . esc_html__( 'TEST ON', 'mighty-shield' ) : esc_html__( 'Test', 'mighty-shield' ) ),
            'href'  => '#',
            'meta'  => [ 'class' => $on ? 'mshield-tb-on' : '' ],
        ] );

        // Enable/disable test mode.
        $this->action_node( $bar, 'toggle', '', '<span class="mshield-tb-check">' . ( $on ? '✓' : '' ) . '</span>' . esc_html__( 'Test mode', 'mighty-shield' ) );

        // Simulate vs enforce.
        $this->action_node( $bar, 'mode', '', '<span class="mshield-tb-check"></span>' . ( $simulate ? esc_html__( 'Mode: Simulate (log only)', 'mighty-shield' ) : esc_html__( 'Mode: Enforce (block/flag)', 'mighty-shield' ) ) );

        // Per-layer force-trip toggles (only while test mode is on).
        if( $on ) {
            foreach( self::LAYER_LABELS as $key => $label ) {
                $checked = test_mode::forcing( $key );
                $this->action_node( $bar, 'layer', $key, '<span class="mshield-tb-check">' . ( $checked ? '✓' : '' ) . '</span>' . esc_html( $label ), 'mshield-test-layers' );
            }
        }

    }

    /**
     * Add a clickable action node whose data-* attributes live in the anchor markup.
     *
     * @since   1.7.0
     */
    private function action_node( $bar, $do, $layer, $label_html, $group = '' ) {

        $node = [
            'id'     => 'mshield-test-' . $do . ( $layer !== '' ? '-' . $layer : '' ),
            'parent' => $group !== '' ? $group : 'mshield-test',
            'title'  => '<span class="mshield-tb-action" data-do="' . esc_attr( $do ) . '" data-layer="' . esc_attr( $layer ) . '">' . $label_html . '</span>',
            'href'   => '#',
        ];

        if( $group === 'mshield-test-layers' && ! $this->group_added ) {
            $bar->add_group( [ 'id' => 'mshield-test-layers', 'parent' => 'mshield-test' ] );
            $this->group_added = true;
        }

        $bar->add_node( $node );

    }

    /**
     * Track whether the layer group node has been created.
     *
     * @since   1.7.0
     */
    private $group_added = false;

    /**
     * AJAX: toggle test mode / simulate / a layer for the current user.
     *
     * @since   1.7.0
     */
    public function ajax_toggle() {

        if( ! $this->can() ) wp_send_json_error( '', 403 );
        if( ! check_ajax_referer( 'mshield_test_toggle', 'nonce', false ) ) wp_send_json_error( '', 400 );

        $uid = get_current_user_id();
        $do  = isset( $_POST['do'] ) ? sanitize_key( $_POST['do'] ) : '';

        if( $do === 'toggle' ) {

            $new = get_user_meta( $uid, 'mshield_test_mode', true ) === 'yes' ? 'no' : 'yes';
            update_user_meta( $uid, 'mshield_test_mode', $new );

        } elseif( $do === 'mode' ) {

            $new = get_user_meta( $uid, 'mshield_test_simulate', true ) === 'no' ? 'yes' : 'no';
            update_user_meta( $uid, 'mshield_test_simulate', $new );

        } elseif( $do === 'layer' ) {

            $layer = isset( $_POST['layer'] ) ? sanitize_key( $_POST['layer'] ) : '';
            if( in_array( $layer, test_mode::LAYERS, true ) ) {
                $layers = get_user_meta( $uid, 'mshield_test_layers', true );
                $layers = is_array( $layers ) ? $layers : [];
                if( in_array( $layer, $layers, true ) ) {
                    $layers = array_values( array_diff( $layers, [ $layer ] ) );
                } else {
                    $layers[] = $layer;
                }
                update_user_meta( $uid, 'mshield_test_layers', $layers );
            }

        }

        wp_send_json_success();

    }

}
