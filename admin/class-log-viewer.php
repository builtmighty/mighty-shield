<?php
/**
 * Log Viewer.
 *
 * Handles log export and bulk actions.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Admin;

use MightyShield\Includes\db;

class log_viewer {

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        add_action( 'admin_init', [ $this, 'handle_export' ] );

    }

    /**
     * Handle CSV export.
     *
     * @since   1.0.0
     */
    public function handle_export() {

        if( ! isset( $_GET['mshield_export_logs'] ) ) return;
        if( ! current_user_can( 'manage_woocommerce' ) ) return;
        if( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'mshield_export_logs' ) ) return;

        $logs = db::get_logs( [ 'per_page' => 10000, 'page' => 1 ] );

        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename=mightyshield-logs-' . date( 'Y-m-d' ) . '.csv' );

        $output = fopen( 'php://output', 'w' );

        // Header row.
        fputcsv( $output, [ 'ID', 'IP', 'Action', 'Endpoint', 'Reason', 'Date' ] );

        foreach( $logs as $log ) {
            fputcsv( $output, [
                $log->id,
                $log->ip,
                $log->action,
                $log->endpoint,
                $log->reason,
                $log->created_at,
            ] );
        }

        fclose( $output );
        exit;

    }

}
