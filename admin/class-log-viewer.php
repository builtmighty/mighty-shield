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

        // The same filters the screen is showing. The Export button sits inside
        // the filter bar, so narrowing to one address and exporting used to hand
        // back all ten thousand rows instead -- silently, and truncated at that.
        $args = [ 'per_page' => 10000, 'page' => 1 ];

        // Named exactly as the screen names them, because get_logs() takes
        // 'days' where the query string says 'range'.
        foreach( [ 'action' => 'filter_action', 'ip' => 'filter_ip', 'search' => 's' ] as $arg => $param ) {
            if( ! empty( $_GET[ $param ] ) ) $args[ $arg ] = sanitize_text_field( wp_unslash( $_GET[ $param ] ) );
        }

        if( ! empty( $_GET['range'] ) ) $args['days'] = (int) $_GET['range'];

        $logs = db::get_logs( $args );

        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename=mightyshield-logs-' . gmdate( 'Y-m-d' ) . '.csv' );

        $output = fopen( 'php://output', 'w' );

        // Header row.
        fputcsv( $output, [ 'ID', 'IP', 'Action', 'Endpoint', 'Reason', 'Date' ] );

        foreach( $logs as $log ) {
            fputcsv( $output, array_map( [ __CLASS__, 'defuse' ], [
                $log->id,
                $log->ip,
                $log->action,
                $log->endpoint,
                $log->reason,
                $log->created_at,
            ] ) );
        }

        fclose( $output );
        exit;

    }

    /**
     * Stop a spreadsheet treating a log value as a formula.
     *
     * Excel, Numbers and Sheets all evaluate a cell beginning with = + - @ or a
     * leading tab. The reason column carries text that came off a checkout
     * form, so a log export is a file built from attacker input and opened by
     * the merchant — the textbook shape of CSV injection.
     *
     * Nothing reaches this today: every reason string begins with a literal and
     * the IP column is validated before it is ever stored. That is a property
     * of the current callers rather than of this function, and one new
     * log_event() whose reason starts with a variable would quietly make it
     * exploitable. Neutralising here means that can never be the file's problem.
     *
     * A leading apostrophe is the standard mitigation: spreadsheets read the
     * rest of the cell as literal text and do not display the quote.
     *
     * @since   2.0.0
     *
     * @param   mixed   $value  Cell value.
     * @return  string
     */
    private static function defuse( $value ) {

        $value = (string) $value;

        if( $value === '' ) return $value;

        return \in_array( $value[0], [ '=', '+', '-', '@', "\t", "\r" ], true )
            ? "'" . $value
            : $value;

    }

}
