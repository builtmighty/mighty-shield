<?php
/**
 * Teaching the identity graph about chargebacks the plugin never saw.
 *
 * Outcome learning is what makes the second order from a bad customer harder
 * than the first, and it is fed by exactly one automatic source: Stripe's
 * charge.dispute.created webhook. Every other processor -- Square,
 * Authorize.Net, Braintree, PayPal, anything behind a payment aggregator --
 * disputes into a dashboard MightyShield cannot see. On those stores the
 * graph learns from completions and refunds and from the merchant's own
 * review verdicts, and never once from the bank actually taking money back,
 * which is the strongest signal there is.
 *
 * Every one of those processors will export a dispute report as CSV. This
 * reads one.
 *
 * The hard part is matching, and it is why this works in two steps. A dispute
 * report identifies a transaction the way the PROCESSOR knows it, not the way
 * WooCommerce does, and which column that is differs by provider and changes
 * between their own export versions. So rather than ask the merchant to name
 * a column -- a question they would have to open the file to answer -- this
 * tries every column, counts how many orders each one finds, and shows the
 * result before anything is written. A preview that says "column
 * charge_id matched 14 of your 15 rows" is answerable at a glance; "which
 * column holds the transaction ID" is not.
 *
 * Nothing here decides anything about an order. It records an outcome, and
 * outcomes::record() owns what that does -- including the severity ratchet
 * that stops a re-imported file counting the same chargeback twice.
 *
 * @package MightyShield
 * @since   2.3.0
 */
namespace MightyShield\Includes;

defined( 'ABSPATH' ) || exit;

class dispute_import {

    /**
     * Rows to read. A dispute report is small by nature -- a store with more
     * than this many chargebacks in one export has a different problem.
     *
     * @since   2.3.0
     */
    const MAX_ROWS = 2000;

    /**
     * Rows to sample when working out which column holds the reference.
     *
     * @since   2.3.0
     */
    const SAMPLE = 60;

    /**
     * Read a CSV and work out which column identifies an order.
     *
     * @since   2.3.0
     *
     * @param   string  $path   A readable CSV.
     * @return  array|\WP_Error [ header, rows, column, matched, total, examples ]
     */
    public static function preview( $path ) {

        $rows = self::read( $path );

        if( is_wp_error( $rows ) ) return $rows;

        list( $header, $data ) = $rows;

        if( empty( $data ) ) {
            return new \WP_Error( 'mshield_csv_empty', __( 'That file has a header but no rows.', 'mighty-shield' ) );
        }

        $sample = array_slice( $data, 0, self::SAMPLE );
        $best   = [ 'index' => -1, 'matched' => 0, 'examples' => [] ];

        foreach( array_keys( $header ) as $i ) {

            $matched  = 0;
            $examples = [];

            foreach( $sample as $row ) {

                $order = self::resolve( $row[ $i ] ?? '' );

                if( ! $order ) continue;

                $matched++;

                if( count( $examples ) < 5 ) {
                    $examples[] = [
                        'value' => (string) ( $row[ $i ] ?? '' ),
                        'order' => $order->get_id(),
                    ];
                }

            }

            if( $matched > $best['matched'] ) {
                $best = [ 'index' => $i, 'matched' => $matched, 'examples' => $examples ];
            }

        }

        return [
            'header'   => $header,
            'total'    => count( $data ),
            'sampled'  => count( $sample ),
            'column'   => $best['index'],
            'label'    => $best['index'] >= 0 ? ( $header[ $best['index'] ] ?? '' ) : '',
            'matched'  => $best['matched'],
            'examples' => $best['examples'],
        ];

    }

    /**
     * Record a chargeback against every order the chosen column finds.
     *
     * @since   2.3.0
     *
     * @param   string  $path
     * @param   int     $column Index into each row.
     * @return  array|\WP_Error [ recorded, already, unmatched ]
     */
    public static function apply( $path, $column ) {

        $rows = self::read( $path );

        if( is_wp_error( $rows ) ) return $rows;

        list( , $data ) = $rows;

        $column = (int) $column;

        $out = [ 'recorded' => 0, 'already' => 0, 'unmatched' => 0 ];

        foreach( $data as $row ) {

            $order = self::resolve( $row[ $column ] ?? '' );

            if( ! $order ) { $out['unmatched']++; continue; }

            // record() ratchets: it refuses to lower an outcome and refuses to
            // apply the same one twice, so re-importing a file the merchant
            // already imported costs the identity graph nothing. That guard
            // lives there rather than here on purpose -- it is the same one
            // that protects against a redelivered Stripe webhook.
            if( \MightyShield\Protection\outcomes::record( $order, 'chargeback' ) ) {
                $out['recorded']++;
            } else {
                $out['already']++;
            }

        }

        return $out;

    }

    /**
     * The order a cell refers to, if any.
     *
     * Tried in order of how sure we can be:
     *
     *   1. A processor transaction id stored on the order. Exact, and what a
     *      dispute report actually contains.
     *   2. A bare order number. Checked SECOND and guarded, because a dispute
     *      report is full of numbers -- amounts, fees, timestamps -- and any
     *      of them could collide with an order id. Requiring the order to
     *      carry a MightyShield rating is what makes this safe: an order the
     *      plugin never scored is not one it should be learning from, and an
     *      amount of 1043 will not have one.
     *
     * @since   2.3.0
     *
     * @param   string  $value
     * @return  \WC_Order|null
     */
    private static function resolve( $value ) {

        $value = trim( (string) $value );

        if( $value === '' || strlen( $value ) > 191 ) return null;

        $by_txn = self::by_transaction_id( $value );

        if( $by_txn ) return $by_txn;

        if( ! ctype_digit( $value ) ) return null;

        $order = wc_get_order( (int) $value );

        if( ! $order ) return null;

        // A rating is the proof that this number is an order id rather than a
        // coincidence. Without it, importing a report whose "amount" column
        // happens to hold order numbers would record chargebacks against
        // innocent orders.
        return db::get_risk( $order->get_id() ) ? $order : null;

    }

    /**
     * The order carrying a given processor transaction id.
     *
     * @since   2.3.0
     *
     * @param   string  $txn
     * @return  \WC_Order|null
     */
    private static function by_transaction_id( $txn ) {

        $found = wc_get_orders( [
            'limit'      => 1,
            'return'     => 'ids',
            'type'       => 'shop_order',
            // The order's own transaction_id field, not a meta lookup. Under
            // HPOS the value is a column on wc_orders and is not in the meta
            // table at all, so a meta_key query matched nothing on every HPOS
            // store -- which is every store WooCommerce has created since 8.2.
            // wc_get_orders() maps this argument to the right place on both
            // storage backends.
            'transaction_id' => $txn,
        ] );

        if( empty( $found ) ) return null;

        $order = wc_get_order( (int) $found[0] );

        return $order ?: null;

    }

    /**
     * Read the file into a header and rows.
     *
     * @since   2.3.0
     *
     * @param   string  $path
     * @return  array|\WP_Error
     */
    private static function read( $path ) {

        if( ! is_readable( $path ) ) {
            return new \WP_Error( 'mshield_csv_unreadable', __( 'That file could not be read.', 'mighty-shield' ) );
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $handle = fopen( $path, 'r' );

        if( ! $handle ) {
            return new \WP_Error( 'mshield_csv_unreadable', __( 'That file could not be opened.', 'mighty-shield' ) );
        }

        $header = fgetcsv( $handle );

        if( ! is_array( $header ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
            fclose( $handle );
            return new \WP_Error( 'mshield_csv_header', __( 'That does not look like a CSV file.', 'mighty-shield' ) );
        }

        // A spreadsheet exported from Excel often carries a byte-order mark on
        // the first header, which silently breaks a match on that column.
        if( isset( $header[0] ) ) {
            $header[0] = preg_replace( '/^\xEF\xBB\xBF/', '', (string) $header[0] );
        }

        $header = array_map( function( $h ) { return sanitize_text_field( (string) $h ); }, $header );

        $data = [];

        while( count( $data ) < self::MAX_ROWS && ( $row = fgetcsv( $handle ) ) !== false ) {

            if( ! is_array( $row ) ) continue;

            // A trailing blank line is a row of one empty cell.
            if( count( $row ) === 1 && trim( (string) $row[0] ) === '' ) continue;

            $data[] = array_map( function( $c ) { return sanitize_text_field( (string) $c ); }, $row );

        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose( $handle );

        return [ $header, $data ];

    }

}
