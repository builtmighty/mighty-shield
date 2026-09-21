<?php
/**
 * Personal data export and erasure.
 *
 * MightyShield holds two very different kinds of record about a shopper, and
 * this file treats them differently on purpose.
 *
 *   The log      Cleartext. IP address, user agent, the billing email that was
 *                typed, the URL. Written when something was blocked, rate
 *                limited or flagged. This is ordinary personal data and it is
 *                deleted on request.
 *
 *   The identity Salted hashes and counters -- how many orders this email has
 *   graph        placed, how many were refunded, how many became chargebacks.
 *                No value is stored in the clear anywhere. This is the store's
 *                fraud history, and it is RETAINED on an erasure request.
 *
 * That second decision is the one worth explaining, because "the plugin
 * refused to delete something" reads badly until you see what deleting it
 * would mean.
 *
 * The identity graph is what makes a chargeback count against the next order.
 * If an erasure request emptied it, erasure would become the reset button:
 * charge back an order, ask the store to forget you, order again with a clean
 * record. The request costs nothing to make and every store must honour it,
 * so it would be the cheapest laundering step available and it would work on
 * every WooCommerce store running this plugin.
 *
 * GDPR anticipates exactly this. Article 17(3)(e) keeps the right to erasure
 * from applying where the data is needed to establish, exercise or defend
 * legal claims, and Recital 47 names fraud prevention as a legitimate
 * interest in its own right. WordPress's eraser API has a first-class way to
 * say so -- items_retained plus a message -- rather than silently doing
 * nothing, and that is what this uses.
 *
 * The honest part is that the retained record is genuinely not readable. The
 * hash is one-way and salted with a key unique to this site, so a row cannot
 * be turned back into an email address; it can only be recognised if the same
 * address is presented again. Uninstalling the plugin deletes the salt along
 * with everything else, which makes every remaining hash permanently
 * meaningless.
 *
 * @package MightyShield
 * @since   2.3.0
 */
namespace MightyShield\Includes;

defined( 'ABSPATH' ) || exit;

class privacy {

    /**
     * Rows per page. WordPress calls these repeatedly until done is true, so
     * this only has to be small enough not to time out.
     *
     * @since   2.3.0
     */
    const PER_PAGE = 100;

    /**
     * Identity types derivable from an email address alone.
     *
     * The other five -- phone, address, device, ip_block, card_fp -- are
     * hashes of values WordPress does not hand us, and a hash cannot be
     * searched by anything but itself. They are reported in the export as a
     * count so the total is not misrepresented.
     *
     * @since   2.3.0
     */
    const EMAIL_TYPES = [ 'email', 'email_root' ];

    /**
     * Register.
     *
     * @since   2.3.0
     */
    public static function register() {

        add_filter( 'wp_privacy_personal_data_exporters', [ __CLASS__, 'register_exporter' ] );
        add_filter( 'wp_privacy_personal_data_erasers', [ __CLASS__, 'register_eraser' ] );
        add_action( 'admin_init', [ __CLASS__, 'add_policy_content' ] );

    }

    /**
     * @since   2.3.0
     *
     * @param   array   $exporters
     * @return  array
     */
    public static function register_exporter( $exporters ) {

        $exporters['mighty-shield'] = [
            'exporter_friendly_name' => __( 'MightyShield', 'mighty-shield' ),
            'callback'               => [ __CLASS__, 'export' ],
        ];

        return $exporters;

    }

    /**
     * @since   2.3.0
     *
     * @param   array   $erasers
     * @return  array
     */
    public static function register_eraser( $erasers ) {

        $erasers['mighty-shield'] = [
            'eraser_friendly_name' => __( 'MightyShield', 'mighty-shield' ),
            'callback'             => [ __CLASS__, 'erase' ],
        ];

        return $erasers;

    }

    /**
     * Export everything MightyShield holds for an email address.
     *
     * Page 1 reports the identity graph, which is a fixed handful of rows.
     * Every page including the first reports a slice of the log, which is not.
     *
     * @since   2.3.0
     *
     * @param   string  $email
     * @param   int     $page
     * @return  array
     */
    public static function export( $email, $page = 1 ) {

        $page  = max( 1, (int) $page );
        $items = [];

        if( $page === 1 ) {
            $items = array_merge( $items, self::export_identities( $email ) );
        }

        $logs = self::log_rows( $email, $page );

        foreach( $logs as $row ) {
            $items[] = self::export_log_row( $row );
        }

        return [
            'data' => $items,
            'done' => count( $logs ) < self::PER_PAGE,
        ];

    }

    /**
     * The identity graph, as one group per type that actually has a row.
     *
     * @since   2.3.0
     *
     * @param   string  $email
     * @return  array
     */
    private static function export_identities( $email ) {

        $items = [];

        foreach( self::EMAIL_TYPES as $type ) {

            $value = entities::normalize( $type, $email );
            if( $value === '' ) continue;

            $row = entities::get( $type, $value );
            if( ! $row ) continue;

            $items[] = [
                'group_id'          => 'mshield-identity',
                'group_label'       => __( 'MightyShield fraud history', 'mighty-shield' ),
                'group_description' => __( 'What this store has seen from this identity before. Stored as a one-way salted hash, never as the address itself.', 'mighty-shield' ),
                'item_id'           => 'mshield-identity-' . $type,
                'data'              => [
                    [
                        'name'  => __( 'Identity type', 'mighty-shield' ),
                        'value' => entities::type_label( $type ),
                    ],
                    [
                        'name'  => __( 'First seen', 'mighty-shield' ),
                        'value' => $row['first_seen'],
                    ],
                    [
                        'name'  => __( 'Last seen', 'mighty-shield' ),
                        'value' => $row['last_seen'],
                    ],
                    [
                        'name'  => __( 'Orders placed', 'mighty-shield' ),
                        'value' => $row['order_count'],
                    ],
                    [
                        'name'  => __( 'Orders completed', 'mighty-shield' ),
                        'value' => $row['approved_count'],
                    ],
                    [
                        'name'  => __( 'Orders refunded', 'mighty-shield' ),
                        'value' => $row['refund_count'],
                    ],
                    [
                        'name'  => __( 'Orders reported as fraud', 'mighty-shield' ),
                        'value' => $row['denied_count'],
                    ],
                    [
                        'name'  => __( 'Chargebacks', 'mighty-shield' ),
                        'value' => $row['chargeback_count'],
                    ],
                    [
                        'name'  => __( 'Checkouts refused', 'mighty-shield' ),
                        'value' => $row['refused_count'],
                    ],
                    [
                        'name'  => __( 'Reputation', 'mighty-shield' ),
                        'value' => $row['reputation'],
                    ],
                ],
            ];

        }

        return $items;

    }

    /**
     * One log row.
     *
     * @since   2.3.0
     *
     * @param   array   $row
     * @return  array
     */
    private static function export_log_row( $row ) {

        $forensics = json_decode( (string) $row['request_data'], true );
        if( ! is_array( $forensics ) ) $forensics = [];

        $data = [
            [
                'name'  => __( 'Date', 'mighty-shield' ),
                'value' => $row['created_at'],
            ],
            [
                'name'  => __( 'What happened', 'mighty-shield' ),
                'value' => $row['action'],
            ],
            [
                'name'  => __( 'Why', 'mighty-shield' ),
                'value' => $row['reason'],
            ],
            [
                'name'  => __( 'IP address', 'mighty-shield' ),
                'value' => $row['ip'],
            ],
        ];

        if( ! empty( $forensics['ua'] ) ) {
            $data[] = [
                'name'  => __( 'Browser', 'mighty-shield' ),
                'value' => $forensics['ua'],
            ];
        }

        if( ! empty( $row['order_id'] ) ) {
            $data[] = [
                'name'  => __( 'Order', 'mighty-shield' ),
                'value' => $row['order_id'],
            ];
        }

        if( $row['trust'] !== null && $row['trust'] !== '' ) {
            $data[] = [
                'name'  => __( 'Trust rating', 'mighty-shield' ),
                'value' => $row['trust'],
            ];
        }

        return [
            'group_id'          => 'mshield-log',
            'group_label'       => __( 'MightyShield security log', 'mighty-shield' ),
            'group_description' => __( 'Checkout and login events this store recorded against this email address.', 'mighty-shield' ),
            'item_id'           => 'mshield-log-' . (int) $row['id'],
            'data'              => $data,
        ];

    }

    /**
     * Erase what can be erased, and say plainly what cannot.
     *
     * @since   2.3.0
     *
     * @param   string  $email
     * @param   int     $page
     * @return  array
     */
    public static function erase( $email, $page = 1 ) {

        global $wpdb;

        // Deliberately page 1 every time, ignoring $page.
        //
        // WordPress increments $page on each call, but this deletes as it
        // goes: by the time it asks for "page 2" the first hundred rows are
        // gone, so an OFFSET of 100 would step over a hundred rows that still
        // need deleting and report done. Always taking the first hundred that
        // remain is both correct and simpler, and the loop still terminates
        // because each pass removes what it just read.
        $rows = self::log_rows( $email, 1, [ 'id' ] );
        $done = count( $rows ) < self::PER_PAGE;

        $removed = false;

        if( $rows ) {

            $ids = array_map( 'intval', wp_list_pluck( $rows, 'id' ) );

            // Integers only, produced by intval immediately above.
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $removed = (bool) $wpdb->query(
                "DELETE FROM {$wpdb->prefix}mshield_log WHERE id IN (" . implode( ',', $ids ) . ')'
            );

        }

        $messages = [];
        $retained = false;

        // Said once, on the last page, so a request spanning ten pages does
        // not repeat the same paragraph ten times.
        if( $done && self::has_identity( $email ) ) {

            $retained   = true;
            $messages[] = __( 'MightyShield has kept this store\'s fraud history for this email address — how many orders it placed, and how many were refunded, reported as fraud or charged back. It is stored as a one-way salted hash rather than as the address itself, so it cannot be read back or turned into contact details; it can only be recognised if the same address is used again. It is kept because erasing it would let a chargeback be cleared by asking to be forgotten, and is permitted for fraud prevention and for defending legal claims. It is destroyed if MightyShield is uninstalled.', 'mighty-shield' );

        }

        return [
            'items_removed'  => $removed,
            'items_retained' => $retained,
            'messages'       => $messages,
            'done'           => $done,
        ];

    }

    /**
     * Whether the identity graph holds anything for this address.
     *
     * @since   2.3.0
     *
     * @param   string  $email
     * @return  bool
     */
    private static function has_identity( $email ) {

        foreach( self::EMAIL_TYPES as $type ) {

            $value = entities::normalize( $type, $email );
            if( $value === '' ) continue;

            if( entities::get( $type, $value ) ) return true;

        }

        return false;

    }

    /**
     * Log rows carrying this email address.
     *
     * The address lives inside the JSON forensics blob rather than a column of
     * its own, so this matches on the encoded key. Narrow on purpose: matching
     * the bare address anywhere in the blob would also hit a URL that happened
     * to contain it.
     *
     * @since   2.3.0
     *
     * @param   string      $email
     * @param   int         $page
     * @param   string[]    $columns
     * @return  array
     */
    private static function log_rows( $email, $page, $columns = [ '*' ] ) {

        global $wpdb;

        $email = sanitize_email( $email );
        if( $email === '' ) return [];

        // How capture_forensics() writes it: {"email":"someone@example.com"}.
        // wp_json_encode escapes forward slashes, which an address cannot
        // contain, so the encoded form and the raw form agree here.
        $needle = '%' . $wpdb->esc_like( '"email":"' . strtolower( $email ) . '"' ) . '%';

        $select = implode( ', ', array_map( function( $c ) {
            return $c === '*' ? '*' : '`' . preg_replace( '/[^a-z_]/', '', $c ) . '`';
        }, $columns ) );

        $offset = ( max( 1, (int) $page ) - 1 ) * self::PER_PAGE;

        // $select is built from a hardcoded caller-supplied list and stripped
        // to [a-z_]; every value is bound.
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT {$select} FROM {$wpdb->prefix}mshield_log
              WHERE request_data LIKE %s
              ORDER BY id ASC
              LIMIT %d OFFSET %d",
            $needle,
            self::PER_PAGE,
            $offset
        ), ARRAY_A );

        return $rows ?: [];

    }

    /**
     * Suggested text for the site's privacy policy.
     *
     * @since   2.3.0
     */
    public static function add_policy_content() {

        if( ! function_exists( 'wp_add_privacy_policy_content' ) ) return;

        $content =
            '<h2>' . esc_html__( 'MightyShield fraud prevention', 'mighty-shield' ) . '</h2>'
            . '<p>' . esc_html__( 'We check every order for signs of card fraud. To do that we record the IP address, browser and email address used on checkouts that are blocked or flagged, and we keep a history of how previous orders from the same customer turned out.', 'mighty-shield' ) . '</p>'
            . '<p>' . esc_html__( 'That history is stored as a one-way salted hash rather than as your details themselves, so it cannot be read back or used to contact you. Security log entries are deleted automatically after the retention period set in the plugin, 30 days by default.', 'mighty-shield' ) . '</p>'
            . '<p>' . esc_html__( 'Depending on which optional features this store has enabled, checkout details may be sent to MaxMind, Smarty, Cloudflare, Google or an AI provider to be checked. See the plugin listing for exactly what each service receives.', 'mighty-shield' ) . '</p>';

        // Already well-formed HTML, so no wpautop — running it over content
        // that already has <h2> and <p> produces stray empty paragraphs.
        wp_add_privacy_policy_content( 'MightyShield', wp_kses_post( $content ) );

    }

}
