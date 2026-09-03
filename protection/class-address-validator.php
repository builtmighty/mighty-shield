<?php
/**
 * Address Validator.
 *
 * Score-based detection of fake/nonsensical addresses.
 *
 * @package MightyShield
 * @since   1.0.0
 */
namespace MightyShield\Protection;

use MightyShield\Includes\ip_utils;
use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\risk_context;
use MightyShield\Includes\response;

class address_validator {

    /**
     * Sensitivity thresholds.
     *
     * @since   1.0.0
     */
    private const THRESHOLDS = [
        'low'    => 10,
        'medium' => 7,
        'high'   => 5,
    ];

    /**
     * Known fake name patterns.
     *
     * @since   1.0.0
     */
    private const FAKE_PATTERNS = [
        'test',
        'asdf',
        'qwerty',
        'abc',
        'xyz',
        'aaa',
        'bbb',
        'xxx',
        'zzz',
        'fake',
        'sample',
        'example',
        'john doe',
        'jane doe',
        'foo',
        'bar',
        'baz',
        'nobody',
        'noname',
        'nope',
    ];

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Validate address during checkout.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'validate_address' ], 10, 2 );

    }

    /**
     * Validate billing/shipping address for suspicious patterns.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function validate_address( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        $verdict = self::assess( $data );

        if( ! $verdict['blockable'] ) return;

        $ip = ip_utils::get_client_ip();
        db::log_event( $ip, 'classic_checkout', 'blocked', $verdict['reason'] );

        $errors->add( 'mighty_shield_address', response::with_note( __( 'Please verify your billing information and try again.', 'mighty-shield' ) ) );

    }

    /**
     * Score the address and record what it found.
     *
     * The one place this check turns into a signal, called by both checkouts.
     * The Store API path used to call score_address() and act on the number
     * without ever recording it, so an address that looked made up blocked on
     * one checkout and scored nothing on the other.
     *
     * Emission is unconditional and separate from the decision to block: that
     * separation is the contract every check here follows, and welding the two
     * together is exactly how this drifted.
     *
     * @since   2.0.0
     *
     * @param   array   $data   Normalised billing fields.
     * @return  array   [ 'score', 'threshold', 'signals', 'blockable', 'reason' ]
     */
    public static function assess( $data ) {

        $result  = self::score_address( $data );
        $score   = (int) $result['score'];
        $signals = (array) $result['signals'];

        $threshold = self::block_threshold();

        $reason = 'Address validation score ' . $score . '/' . $threshold . ': ' . implode( ', ', $signals );

        // Emit for any non-zero score, not just at/above the block threshold.
        // A score of 6 against a threshold of 7 is real evidence, and under the
        // old all-or-nothing model it produced nothing at all. Scaling
        // confidence by how far the score got means a near-miss contributes
        // partial weight and can still compound with other signals into a risk level.
        if( $score > 0 && $threshold > 0 ) {

            risk_context::add( 'address_fake', $reason, min( 1.0, $score / $threshold ) );

        }

        return [
            'score'     => $score,
            'threshold' => $threshold,
            'signals'   => $signals,
            'blockable' => $threshold > 0 && $score >= $threshold,
            'reason'    => $reason,
        ];

    }

    /**
     * Score an address for suspicious patterns. Reusable by classic and Store
     * API (block) checkout.
     *
     * @since   1.8.0
     *
     * @param   array   $data   Billing fields (billing_first_name, billing_last_name,
     *                          billing_address_1, billing_postcode, billing_phone,
     *                          billing_email, billing_city).
     * @return  array   [ 'score' => int, 'signals' => string[] ]
     */
    /**
     * The score at/above which an address is blocked, per the configured sensitivity.
     *
     * @since   1.8.0
     *
     * @return  int
     */
    public static function block_threshold() {

        $sensitivity = settings::get( 'mshield_address_sensitivity' );
        return isset( self::THRESHOLDS[ $sensitivity ] ) ? self::THRESHOLDS[ $sensitivity ] : self::THRESHOLDS['medium'];

    }

    public static function score_address( $data ) {

        $score   = 0;
        $signals = [];

        // Check billing first name.
        $first = isset( $data['billing_first_name'] ) ? trim( $data['billing_first_name'] ) : '';
        if( mb_strlen( $first ) === 1 ) {
            $score += 2;
            $signals[] = 'single-char first name';
        }

        // Check billing last name.
        $last = isset( $data['billing_last_name'] ) ? trim( $data['billing_last_name'] ) : '';
        if( mb_strlen( $last ) === 1 ) {
            $score += 2;
            $signals[] = 'single-char last name';
        }

        // Check for known fake name patterns.
        $full_name = strtolower( $first . ' ' . $last );
        foreach( self::FAKE_PATTERNS as $pattern ) {
            if( strtolower( $first ) === $pattern || strtolower( $last ) === $pattern || $full_name === $pattern ) {
                $score += 3;
                $signals[] = "fake name pattern: {$pattern}";
                break;
            }
        }

        // Check address line length.
        $address = isset( $data['billing_address_1'] ) ? trim( $data['billing_address_1'] ) : '';
        if( ! empty( $address ) && strlen( $address ) < 5 ) {
            $score += 2;
            $signals[] = 'very short address';
        }

        // Check ZIP/postcode for repeated digits.
        $postcode = isset( $data['billing_postcode'] ) ? trim( $data['billing_postcode'] ) : '';
        if( ! empty( $postcode ) && self::is_repeated_chars( $postcode ) ) {
            $score += 2;
            $signals[] = 'repeated-digit ZIP';
        }

        // Check phone for repeated digits.
        $phone = isset( $data['billing_phone'] ) ? preg_replace( '/[^0-9]/', '', $data['billing_phone'] ) : '';
        if( strlen( $phone ) >= 7 && self::is_repeated_chars( $phone ) ) {
            $score += 2;
            $signals[] = 'repeated-digit phone';
        }

        // Check if billing name matches email local part exactly.
        $email = isset( $data['billing_email'] ) ? $data['billing_email'] : '';
        if( ! empty( $email ) && ! empty( $first ) && ! empty( $last ) ) {
            $local = strtolower( substr( $email, 0, strpos( $email, '@' ) ) );
            $name_combo = strtolower( $first . $last );
            if( $local === $name_combo && strlen( $local ) <= 6 ) {
                $score += 1;
                $signals[] = 'name matches email local part';
            }
        }

        // Check city for suspicious patterns.
        $city = isset( $data['billing_city'] ) ? trim( $data['billing_city'] ) : '';
        if( strlen( $city ) === 1 || ( ! empty( $city ) && self::is_repeated_chars( $city ) ) ) {
            $score += 2;
            $signals[] = 'suspicious city';
        }

        return [ 'score' => $score, 'signals' => $signals ];

    }

    /**
     * Check if a string is made of repeated characters.
     *
     * @since   1.0.0
     *
     * @param   string  $str    String to check.
     * @return  bool
     */
    private static function is_repeated_chars( $str ) {

        $str = preg_replace( '/[^a-z0-9]/i', '', $str );
        if( strlen( $str ) < 3 ) return false;
        return strlen( count_chars( $str, 3 ) ) === 1;

    }

}
