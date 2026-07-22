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
        if( ! empty( $postcode ) && $this->is_repeated_chars( $postcode ) ) {
            $score += 2;
            $signals[] = 'repeated-digit ZIP';
        }

        // Check phone for repeated digits.
        $phone = isset( $data['billing_phone'] ) ? preg_replace( '/[^0-9]/', '', $data['billing_phone'] ) : '';
        if( strlen( $phone ) >= 7 && $this->is_repeated_chars( $phone ) ) {
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
        if( strlen( $city ) === 1 || ( ! empty( $city ) && $this->is_repeated_chars( $city ) ) ) {
            $score += 2;
            $signals[] = 'suspicious city';
        }

        // Get threshold based on sensitivity.
        $sensitivity = settings::get( 'mshield_address_sensitivity' );
        $threshold   = isset( self::THRESHOLDS[ $sensitivity ] ) ? self::THRESHOLDS[ $sensitivity ] : self::THRESHOLDS['medium'];

        // Check if score exceeds threshold.
        if( $score >= $threshold ) {

            $ip = ip_utils::get_client_ip();
            db::log_event( $ip, 'classic_checkout', 'blocked', 'Address validation failed (score: ' . $score . '/' . $threshold . '): ' . implode( ', ', $signals ) );

            $errors->add( 'mighty_shield_address', __( 'Please verify your billing information and try again.', 'mighty-shield' ) );

        }

    }

    /**
     * Check if a string is made of repeated characters.
     *
     * @since   1.0.0
     *
     * @param   string  $str    String to check.
     * @return  bool
     */
    private function is_repeated_chars( $str ) {

        $str = preg_replace( '/[^a-z0-9]/i', '', $str );
        if( strlen( $str ) < 3 ) return false;
        return strlen( count_chars( $str, 3 ) ) === 1;

    }

}
