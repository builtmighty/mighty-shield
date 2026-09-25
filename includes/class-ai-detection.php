<?php
/**
 * Address helpers.
 *
 * What is left of the old AI-detection scorer. Its four checks moved to
 * protection/class-order-signals.php in 1.9.2, where they run on every checkout
 * instead of only when AI review was switched on, and its own 0-10 suspicion
 * score was retired: the plugin now has one scale, the 1-100 trust rating.
 *
 * These two helpers stay because they are used independently of any of that —
 * by class-entities.php to derive identities, and by the AI prompt builder to
 * format an address.
 *
 * @package MightyShield
 * @since   1.8.0
 */
namespace MightyShield\Includes;

defined( 'ABSPATH' ) || exit;

class ai_detection {

    /**
     * Tokens that mean the same thing on an envelope, folded to one spelling.
     *
     * USPS Publication 28's common street suffixes, directionals and unit
     * designators. A drop address is one real place; what varies between the
     * orders sent to it is the spelling -- "Terrace", "Terr.", "TER" -- and
     * each spelling used to be a different identity in the graph, so an
     * address with three chargebacks behind it matched a fourth order only
     * when the fraudster typed it the same way. Whole tokens only, so "Stone
     * Street" becomes "stone st" and not "sne st". Non-English addresses
     * carry none of these tokens and pass through unchanged.
     *
     * Changing this changes every address hash, which is why schema 10
     * re-hashes the graph in place: see entities::maybe_rehash_addresses().
     *
     * @since   2.3.0
     */
    private const ADDRESS_TOKENS = [
        // Suffixes.
        'street' => 'st', 'str' => 'st', 'avenue' => 'ave', 'av' => 'ave', 'aven' => 'ave',
        'boulevard' => 'blvd', 'boul' => 'blvd', 'blv' => 'blvd', 'drive' => 'dr', 'drv' => 'dr',
        'road' => 'rd', 'lane' => 'ln', 'court' => 'ct', 'crt' => 'ct', 'circle' => 'cir', 'circ' => 'cir',
        'place' => 'pl', 'terrace' => 'ter', 'terr' => 'ter', 'parkway' => 'pkwy', 'pkway' => 'pkwy', 'pky' => 'pkwy',
        'highway' => 'hwy', 'hiway' => 'hwy', 'square' => 'sq', 'sqr' => 'sq', 'trail' => 'trl', 'expressway' => 'expy',
        'freeway' => 'fwy', 'alley' => 'aly', 'plaza' => 'plz', 'crossing' => 'xing', 'extension' => 'ext',
        'heights' => 'hts', 'junction' => 'jct', 'mount' => 'mt', 'mountain' => 'mtn', 'point' => 'pt',
        'ridge' => 'rdg', 'station' => 'sta', 'turnpike' => 'tpke', 'valley' => 'vly', 'village' => 'vlg',
        'center' => 'ctr', 'centre' => 'ctr', 'estates' => 'ests', 'gardens' => 'gdns', 'grove' => 'grv',
        'harbor' => 'hbr', 'harbour' => 'hbr', 'hills' => 'hls', 'landing' => 'lndg', 'meadows' => 'mdws',
        'springs' => 'spgs', 'summit' => 'smt',
        // Directionals.
        'north' => 'n', 'south' => 's', 'east' => 'e', 'west' => 'w',
        'northeast' => 'ne', 'northwest' => 'nw', 'southeast' => 'se', 'southwest' => 'sw',
        // Unit designators.
        'apartment' => 'apt', 'suite' => 'ste', 'floor' => 'fl', 'building' => 'bldg', 'room' => 'rm',
        'department' => 'dept', 'basement' => 'bsmt', 'penthouse' => 'ph', 'space' => 'spc', 'trailer' => 'trlr',
    ];

    /**
     * Read a shipping field, falling back to billing.
     *
     * Virtual and downloadable orders leave shipping blank rather than
     * mirroring billing, so every shipping read goes through here — otherwise
     * three of the four signals silently never trip on those orders.
     *
     * @since   1.8.0
     *
     * @param   \WC_Order   $order
     * @param   string      $field  Field suffix, e.g. 'city'.
     * @return  string
     */
    public static function shipping_or_billing( $order, $field ) {

        $ship = 'get_shipping_' . $field;
        $bill = 'get_billing_' . $field;

        $value = method_exists( $order, $ship ) ? trim( (string) $order->$ship() ) : '';
        if( $value !== '' ) return $value;

        return method_exists( $order, $bill ) ? trim( (string) $order->$bill() ) : '';

    }

    /**
     * Normalize a street address for comparison.
     *
     * "123 Main St." and "123  main st" must compare equal — WooCommerce order
     * queries match addresses exactly, so the real comparison happens here.
     *
     * @since   1.8.0
     *
     * @param   string  $address
     * @return  string
     */
    public static function normalize_address( $address ) {

        // Letters and digits in any script. The ASCII-only version stripped a
        // Cyrillic, Greek, Arabic or CJK street down to its house number, so
        // every "number 12" in a postcode became one address identity and one
        // neighbour's chargeback landed on the rest of the street.
        $address = function_exists( 'mb_strtolower' ) ? mb_strtolower( trim( $address ), 'UTF-8' ) : strtolower( trim( $address ) );
        $address = (string) preg_replace( '/[^\p{L}\p{N} ]/u', '', $address );
        $address = (string) preg_replace( '/\s+/u', ' ', $address );

        // Fold the spellings that mean the same thing. See ADDRESS_TOKENS.
        $tokens = explode( ' ', $address );

        foreach( $tokens as &$token ) {
            if( isset( self::ADDRESS_TOKENS[ $token ] ) ) $token = self::ADDRESS_TOKENS[ $token ];
        }
        unset( $token );

        return implode( ' ', $tokens );

    }

}
