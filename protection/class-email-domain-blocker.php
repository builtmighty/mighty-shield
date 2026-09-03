<?php
/**
 * Email Domain Blocker.
 *
 * Blocks checkout with disposable/temporary email domains.
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

class email_domain_blocker {

    /**
     * Built-in disposable email domains.
     *
     * @since   1.0.0
     */
    private const DISPOSABLE_DOMAINS = [
        'mailinator.com',
        'guerrillamail.com',
        'guerrillamail.net',
        'guerrillamail.org',
        'guerrillamail.de',
        'grr.la',
        'guerrillamailblock.com',
        'tempmail.com',
        'temp-mail.org',
        'temp-mail.io',
        'throwaway.email',
        'throwaway.com',
        'yopmail.com',
        'yopmail.fr',
        'sharklasers.com',
        'guerrillamail.info',
        'maildrop.cc',
        'dispostable.com',
        'mailnesia.com',
        'mailcatch.com',
        'trashmail.com',
        'trashmail.me',
        'trashmail.net',
        'trashmail.org',
        'fakeinbox.com',
        'tempail.com',
        'tempmailaddress.com',
        'emailondeck.com',
        'getnada.com',
        'mohmal.com',
        'discard.email',
        'discardmail.com',
        'discardmail.de',
        'harakirimail.com',
        'mailexpire.com',
        'mailforspam.com',
        'safetymail.info',
        'trashymail.com',
        'trashymail.net',
        'binkmail.com',
        'bobmail.info',
        'chammy.info',
        'devnullmail.com',
        'letthemeatspam.com',
        'mailblocks.com',
        'mailmetrash.com',
        'mytempemail.com',
        'nobulk.com',
        'noclickemail.com',
        'nogmailspam.info',
        'nomail.xl.cx',
        'nospam.ze.tc',
        'owlpic.com',
        'proxymail.eu',
        'rcpt.at',
        'reallymymail.com',
        'rtrtr.com',
        'sharklasers.com',
        'shieldedmail.com',
        'spamavert.com',
        'spambob.com',
        'spamcero.com',
        'spamcorptastic.com',
        'spamcowboy.com',
        'spamcowboy.net',
        'spamcowboy.org',
        'spamday.com',
        'spamfree24.com',
        'spamfree24.de',
        'spamfree24.eu',
        'spamfree24.info',
        'spamfree24.net',
        'spamfree24.org',
        'spamgourmet.com',
        'spamgourmet.net',
        'spamgourmet.org',
        'spamherelots.com',
        'spamhereplease.com',
        'spamhole.com',
        'spamify.com',
        'spaminator.de',
        'spamkill.info',
        'spaml.com',
        'spaml.de',
        'spammotel.com',
        'spamobox.com',
        'spamoff.de',
        'spamslicer.com',
        'spamspot.com',
        'spamstack.net',
        'spamtrail.com',
        'spamtrap.ro',
        'tempr.email',
        'tmail.ws',
        'tmpmail.net',
        'tmpmail.org',
        'boun.cr',
        'bugmenot.com',
        'bumpymail.com',
        'casualdx.com',
        'centermail.com',
        'centermail.net',
        'chogmail.com',
        'cool.fr.nf',
        'correo.blogos.net',
        'cosmorph.com',
        'courriel.fr.nf',
        'courrieltemporaire.com',
        'dandikmail.com',
        'deadaddress.com',
        'despam.it',
        'devnullmail.com',
        'dfgh.net',
        'digitalsanctuary.com',
        'dingbone.com',
        'disposableaddress.com',
        'disposableemailaddresses.emailmiser.com',
        'disposableinbox.com',
        'dispose.it',
        'dm.w3internet.co.uk',
        'dodgeit.com',
        'dodgit.com',
        'dontreg.com',
        'dontsendmespam.de',
        'drdrb.com',
        'dump-email.info',
        'dumpandjunk.com',
        'dumpmail.de',
        'dumpyemail.com',
        'e4ward.com',
        'easytrashmail.com',
        'emailgo.de',
        'emailias.com',
        'emailigo.de',
        'emailinfive.com',
        'emaillime.com',
        'emailmiser.com',
        'emailproxsy.com',
        'emailsensei.com',
        'emailtemporario.com.br',
        'emailto.de',
        'emailwarden.com',
        'emailx.at.hm',
        'emailxfer.com',
        'emz.net',
        'enterto.com',
        'ephemail.net',
        'etranquil.com',
        'etranquil.net',
        'etranquil.org',
        'evopo.com',
        'explodemail.com',
        'express.net.ua',
        'eyepaste.com',
        'fastacura.com',
        'filzmail.com',
        'fixmail.tk',
        'flurred.com',
        'flyspam.com',
        'getairmail.com',
        'getmails.eu',
        'getonemail.com',
        'getonemail.net',
        'girlsundertheinfluence.com',
        'gishpuppy.com',
        'goemailgo.com',
        'great-host.in',
        'greensloth.com',
        'haltospam.com',
        'hotpop.com',
        'ichimail.com',
        'imails.info',
        'inbax.tk',
        'inbox.si',
        'incognitomail.com',
        'incognitomail.net',
        'incognitomail.org',
    ];

    /**
     * Construct.
     *
     * @since   1.0.0
     */
    public function __construct() {

        // Check email during checkout validation.
        add_action( 'woocommerce_after_checkout_validation', [ $this, 'check_email' ], 10, 2 );

    }

    /**
     * Check billing email domain.
     *
     * @since   1.0.0
     *
     * @param   array    $data   Checkout posted data.
     * @param   object   $errors WP_Error object.
     */
    public function check_email( $data, $errors ) {

        if( \MightyShield\Includes\exempt::is_exempt( $data['billing_email'] ?? '' ) ) return;

        $email = isset( $data['billing_email'] ) ? $data['billing_email'] : '';
        if( empty( $email ) ) return;

        if( self::is_disposable_email( $email ) ) {

            $ip     = ip_utils::get_client_ip();
            $domain = strtolower( substr( strrchr( $email, '@' ), 1 ) );
            risk_context::add( 'email_disposable', "Disposable or blocked email domain: {$domain}" );

            db::log_event( $ip, 'classic_checkout', 'blocked', "Disposable email domain: {$domain}" );

            $errors->add( 'mighty_shield_email', response::with_note( __( 'Please use a valid, non-disposable email address.', 'mighty-shield' ) ) );

        }

    }

    /**
     * Whether an email uses a blocked/disposable domain.
     *
     * Reusable by both classic checkout and the Store API (block) checkout.
     *
     * @since   1.8.0
     *
     * @param   string  $email  Email address.
     * @return  bool
     */
    public static function is_disposable_email( $email ) {

        $email = strtolower( trim( (string) $email ) );
        if( $email === '' || strpos( $email, '@' ) === false ) return false;

        $domain = substr( strrchr( $email, '@' ), 1 );
        if( $domain === '' ) return false;

        return in_array( $domain, self::get_blocked_domains(), true );

    }

    /**
     * Get all blocked email domains.
     *
     * Combines built-in list with admin-configured domains.
     *
     * @since   1.0.0
     *
     * @return  array
     */
    public static function get_blocked_domains() {

        $domains = self::DISPOSABLE_DOMAINS;

        // Add admin-configured domains.
        $custom = settings::get( 'mshield_blocked_email_domains' );
        if( ! empty( $custom ) ) {
            $custom_domains = array_map( 'trim', explode( "\n", strtolower( $custom ) ) );
            $custom_domains = array_filter( $custom_domains );
            $domains = array_merge( $domains, $custom_domains );
        }

        // Allow filtering.
        $domains = apply_filters( 'mighty_shield_blocked_email_domains', $domains );

        return array_unique( $domains );

    }

}
