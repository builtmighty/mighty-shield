<?php
/**
 * Bot challenge on the spam surfaces.
 *
 * Checkout is not the only thing worth defending. Credential stuffing hits the
 * login form, bulk fake accounts hit registration, and comment spam hits the
 * comment form — none of which this plugin touched until 1.9.4. account_guard
 * already COUNTS failed logins and new accounts, but only ever to inform a
 * later checkout; nothing on those surfaces refused anything.
 *
 * Each surface is separately switchable and each honours the allowlist first,
 * like every other layer. The verification itself is captcha::passes(), which
 * fails open on a provider outage or a misconfigured key — a challenge that
 * silently refuses everyone would be a far worse outage than the spam.
 *
 * @package MightyShield
 * @since   1.9.4
 */
namespace MightyShield\Protection;

use MightyShield\Includes\db;
use MightyShield\Includes\settings;
use MightyShield\Includes\exempt;
use MightyShield\Includes\ip_utils;

class challenge {

    /**
     * surface => the option that switches it on.
     *
     * @since   1.9.4
     */
    const SURFACES = [
        'login'        => 'mshield_captcha_on_login',
        'register'     => 'mshield_captcha_on_register',
        'lostpassword' => 'mshield_captcha_on_lostpassword',
        'comment'      => 'mshield_captcha_on_comments',
    ];

    /**
     * Construct.
     *
     * @since   1.9.4
     */
    public function __construct() {

        // No provider, no widget to draw and nothing to verify.
        if( ! captcha::is_ready() ) return;

        if( self::on( 'login' ) ) {
            add_action( 'login_form',            [ $this, 'render_login' ] );
            add_action( 'woocommerce_login_form', [ $this, 'render_login' ] );
            // Priority 30: after WordPress has checked the password, so a bad
            // password still reports a bad password. Failing earlier would turn
            // every wrong password into "bot verification failed".
            add_filter( 'authenticate',          [ $this, 'check_login' ], 30, 3 );
        }

        if( self::on( 'register' ) ) {
            add_action( 'register_form',              [ $this, 'render_register' ] );
            add_action( 'woocommerce_register_form',  [ $this, 'render_register' ] );
            add_filter( 'registration_errors',        [ $this, 'check_register' ], 10, 3 );
            add_action( 'woocommerce_register_post',  [ $this, 'check_register_woo' ], 10, 3 );
        }

        if( self::on( 'lostpassword' ) ) {
            add_action( 'lostpassword_form',  [ $this, 'render_lostpassword' ] );
            add_action( 'lostpassword_post',  [ $this, 'check_lostpassword' ], 10, 1 );
        }

        if( self::on( 'comment' ) ) {
            add_action( 'comment_form_after_fields',          [ $this, 'render_comment' ] );
            add_action( 'comment_form_logged_in_after',       [ $this, 'render_comment' ] );
            add_filter( 'preprocess_comment',                 [ $this, 'check_comment' ], 10, 1 );
        }

        // wp-login.php does not run wp_enqueue_scripts for the theme, so the
        // provider script has to be asked for on its own hook.
        add_action( 'login_enqueue_scripts', [ $this, 'enqueue_login' ] );

    }

    /**
     * Whether a surface is switched on.
     *
     * @since   1.9.4
     *
     * @param   string  $surface
     * @return  bool
     */
    public static function on( $surface ) {

        if( ! isset( self::SURFACES[ $surface ] ) ) return false;

        return settings::get( self::SURFACES[ $surface ] ) === 'yes';

    }

    /**
     * Whether this visitor should be challenged at all.
     *
     * Allowlisted addresses, and anyone already signed in, are left alone: a
     * logged-in customer posting a comment has already proved more than a
     * challenge would.
     *
     * @since   1.9.4
     *
     * @param   string  $surface
     * @return  bool
     */
    private static function applies( $surface ) {

        if( ! self::on( $surface ) ) return false;
        if( ! captcha::is_ready() ) return false;

        return ! exempt::is_exempt();

    }

    /**
     * Enqueue on wp-login.php.
     *
     * @since   1.9.4
     */
    public function enqueue_login() {

        foreach( [ 'login', 'register', 'lostpassword' ] as $surface ) {
            if( self::applies( $surface ) ) {
                captcha::enqueue( $surface );
                return;
            }
        }

    }

    /**
     * Widget renderers. One per surface so the action string is right — a
     * token minted for one form must not verify against another.
     *
     * @since   1.9.4
     */
    public function render_login()        { if( self::applies( 'login' ) )        captcha::widget( 'login' ); }
    public function render_register()     { if( self::applies( 'register' ) )     captcha::widget( 'register' ); }
    public function render_lostpassword() { if( self::applies( 'lostpassword' ) ) captcha::widget( 'lostpassword' ); }
    public function render_comment()      { if( self::applies( 'comment' ) )      captcha::widget( 'comment' ); }

    /**
     * Refuse a login whose challenge failed.
     *
     * @since   1.9.4
     *
     * @param   null|\WP_User|\WP_Error $user
     * @param   string                  $username
     * @param   string                  $password
     * @return  null|\WP_User|\WP_Error
     */
    public function check_login( $user, $username, $password ) {

        // Nothing was submitted (an XML-RPC or application-password request,
        // or a cookie check), so there is no form and no challenge to fail.
        if( empty( $_POST['log'] ) && empty( $_POST['username'] ) ) return $user;

        // Already failing for another reason. Leave that reason intact rather
        // than replacing "wrong password" with "verification failed".
        if( is_wp_error( $user ) ) return $user;

        if( ! self::applies( 'login' ) ) return $user;
        if( captcha::passes( 'login' ) )  return $user;

        self::record( 'login', $username );

        return new \WP_Error( 'mshield_challenge', self::message() );

    }

    /**
     * Refuse a WordPress registration whose challenge failed.
     *
     * @since   1.9.4
     *
     * @param   \WP_Error   $errors
     * @param   string      $login
     * @param   string      $email
     * @return  \WP_Error
     */
    public function check_register( $errors, $login, $email ) {

        if( ! self::applies( 'register' ) ) return $errors;
        if( captcha::passes( 'register' ) ) return $errors;

        self::record( 'registration', $email );

        $errors->add( 'mshield_challenge', self::message() );

        return $errors;

    }

    /**
     * Refuse a WooCommerce registration whose challenge failed.
     *
     * @since   1.9.4
     *
     * @param   string      $login
     * @param   string      $email
     * @param   \WP_Error   $errors
     */
    public function check_register_woo( $login, $email, $errors ) {

        if( ! self::applies( 'register' ) ) return;
        if( captcha::passes( 'register' ) ) return;

        self::record( 'registration', $email );

        $errors->add( 'mshield_challenge', self::message() );

    }

    /**
     * Refuse a password reset whose challenge failed.
     *
     * @since   1.9.4
     *
     * @param   \WP_Error   $errors
     */
    public function check_lostpassword( $errors ) {

        if( ! self::applies( 'lostpassword' ) ) return;
        if( captcha::passes( 'lostpassword' ) ) return;

        self::record( 'lostpassword', isset( $_POST['user_login'] ) ? sanitize_text_field( wp_unslash( $_POST['user_login'] ) ) : '' );

        if( is_wp_error( $errors ) ) $errors->add( 'mshield_challenge', self::message() );

    }

    /**
     * Hold a comment whose challenge failed.
     *
     * Held, not refused. A false positive here costs a real reader the comment
     * they just wrote, with no way to recover it — the moderation queue keeps
     * it and puts a human in the loop, which is what the queue is for.
     *
     * @since   1.9.4
     *
     * @param   array   $comment
     * @return  array
     */
    public function check_comment( $comment ) {

        if( ! self::applies( 'comment' ) ) return $comment;
        if( captcha::passes( 'comment' ) )  return $comment;

        self::record( 'comment', $comment['comment_author_email'] ?? '' );

        // 0 = held for moderation. WordPress reads this later in wp_allow_comment.
        add_filter( 'pre_comment_approved', '__return_zero', 99 );

        return $comment;

    }

    /**
     * The message shown when a challenge fails.
     *
     * Deliberately says what happened rather than accusing the visitor — the
     * usual cause is a blocked third-party script, not a bot.
     *
     * @since   1.9.4
     *
     * @return  string
     */
    private static function message() {

        return __( 'We could not verify that you are a person. Please reload the page and try again.', 'mighty-shield' );

    }

    /**
     * Log a failed challenge.
     *
     * @since   1.9.4
     *
     * @param   string  $endpoint
     * @param   string  $who
     */
    private static function record( $endpoint, $who ) {

        db::log_event(
            ip_utils::get_client_ip(),
            $endpoint,
            $endpoint === 'comment' ? 'flagged' : 'blocked',
            sprintf(
                'Bot challenge failed (%s)%s',
                settings::get( 'mshield_captcha_provider' ),
                $who !== '' ? ': ' . $who : ''
            )
        );

    }

}
