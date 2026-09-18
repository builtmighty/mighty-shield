<?php
/**
 * Setup Wizard.
 *
 * What a merchant sees the first time they activate MightyShield, and the only
 * part of the plugin written on the assumption that they know none of its
 * vocabulary yet.
 *
 * It explains as much as it configures, deliberately. The riskiest thing anyone
 * can do with this plugin is enforce a rule they do not understand: a bot
 * challenge that turns real customers away, an authorize-and-hold on a gateway
 * that cannot do it, a scoring profile that refuses everybody on a VPN. So every
 * step says what the setting does in plain words before offering the control,
 * and the last step -- the one that decides whether any of it acts on a real
 * order -- defaults to observing.
 *
 * Shown to fresh activations only. `mshield_onboarding` is written by
 * activation(), which does not fire on a plugin update, so an existing store is
 * structurally unable to reach it by accident.
 *
 * @package MightyShield
 * @since   2.0.2
 */
namespace MightyShield\Admin;

use MightyShield\Includes\settings;
use MightyShield\Includes\scoring_profiles;
use MightyShield\Protection\challenge;
use MightyShield\Protection\captcha;

class setup_wizard {

    /**
     * This screen's page slug.
     *
     * Also listed in admin_page::SCREENS, which is what gets it the stylesheet,
     * the admin JS, the theme body class and the foreign-notice suppression.
     *
     * @since   2.0.2
     */
    const SLUG = 'mshield-setup';

    /**
     * The option holding the wizard's status: pending, done or skipped.
     *
     * @since   2.0.2
     */
    const OPTION = 'mshield_onboarding';

    /**
     * How far the merchant has got, so leaving and coming back resumes.
     *
     * @since   2.0.2
     */
    const PROGRESS = 'mshield_onboarding_step';

    /**
     * The steps, in order.
     *
     * One list drives the allowlist, the progress counter, next/previous, and
     * the save handler's dispatch. Adding a step here is the whole change.
     *
     * @since   2.0.2
     */
    const STEPS = [ 'welcome', 'scoring', 'challenge', 'alerts', 'protection', 'done' ];

    /**
     * Construct.
     *
     * @since   2.0.2
     */
    public function __construct() {

        add_action( 'admin_menu', [ $this, 'register_menu' ], 99 );
        add_action( 'admin_init', [ $this, 'handle' ] );
        add_action( 'admin_notices', [ __CLASS__, 'render_entry_notice' ] );

    }

    /**
     * Register the screen without putting it in any menu.
     *
     * An EMPTY parent slug, which is the supported way to register a routable
     * page that appears nowhere. Two near misses to avoid:
     *
     * - `null` as the parent is the older idiom, but add_submenu_page() passes
     *   it straight into plugin_basename(), which is a deprecation on PHP 8.1
     *   and above.
     * - Registering under 'woocommerce' and then calling remove_submenu_page()
     *   looks equivalent and is not. The page's own registration does survive in
     *   $_registered_pages, but get_admin_page_parent() works out the parent by
     *   SCANNING $submenu -- the very array remove_submenu_page() empties. With
     *   no parent found it builds the hookname 'admin_page_<slug>' instead of
     *   'woocommerce_page_<slug>', that key is not registered, and every visit
     *   dies with "Sorry, you are not allowed to access this page."
     *
     * With an empty parent the hookname is 'admin_page_<slug>' from the start,
     * which is what gets registered, so the two agree. The capability is still
     * enforced twice: add_submenu_page() refuses to register the page for a user
     * without it, and render() checks again.
     *
     * @since   2.0.2
     */
    public function register_menu() {

        add_submenu_page(
            '',
            __( 'MightyShield setup', 'mighty-shield' ),
            __( 'MightyShield setup', 'mighty-shield' ),
            'manage_woocommerce',
            self::SLUG,
            [ $this, 'render' ]
        );

    }

    /**
     * Whether the wizard still has something to offer.
     *
     * @since   2.0.2
     *
     * @return  bool
     */
    public static function is_pending() {

        return get_option( self::OPTION, '' ) === 'pending';

    }

    /**
     * Whether the merchant walked away from it.
     *
     * @since   2.0.2
     *
     * @return  bool
     */
    public static function was_skipped() {

        return get_option( self::OPTION, '' ) === 'skipped';

    }

    /**
     * The wizard's URL, optionally at a given step.
     *
     * @since   2.0.2
     *
     * @param   string  $step
     * @return  string
     */
    public static function url( $step = '' ) {

        $url = admin_url( 'admin.php?page=' . self::SLUG );

        if( $step !== '' && \in_array( $step, self::STEPS, true ) ) {
            $url = add_query_arg( 'step', $step, $url );
        }

        return $url;

    }

    /**
     * Offer the wizard on other admin screens while it is still pending.
     *
     * The activation redirect only fires once, and it deliberately does not fire
     * on a bulk activation or before WooCommerce is available. This is how
     * somebody in either of those positions finds the wizard at all.
     *
     * Not shown once skipped: that was a decision, and nagging over it is how a
     * plugin teaches merchants to ignore its notices.
     *
     * @since   2.0.2
     */
    public static function render_entry_notice() {

        if( ! self::is_pending() ) return;
        if( ! current_user_can( 'manage_woocommerce' ) ) return;
        if( ! class_exists( 'WooCommerce' ) ) return;

        printf(
            '<div class="notice notice-info"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
            esc_html__( 'MightyShield:', 'mighty-shield' ),
            esc_html__( 'Installed, but not set up yet. The setup takes a couple of minutes and explains what each part does.', 'mighty-shield' ),
            esc_url( self::url() ),
            esc_html__( 'Run setup', 'mighty-shield' )
        );

    }

    /**
     * Which step to draw.
     *
     * The URL wins, so Back, deep links and bookmarks all behave. The stored
     * progress is only a fallback for arriving with no step at all.
     *
     * @since   2.0.2
     *
     * @return  string
     */
    private function current_step() {

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- choosing which page to draw, not acting.
        $step = isset( $_GET['step'] ) ? sanitize_key( wp_unslash( $_GET['step'] ) ) : '';

        if( \in_array( $step, self::STEPS, true ) ) return $step;

        $saved = get_option( self::PROGRESS, '' );

        return \in_array( $saved, self::STEPS, true ) ? $saved : self::STEPS[0];

    }

    /**
     * The step after this one, or '' at the end.
     *
     * @since   2.0.2
     *
     * @param   string  $step
     * @return  string
     */
    private static function next_step( $step ) {

        $at = array_search( $step, self::STEPS, true );

        if( $at === false || $at >= count( self::STEPS ) - 1 ) return '';

        return self::STEPS[ $at + 1 ];

    }

    /**
     * The step before this one, or '' at the start.
     *
     * @since   2.0.2
     *
     * @param   string  $step
     * @return  string
     */
    private static function prev_step( $step ) {

        $at = array_search( $step, self::STEPS, true );

        if( $at === false || $at === 0 ) return '';

        return self::STEPS[ $at - 1 ];

    }

    /**
     * Record how far the merchant has got, never backwards.
     *
     * Going back a step to re-read something must not move the resume pointer
     * back with it.
     *
     * @since   2.0.2
     *
     * @param   string  $step
     */
    private static function advance( $step ) {

        if( ! \in_array( $step, self::STEPS, true ) ) return;

        $now = array_search( get_option( self::PROGRESS, self::STEPS[0] ), self::STEPS, true );
        $to  = array_search( $step, self::STEPS, true );

        if( $now === false || $to > $now ) update_option( self::PROGRESS, $step, false );

    }

    /**
     * Save one step, then move on.
     *
     * Deliberately NOT a Settings API form. options.php writes null over every
     * option registered to a group that the submitted form does not include, and
     * these steps each touch a handful of keys out of groups holding dozens --
     * mshield_scoring alone owns three options per signal. Posting a partial
     * wizard form at options.php would quietly erase most of the Scoring tab.
     *
     * So: own form, own nonce, own explicit key list per step, and update_option
     * directly. Exactly what handle_actions() does for the same reason.
     *
     * @since   2.0.2
     */
    public function handle() {

        // Leaving the wizard entirely. A GET that writes a decision, so nonced.
        if( isset( $_GET['mshield_setup_bail'] ) && isset( $_GET['_wpnonce'] ) ) {

            if( current_user_can( 'manage_woocommerce' )
                && wp_verify_nonce( $_GET['_wpnonce'], 'mshield_setup_bail' ) ) {

                // Skipped, not done. Nothing is configured and nothing is
                // nagged about afterwards -- walking away was a decision, and a
                // plugin that argues with it teaches people to ignore it.
                update_option( self::OPTION, 'skipped', false );

            }

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=dashboard' ) );
            exit;

        }

        if( ! isset( $_POST['mshield_setup_step'] ) ) return;
        if( ! current_user_can( 'manage_woocommerce' ) ) return;

        $step = sanitize_key( wp_unslash( $_POST['mshield_setup_step'] ) );

        // Validated against the list BEFORE it is concatenated into a nonce
        // action, so no request can name the action it wants checked.
        if( ! \in_array( $step, self::STEPS, true ) ) return;

        check_admin_referer( 'mshield_setup_' . $step );

        $skipping = isset( $_POST['mshield_setup_skip'] );
        $message  = '';

        // Skip writes nothing at all. Every setting this wizard touches already
        // has a safe default in settings::$defaults, so a skipped step leaves
        // the store exactly where a considered default put it.
        if( ! $skipping ) $message = $this->save( $step );

        $next = self::next_step( $step );

        if( $next === '' || $step === 'done' ) {

            update_option( self::OPTION, 'done', false );
            update_option( self::PROGRESS, 'done', false );

            set_transient( 'mshield_admin_notice', [ 'setup', __( 'Setup complete. You can change any of it from these tabs at any time.', 'mighty-shield' ), 'success' ], 30 );

            wp_safe_redirect( admin_url( 'admin.php?page=mighty-shield&tab=dashboard' ) );
            exit;

        }

        self::advance( $next );

        if( $message !== '' ) {
            set_transient( 'mshield_admin_notice', [ 'setup', $message, 'success' ], 30 );
        }

        wp_safe_redirect( self::url( $next ) );
        exit;

    }

    /**
     * Write one step's settings, and nothing else.
     *
     * Each branch names its own keys. There is no loop over $_POST anywhere in
     * this class: an option the wizard does not know about cannot be written by
     * asking for it.
     *
     * @since   2.0.2
     *
     * @param   string  $step
     * @return  string  A sentence for the merchant, or ''.
     */
    private function save( $step ) {

        switch( $step ) {

            case 'protection':

                $state   = isset( $_POST['mshield_state'] ) ? sanitize_key( wp_unslash( $_POST['mshield_state'] ) ) : '';
                $message = admin_page::apply_state( $state );

                // A fresh install ships with the Store API firewall on and in
                // allowlist mode, and the allowlist holds only this server. On a
                // store using the block checkout that means no customer can
                // check out at all. checkout_conflict() is the existing warning
                // for it; this is the one place that offers the fix.
                if( isset( $_POST['mshield_fix_checkout'] ) && $_POST['mshield_fix_checkout'] === 'yes' ) {
                    settings::update( 'mshield_firewall_mode', 'blocklist' );
                }

                return $message;

            case 'scoring':

                $profile = isset( $_POST['mshield_profile'] ) ? sanitize_key( wp_unslash( $_POST['mshield_profile'] ) ) : '';

                if( ! scoring_profiles::exists( $profile ) ) return '';

                scoring_profiles::apply( $profile );

                return sprintf(
                    /* translators: %s: profile name. */
                    __( 'Scoring set to %s.', 'mighty-shield' ),
                    scoring_profiles::label( $profile )
                );

            case 'challenge':

                $provider = isset( $_POST['mshield_captcha_provider'] ) ? sanitize_key( wp_unslash( $_POST['mshield_captcha_provider'] ) ) : 'off';

                // Fails to off, never to a provider. A wrong value here would
                // switch on a challenge the merchant did not ask for.
                if( ! \in_array( $provider, [ 'off', 'turnstile', 'recaptcha_v3' ], true ) ) $provider = 'off';

                settings::update( 'mshield_captcha_provider', $provider );

                // Blank means keep, as everywhere else the plugin takes a
                // secret. Walking forward past a masked field must not erase it.
                foreach( [ 'mshield_captcha_site_key', 'mshield_captcha_secret_key' ] as $key ) {

                    $value = isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '';

                    if( $value !== '' ) settings::update( $key, $value );

                }

                // Driven off the canonical map, so a surface added later appears
                // here without anybody remembering to come back.
                foreach( challenge::SURFACES as $option ) {
                    settings::update( $option, admin_page::sanitize_checkbox( $_POST[ $option ] ?? null ) );
                }

                return $provider === 'off'
                    ? __( 'Bot challenge left off.', 'mighty-shield' )
                    : __( 'Bot challenge saved.', 'mighty-shield' );

            case 'alerts':

                settings::update( 'mshield_ai_notify_admin', admin_page::sanitize_checkbox( $_POST['mshield_ai_notify_admin'] ?? null ) );
                settings::update( 'mshield_ai_notify_emails', admin_page::sanitize_email_list( wp_unslash( $_POST['mshield_ai_notify_emails'] ?? '' ) ) );

                return __( 'Notification settings saved.', 'mighty-shield' );

        }

        return '';

    }

    /**
     * Draw the wizard.
     *
     * @since   2.0.2
     */
    public function render() {

        if( ! current_user_can( 'manage_woocommerce' ) ) {
            wp_die( esc_html__( 'You do not have permission to set up MightyShield.', 'mighty-shield' ) );
        }

        $step = $this->current_step();
        $at   = array_search( $step, self::STEPS, true );

        // No tab, so shell_open() draws the header and the notices and neither
        // the tab cards nor the protection hero. Both would be wrong here: the
        // wizard should not offer the tabs it is still explaining, and the hero
        // is the decision its last step exists to make.
        admin_page::shell_open( [ 'nav' => false ] );

        echo '<div class="mshield-setup">';

        self::render_rail( $at );

        echo '<div class="mshield-card mshield-setup-body">';

        include MSHIELD_PATH . 'admin/views/setup/step-' . $step . '.php';

        echo '</div></div>';

        admin_page::shell_close();

    }

    /**
     * The progress rail.
     *
     * @since   2.0.2
     *
     * @param   int     $at     Index of the current step.
     */
    private static function render_rail( $at ) {

        $titles = self::titles();

        printf(
            '<div class="mshield-setup-rail" role="list" aria-label="%s">',
            esc_attr__( 'Setup progress', 'mighty-shield' )
        );

        foreach( self::STEPS as $i => $key ) {

            $class = 'ms-rail-step';
            if( $i <  $at ) $class .= ' is-done';
            if( $i === $at ) $class .= ' is-now';

            printf(
                '<span class="%s" role="listitem"%s><span class="ms-rail-dot" aria-hidden="true"></span><span class="ms-rail-label">%s</span></span>',
                esc_attr( $class ),
                $i === $at ? ' aria-current="step"' : '',
                esc_html( $titles[ $key ] )
            );

        }

        echo '</div>';

    }

    /**
     * Short titles for the rail.
     *
     * @since   2.0.2
     *
     * @return  array
     */
    public static function titles() {

        return [
            'welcome'    => __( 'How it works', 'mighty-shield' ),
            'scoring'    => __( 'Strictness', 'mighty-shield' ),
            'challenge'  => __( 'Bots', 'mighty-shield' ),
            'alerts'     => __( 'Alerts', 'mighty-shield' ),
            'protection' => __( 'Go live', 'mighty-shield' ),
            'done'       => __( 'Finish', 'mighty-shield' ),
        ];

    }

    /**
     * The footer controls every step shares.
     *
     * Continue and Skip are submit buttons on the step's own form, branched on
     * name in handle(). Back is a plain link, because retreating from a
     * half-filled step must not save that half-filled state.
     *
     * @since   2.0.2
     *
     * @param   string  $step
     * @param   bool    $skippable  Whether this step offers "Skip this step".
     */
    public static function render_controls( $step, $skippable = true ) {

        $prev = self::prev_step( $step );
        $last = self::next_step( $step ) === '';

        echo '<div class="mshield-setup-controls">';

        if( $prev !== '' ) {
            printf(
                '<a class="mshield-btn" href="%s">%s</a>',
                esc_url( self::url( $prev ) ),
                esc_html__( '&larr; Back', 'mighty-shield' )
            );
        }

        echo '<span class="mshield-spacer"></span>';

        // Leaving entirely. Nonced, because it writes a decision.
        printf(
            '<a class="mshield-setup-bail" href="%s">%s</a>',
            esc_url( wp_nonce_url( add_query_arg( 'mshield_setup_bail', 1, self::url() ), 'mshield_setup_bail' ) ),
            esc_html__( 'Skip setup', 'mighty-shield' )
        );

        if( $skippable && ! $last ) {
            printf(
                '<button type="submit" name="mshield_setup_skip" value="1" class="mshield-btn">%s</button>',
                esc_html__( 'Skip this step', 'mighty-shield' )
            );
        }

        printf(
            '<button type="submit" name="mshield_setup_next" value="1" class="mshield-btn is-primary">%s</button>',
            $last ? esc_html__( 'Finish', 'mighty-shield' ) : esc_html__( 'Continue &rarr;', 'mighty-shield' )
        );

        echo '</div>';

    }

    /**
     * Open a step's form.
     *
     * @since   2.0.2
     *
     * @param   string  $step
     */
    public static function form_open( $step ) {

        printf( '<form method="post" action="%s">', esc_url( self::url( $step ) ) );

        wp_nonce_field( 'mshield_setup_' . $step );

        printf( '<input type="hidden" name="mshield_setup_step" value="%s" />', esc_attr( $step ) );

    }

}
