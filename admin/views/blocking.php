<?php
/**
 * Blocking tab.
 *
 * Where the trust rating becomes an action. The headline setting is the
 * observe/enforce switch, because nothing here does anything until it is
 * flipped — deliberately, so thresholds can be tuned against real traffic
 * before they are trusted with revenue.
 *
 * One form spanning several .mshield-section blocks, matching how every other
 * settings tab in the plugin is built.
 *
 * @package MightyShield
 * @since   1.9.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\risk_levels;
use MightyShield\Includes\settings;
use MightyShield\Includes\db;
use MightyShield\Includes\actions;
use MightyShield\Includes\response;

$level_rows = db::get_risk_level_stats( 30 );

// Roll the level/outcome pairs up into a per-level summary.
$by_level = [];
foreach( $level_rows as $row ) {
    $b = $row['risk_level'];
    if( ! isset( $by_level[ $b ] ) ) $by_level[ $b ] = [ 'total' => 0, 'outcomes' => [] ];
    $by_level[ $b ]['total'] += (int) $row['total'];
    if( $row['outcome'] !== '' ) {
        $by_level[ $b ]['outcomes'][ $row['outcome'] ] = (int) $row['total'];
    }
}
?>

<form method="post" action="options.php">
    <?php settings_fields( 'mshield_blocking' ); ?>

    <?php /* The Enforcement panel that used to open this page held the
             observe/enforce radios — a second control for what the dashboard's
             protection switch now owns. It is gone, and so is its
             register_setting() call: an option registered to this group but
             absent from the form gets update_option( $option, null ) on save,
             and this one's sanitiser turns null into 'observe', so every save
             of this page would have quietly dropped the store out of enforce. */ ?>

    <div class="mshield-section">

        <h2><?php esc_html_e( 'Risk Levels', 'mighty-shield' ); ?></h2>

        <p class="description">
            <?php esc_html_e( 'An order falls to the most severe risk level whose threshold its rating is at or below, and that level decides what happens to it. Rejected and Banned are fixed: they are refused before an order exists, so your payment processor is never contacted.', 'mighty-shield' ); ?>
            <?php printf(
                wp_kses_post( __( 'Some actions depend on your processor; which of yours can do what is on the <a href="%s">Payment</a> tab.', 'mighty-shield' ) ),
                esc_url( admin_url( 'admin.php?page=mighty-shield&tab=payment' ) )
            ); ?>
        </p>

        <div class="mshield-tablewrap">
        <table class="mshield-table">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Risk Level', 'mighty-shield' ); ?></th>
                    <th style="width:110px;"><?php esc_html_e( 'Trust at or below', 'mighty-shield' ); ?></th>
                    <?php /* No AI column any more. Which levels go to review is an
                             AI-review setting, so it lives on the AI Review tab as one
                             "Send to Review" control -- five pills in a row rather than
                             a checkbox per row here, and one page to look at when the
                             question is "what does the model see". */ ?>
                    <th style="width:230px;"><?php esc_html_e( 'Action', 'mighty-shield' ); ?></th>
                    <th style="width:120px;"><?php esc_html_e( 'Reaches processor', 'mighty-shield' ); ?></th>
                    <th style="width:170px;"><?php esc_html_e( 'Last 30 days', 'mighty-shield' ); ?></th>
                </tr>
            </thead>
            <tbody>

            <?php foreach( risk_levels::LADDER as $key => $level ) :

                $threshold    = risk_levels::threshold( $key );
                $stat         = $by_level[ $key ] ?? null;
                $configurable = in_array( $key, risk_levels::CONFIGURABLE, true );
                $current      = risk_levels::action( $key );
                $fallback     = actions::fallback( $current );
                ?>

                <tr>
                    <td>
                        <span class="mshield-sig-name"><?php echo esc_html( $level['label'] ); ?></span>
                        <span class="mshield-tip" tabindex="0" role="note"
                              aria-label="<?php echo esc_attr( $level['description'] ); ?>"
                              data-tip="<?php echo esc_attr( $level['description'] ); ?>">?</span>
                    </td>

                    <td>
                        <?php if( $threshold !== null ) : ?>
                            <input type="number" min="1" max="100"
                                   name="mshield_level_<?php echo esc_attr( $key ); ?>_threshold"
                                   value="<?php echo esc_attr( (int) $threshold ); ?>" />
                        <?php elseif( $key === risk_levels::TRUSTED ) : ?>
                            <span class="mshield-hint" role="img"
                                  aria-label="<?php esc_attr_e( 'Above the Low threshold', 'mighty-shield' ); ?>"
                                  title="<?php esc_attr_e( 'Above the Low threshold', 'mighty-shield' ); ?>">+</span>
                        <?php else : ?>
                            <span class="mshield-hint" role="img"
                                  aria-label="<?php esc_attr_e( 'Reachable only from a signal, never from a rating', 'mighty-shield' ); ?>"
                                  title="<?php esc_attr_e( 'Reachable only from a signal, never from a rating', 'mighty-shield' ); ?>">🚫</span>
                        <?php endif; ?>

                        <?php /* There used to be a hidden mshield_level_*_ai field here,
                                 carrying the value past a save that did not render the
                                 control -- because the option was registered to THIS
                                 page's group, and options.php nulls anything in a group
                                 the submitted form omits. The option moved to the AI
                                 group with the control, so the compensation is not
                                 needed and would now be the thing causing the bug. */ ?>
                    </td>

                    <td>
                        <?php if( ! $configurable ) : ?>
                            <?php /* Refusing IS the level. There is nothing to choose. */ ?>
                            <span class="mshield-sig-name"><?php echo esc_html( actions::label( $current ) ); ?></span>
                            <span class="mshield-hint"><?php esc_html_e( 'Fixed. This level is defined by what it does.', 'mighty-shield' ); ?></span>
                        <?php else : ?>
                            <?php
                            $choices   = [];
                            $unusable  = [];

                            foreach( actions::keys() as $act ) {

                                if( actions::is_available( $act ) ) {
                                    $choices[ $act ] = actions::label( $act );
                                    continue;
                                }

                                $unusable[] = actions::label( $act );

                                // An action nothing can perform is left OUT of
                                // the cycle rather than shown greyed: the
                                // sanitiser refuses it, so offering it would be
                                // a step you can take, save, and watch revert.
                                // The one exception is a value already stored --
                                // dropping that would misreport what is set.
                                if( $act === $current ) $choices[ $act ] = actions::label( $act );

                            }

                            $ckeys = array_keys( $choices );
                            $at    = array_search( $current, $ckeys, true );
                            if( $at === false ) $at = 0;
                            ?>
                            <?php /* Same control as Scoring's Force level, minus the
                                     colour coding -- an action is a choice, not a
                                     severity, so there is no ramp to follow. */ ?>
                            <div class="mshield-stepper is-plain" role="group"
                                 aria-label="<?php echo esc_attr( sprintf(
                                     /* translators: %s: risk level name. */
                                     __( 'Action for %s', 'mighty-shield' ),
                                     $level['label']
                                 ) ); ?>"
                                 data-choices="<?php echo esc_attr( wp_json_encode( $choices ) ); ?>">

                                <button type="button" class="ms-step is-down"
                                        aria-label="<?php esc_attr_e( 'Previous action', 'mighty-shield' ); ?>"
                                        <?php disabled( $at === 0 ); ?>>
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                                         stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                        <path d="M15 6l-6 6 6 6"></path>
                                    </svg>
                                </button>

                                <span class="ms-value s-<?php echo esc_attr( $current ); ?>" aria-live="polite">
                                    <?php echo esc_html( actions::label( $current ) ); ?>
                                </span>

                                <button type="button" class="ms-step is-up"
                                        aria-label="<?php esc_attr_e( 'Next action', 'mighty-shield' ); ?>"
                                        <?php disabled( $at === count( $ckeys ) - 1 ); ?>>
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                                         stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                        <path d="M9 6l6 6-6 6"></path>
                                    </svg>
                                </button>

                                <input type="hidden" name="mshield_level_<?php echo esc_attr( $key ); ?>_action"
                                       value="<?php echo esc_attr( $current ); ?>" />
                            </div>

                            <?php if( ! empty( $unusable ) ) : ?>
                                <span class="mshield-hint">
                                    <?php printf(
                                        /* translators: %s: comma-separated action names. */
                                        esc_html__( 'Not offered here, because no active payment method can do it: %s.', 'mighty-shield' ),
                                        esc_html( implode( ', ', array_unique( $unusable ) ) )
                                    ); ?>
                                </span>
                            <?php endif; ?>

                            <span class="mshield-hint">
                                <?php echo esc_html( actions::desc( $current ) ); ?>
                            </span>

                            <?php /* What happens to the money, which is the difference that
                                     actually matters between the three holds -- actions::CATALOG
                                     has carried this field all along and its own docblock says it
                                     is "displayed". It was not: actions::money() had no callers,
                                     so the one control on this page that decides whether a card is
                                     charged, merely authorized, or left alone said nothing about
                                     which. */ ?>
                            <?php $mshield_money = actions::money( $current ); ?>
                            <?php if( $mshield_money !== '' ) : ?>
                                <span class="mshield-hint">
                                    <strong><?php esc_html_e( 'The money:', 'mighty-shield' ); ?></strong>
                                    <?php echo esc_html( $mshield_money ); ?>
                                </span>
                            <?php endif; ?>

                            <?php if( $fallback !== '' && ! actions::is_available( $current ) ) : ?>
                                <span class="mshield-hint">
                                    <strong><?php esc_html_e( 'No active payment method can do this.', 'mighty-shield' ); ?></strong>
                                    <?php printf(
                                        /* translators: %s: name of the fallback action. */
                                        esc_html__( 'These orders will be handled as "%s" instead.', 'mighty-shield' ),
                                        esc_html( actions::label( $fallback ) )
                                    ); ?>
                                </span>
                            <?php elseif( $fallback !== '' ) : ?>
                                <span class="mshield-hint">
                                    <?php printf(
                                        /* translators: %s: name of the fallback action. */
                                        esc_html__( 'Payment methods that cannot do this fall back to "%s".', 'mighty-shield' ),
                                        esc_html( actions::label( $fallback ) )
                                    ); ?>
                                </span>
                            <?php endif; ?>
                        <?php endif; ?>
                    </td>


                    <td>
                        <?php /* Coloured by what happens to the order, not by whether
                                 that is good news: green means it goes through to the
                                 processor, red means it is stopped before it gets there. */ ?>
                        <?php if( actions::contacts_gateway( $current ) ) : ?>
                            <span class="mshield-pill is-ok"><span class="dot"></span><?php esc_html_e( 'Allowed', 'mighty-shield' ); ?></span>
                        <?php else : ?>
                            <span class="mshield-pill is-danger"><span class="dot"></span><?php esc_html_e( 'Blocked', 'mighty-shield' ); ?></span>
                        <?php endif; ?>
                    </td>

                    <td>
                        <?php if( ! $stat ) : ?>
                            <span class="mshield-pill">&mdash;</span>
                        <?php else :
                            $approved = (int) ( $stat['outcomes']['approved'] ?? 0 );
                            $bad      = (int) ( $stat['outcomes']['chargeback'] ?? 0 ) + (int) ( $stat['outcomes']['denied'] ?? 0 );
                            ?>
                            <span class="mshield-pill">
                                <?php
                                printf(
                                    /* translators: %s: number of orders. */
                                    esc_html__( '%s orders', 'mighty-shield' ),
                                    esc_html( number_format_i18n( $stat['total'] ) )
                                );
                                ?>
                            </span>
                            <?php if( $approved || $bad ) : ?>
                                <span class="mshield-hint">
                                    <?php
                                    printf(
                                        /* translators: 1: count that turned out fine, 2: count that turned out bad. */
                                        esc_html__( '%1$d turned out fine, %2$d turned out bad', 'mighty-shield' ),
                                        $approved,
                                        $bad
                                    );
                                    ?>
                                </span>
                            <?php endif; ?>
                        <?php endif; ?>
                    </td>
                </tr>

            <?php endforeach; ?>

            </tbody>
        </table>
        </div>

        <p class="description" style="margin-top:12px;">
            <?php esc_html_e( 'Use the last column to tune. Plenty of High orders that you went on to approve means the threshold is too cautious and you are holding real customers. Orders that stayed in Low and later turned out bad means it is too generous.', 'mighty-shield' ); ?>
        </p>

    </div>

    <div class="mshield-section">

        <h2><?php esc_html_e( 'Store API Firewall', 'mighty-shield' ); ?></h2>

        <p class="description"><?php esc_html_e( 'Controls access to the WooCommerce Store API cart and checkout endpoints (/wc/store/v1/…). Choose the mode that matches your checkout.', 'mighty-shield' ); ?></p>

        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html_e( 'Block Store API', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_block_store_api" value="no" />
                        <input type="checkbox" name="mshield_block_store_api" value="yes" <?php checked( settings::get( 'mshield_block_store_api' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Enable Store API access control.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Firewall Mode', 'mighty-shield' ); ?></th>
                <td>
                    <?php \MightyShield\Admin\admin_page::radios( 'mshield_firewall_mode', [
                        'whitelist' => __( 'Classic checkout: block all non-allowlisted IPs', 'mighty-shield' ),
                        'blocklist' => __( 'Block/One-page checkout: allow shoppers, block only blocklisted IPs', 'mighty-shield' ),
                    ], settings::get( 'mshield_firewall_mode' ) ); ?>
                    <p class="description"><?php esc_html_e( 'Use "Classic checkout" only if real customers never use the Store API (shortcode/classic checkout). If your store uses the block-based Checkout, choose the block/one-page option so real shoppers are not blocked.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>

    </div>

    <div class="mshield-section">

        <h2><?php esc_html_e( 'Block Checkout Protection', 'mighty-shield' ); ?></h2>

        <p class="description"><?php esc_html_e( 'Run the fraud checks on the block-based Checkout, which submits through the Store API. Every check works there, including the ones that need something from the browser: the checkout timer, the device check, the hidden decoy field and the bot challenge. The same order is judged the same way whichever checkout your store uses.', 'mighty-shield' ); ?></p>

        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html_e( 'Enable Store API checks', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_store_api_checks" value="no" />
                        <input type="checkbox" name="mshield_store_api_checks" value="yes" <?php checked( settings::get( 'mshield_store_api_checks' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Apply the server-side fraud checks to block-based (Store API) checkout.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
        </table>

    </div>

    <?php
    $cap_provider = settings::get( 'mshield_captcha_provider' );
    $cap_hide     = function( $key ) use ( $cap_provider ) {
        // Hidden server-side as well as by the JS below, so switching provider
        // does not flash the wrong keys on load.
        return $cap_provider === $key ? '' : ' style="display:none;"';
    };
    ?>

    <div class="mshield-section">

        <h2><?php esc_html_e( 'Bot Challenge', 'mighty-shield' ); ?></h2>

        <?php
        /* What it has actually been doing. The plugin recommends this control
           above all the others and used to show nothing at all about whether it
           was working -- while AI and address verification each get a Test
           Connection button. Everything here was already being recorded. */
        $mshield_cap = \MightyShield\Protection\captcha::status();
        ?>

        <div class="mshield-banner<?php echo $mshield_cap['ready'] ? '' : ' is-warning'; ?>" style="margin-bottom:16px">
            <div>
                <?php if( ! $mshield_cap['ready'] ) : ?>

                    <strong><?php esc_html_e( 'Not running.', 'mighty-shield' ); ?></strong>
                    <?php esc_html_e( 'Pick a provider and save both keys below. Until then nothing is challenged and no order is affected.', 'mighty-shield' ); ?>

                <?php else : ?>

                    <strong><?php esc_html_e( 'Running.', 'mighty-shield' ); ?></strong>
                    <?php
                    printf(
                        /* translators: 1: number refused, 2: number unconfirmed, 3: number of days. */
                        esc_html__( 'In the last %3$d days it turned away %1$d visitors, and %2$d more could not be confirmed either way.', 'mighty-shield' ),
                        (int) $mshield_cap['refused'],
                        (int) $mshield_cap['unconfirmed'],
                        (int) $mshield_cap['days']
                    );
                    ?>

                    <?php if( (int) $mshield_cap['unconfirmed'] > 0 && (int) $mshield_cap['refused'] === 0 ) : ?>
                        <br />
                        <?php esc_html_e( 'Nothing has been turned away, which usually means the widget is not reaching your forms rather than that nobody has tried. Check the Logs tab, filtered to Needs attention.', 'mighty-shield' ); ?>
                    <?php endif; ?>

                    <?php if( ! empty( $mshield_cap['open'] ) ) : ?>
                        <br />
                        <strong><?php esc_html_e( 'Currently letting everybody through on:', 'mighty-shield' ); ?></strong>
                        <?php echo esc_html( implode( ', ', $mshield_cap['open'] ) ); ?>.
                        <?php esc_html_e( 'A run of failures from different networks with none passing means the keys are the likelier fault, so it stopped refusing people there. One success puts it back.', 'mighty-shield' ); ?>
                    <?php endif; ?>

                <?php endif; ?>
            </div>
        </div>

        <p class="description">
            <?php esc_html_e( 'A challenge from Cloudflare or Google, shown to visitors so software can be told apart from people. It guards checkout and, below, the other places spam arrives.', 'mighty-shield' ); ?>
        </p>

        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html_e( 'Provider', 'mighty-shield' ); ?></th>
                <td>
                    <?php \MightyShield\Admin\admin_page::radios( 'mshield_captcha_provider', [
                        'off'          => __( 'Off', 'mighty-shield' ),
                        'turnstile'    => __( 'Cloudflare Turnstile', 'mighty-shield' ),
                        'recaptcha_v3' => __( 'Google reCAPTCHA v3', 'mighty-shield' ),
                    ], $cap_provider ); ?>
                    <p class="description">
                        <?php esc_html_e( 'Nothing is challenged until a provider and both keys are set. A wrong key or a provider outage lets requests through rather than refusing everyone, and emails you once a day until it is fixed.', 'mighty-shield' ); ?>
                    </p>
                </td>
            </tr>

            <?php /* ONE key pair, not one per provider. Both providers use the
                     same two option names, so rendering a hidden duplicate of
                     each would post twice -- and the hidden copy, being last in
                     the DOM, would overwrite whatever was typed in the visible
                     one. The AI tab can get away with per-provider rows because
                     each provider there has its own option. */ ?>
            <tr class="mshield-cap-keys"<?php echo $cap_provider === 'off' ? ' style="display:none;"' : ''; ?>>
                <th scope="row"><?php esc_html_e( 'Site key', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_captcha_site_key" class="regular-text"
                           value="<?php echo esc_attr( settings::get( 'mshield_captcha_site_key' ) ); ?>" />
                    <p class="description mshield-cap-p-turnstile"<?php echo $cap_hide( 'turnstile' ); ?>>
                        <?php esc_html_e( 'From the Cloudflare dashboard, under Turnstile.', 'mighty-shield' ); ?>
                    </p>
                    <p class="description mshield-cap-p-recaptcha_v3"<?php echo $cap_hide( 'recaptcha_v3' ); ?>>
                        <?php esc_html_e( 'From the Google reCAPTCHA admin console. Must be a v3 key.', 'mighty-shield' ); ?>
                    </p>
                </td>
            </tr>
            <tr class="mshield-cap-keys"<?php echo $cap_provider === 'off' ? ' style="display:none;"' : ''; ?>>
                <th scope="row"><?php esc_html_e( 'Secret key', 'mighty-shield' ); ?></th>
                <td>
                    <input type="password" name="mshield_captcha_secret_key" class="regular-text" value="" autocomplete="off"
                           placeholder="<?php echo settings::get( 'mshield_captcha_secret_key' ) !== '' ? esc_attr__( 'saved. Leave blank to keep', 'mighty-shield' ) : ''; ?>" />
                </td>
            </tr>

            <tr>
                <th scope="row"><?php esc_html_e( 'Where it applies', 'mighty-shield' ); ?></th>
                <td>
                    <?php
                    $cap_surfaces = [
                        'mshield_captcha_on_login'        => __( 'Login', 'mighty-shield' ),
                        'mshield_captcha_on_register'     => __( 'Registration', 'mighty-shield' ),
                        'mshield_captcha_on_lostpassword' => __( 'Lost password', 'mighty-shield' ),
                        'mshield_captcha_on_comments'     => __( 'Comments', 'mighty-shield' ),
                    ];
                    foreach( $cap_surfaces as $opt => $label ) : ?>
                        <label style="display:block;margin-bottom:5px">
                            <input type="hidden" name="<?php echo esc_attr( $opt ); ?>" value="no" />
                            <input type="checkbox" name="<?php echo esc_attr( $opt ); ?>" value="yes"
                                   <?php checked( settings::get( $opt ), 'yes' ); ?> />
                            <?php echo esc_html( $label ); ?>
                        </label>
                    <?php endforeach; ?>
                    <p class="description">
                        <?php esc_html_e( 'Checkout is always covered. A failed challenge refuses a login, registration or password reset; a comment is held for moderation instead, because losing a real reader\'s comment outright is worse than making them wait.', 'mighty-shield' ); ?>
                    </p>
                    <p class="description">
                        <strong><?php esc_html_e( 'Login is off by default.', 'mighty-shield' ); ?></strong>
                        <?php esc_html_e( 'A wrong key fails open, but a blocked script means no token at all, and that is refused, which on the login form locks everyone out. Allowlist your own address on the Access tab before turning it on.', 'mighty-shield' ); ?>
                    </p>
                </td>
            </tr>

        </table>

    </div>

    <?php /* The "Failed Card Checks" section that used to sit here is gone.
             It was one checkbox deciding the fate of five different findings --
             address mismatch, security code mismatch, a prepaid card, the
             processor's own risk rating, the issuing country -- and it held the
             order itself, around the risk levels above rather than through
             them. Each of those is now a row on the Scoring tab with its own
             weight, and what happens to the resulting rating is decided here,
             in one place, like everything else. */ ?>

    <div class="mshield-section">

        <h2><?php esc_html_e( 'Refusals', 'mighty-shield' ); ?></h2>

        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html_e( 'Slow down refusals', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="mshield_tarpit_enabled" value="yes"
                               <?php checked( settings::get( 'mshield_tarpit_enabled' ) === 'yes' ); ?> />
                        <?php esc_html_e( 'Delay refused checkouts by a random amount', 'mighty-shield' ); ?>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'Automated card testing depends on getting a fast, consistent answer. Refusing slowly, with a message that varies and reads like an ordinary bank decline, means an attacker cannot tell what tripped or time their way around it. Genuine customers are never refused, so this does not affect them.', 'mighty-shield' ); ?>
                    </p>
                    <p>
                        <label>
                            <?php esc_html_e( 'Between', 'mighty-shield' ); ?>
                            <input type="number" min="0" max="30000" class="small-text"
                                   name="mshield_tarpit_min_ms"
                                   value="<?php echo esc_attr( (int) settings::get( 'mshield_tarpit_min_ms' ) ); ?>" />
                        </label>
                        <label>
                            <?php esc_html_e( 'and', 'mighty-shield' ); ?>
                            <input type="number" min="0" max="30000" class="small-text"
                                   name="mshield_tarpit_max_ms"
                                   value="<?php echo esc_attr( (int) settings::get( 'mshield_tarpit_max_ms' ) ); ?>" />
                            <?php esc_html_e( 'milliseconds', 'mighty-shield' ); ?>
                        </label>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row"><?php esc_html_e( 'What a refused customer reads', 'mighty-shield' ); ?></th>
                <td>
                    <p class="description">
                        <?php esc_html_e( 'MightyShield picks one of these at random each time, so nobody can submit the same order twice and learn anything from the difference in the answer. None of them says what tripped, on purpose. These cover refusals that come from the rating; an individual check that refuses on its own says something specific instead, because the customer usually needs to fix it, as with a mistyped postcode.', 'mighty-shield' ); ?>
                    </p>

                    <ul class="mshield-examples">
                        <?php foreach( response::refusal_messages() as $mshield_example ) : ?>
                            <li><?php echo esc_html( $mshield_example ); ?></li>
                        <?php endforeach; ?>
                    </ul>

                    <p>
                        <label for="mshield_refusal_note">
                            <strong><?php esc_html_e( 'Add your own line to the end of every refusal', 'mighty-shield' ); ?></strong>
                        </label>
                    </p>

                    <textarea name="mshield_refusal_note" id="mshield_refusal_note" rows="3" class="large-text"
                              placeholder="<?php esc_attr_e( 'Need help with this order? Call us on &lt;a href=&quot;tel:5551234567&quot;&gt;(555) 123-4567&lt;/a&gt;.', 'mighty-shield' ); ?>"><?php
                        echo esc_textarea( settings::get( 'mshield_refusal_note' ) );
                    ?></textarea>

                    <p class="description">
                        <?php esc_html_e( 'Being vague protects the store, but it leaves the occasional real customer with no idea who to talk to. This is where you give them a way through. It is added to the end of every refusal, whatever caused it.', 'mighty-shield' ); ?>
                    </p>
                    <p class="description">
                        <?php
                        // Each tag name is escaped on its own, then joined with
                        // the markup. Escaping the joined string would escape
                        // the separators along with it and print them.
                        $mshield_tags = array_map(
                            function( $mshield_tag ) { return '<code>&lt;' . esc_html( $mshield_tag ) . '&gt;</code>'; },
                            array_keys( \MightyShield\Admin\admin_page::refusal_note_tags() )
                        );

                        printf(
                            /* translators: %s: the list of permitted HTML tags. */
                            esc_html__( 'Links work, so a phone number or an email address can be tapped. Bold and italic work too. In full: %s.', 'mighty-shield' ),
                            implode( ', ', $mshield_tags )
                        );
                        ?>
                    </p>
                    <p class="mshield-hint">
                        <?php esc_html_e( 'Leave it empty and refusals read exactly as they do above.', 'mighty-shield' ); ?>
                    </p>
                </td>
            </tr>
        </table>

        <script>
    ( function () {
        var providers = [ 'turnstile', 'recaptcha_v3' ];
        function show( el, on ) { el.style.display = on ? '' : 'none'; }
        function sync() {
            var checked = document.querySelector( 'input[name="mshield_captcha_provider"]:checked' );
            var value   = checked ? checked.value : 'off';
            providers.forEach( function ( key ) {
                document.querySelectorAll( '.mshield-cap-p-' + key ).forEach( function ( row ) {
                    show( row, key === value );
                } );
            } );
            document.querySelectorAll( '.mshield-cap-keys' ).forEach( function ( row ) {
                show( row, value !== 'off' );
            } );
        }
        document.querySelectorAll( 'input[name="mshield_captcha_provider"]' ).forEach( function ( i ) {
            i.addEventListener( 'change', sync );
        } );
        sync();
    } )();
    </script>

    </div>

    <?php /* Outside the last section, so the Save is not trapped inside that
             card. Matches Scoring and AI. */ ?>
    <?php submit_button(); ?>

</form>
