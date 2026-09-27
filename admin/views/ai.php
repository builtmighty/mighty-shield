<?php
/**
 * AI Detection settings view.
 *
 * @package MightyShield
 * @since   1.8.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\settings;
use MightyShield\Admin\admin_page;

$provider    = settings::get( 'mshield_ai_provider' );

// Hide rows that do not apply to the current selection. Rendered server-side so
// there is no flash of the wrong fields before the inline script runs.
$hide        = ' style="display:none;"';
$hide_p      = function( $key ) use ( $provider, $hide ) { return $provider === $key ? '' : $hide; };
// The recipients row is never hidden: the low-rating alert on the Shielding
// tab mails the same list whatever this checkbox says.
$hide_notify = '';

// One dropdown per provider, each in that provider's row, so the choices
// change with the provider selected above. A saved id that is no longer on
// the list is still offered, so saving the page cannot silently move the
// store onto a different model.
$model_select = function( $key ) {
    $name    = 'mshield_ai_' . $key . '_model';
    $current = (string) settings::get( $name );
    echo '<select name="' . esc_attr( $name ) . '" class="regular-text">';
    foreach( \MightyShield\Includes\ai_client::models( $key ) as $id => $label ) {
        echo '<option value="' . esc_attr( $id ) . '"' . selected( $current, $id, false ) . '>' . esc_html( $label ) . '</option>';
    }
    echo '</select>';
};

// Authorize needs a gateway that can reserve funds without capturing. Gated
// here and again in the sanitize callback, so a stale POST or a gateway being
// disabled later cannot leave the store on a setting it cannot honor.

// Signal weights, so the copy below and the runtime never drift apart.

/* translators: %s: score a signal contributes, e.g. 2.5 */
?>

<form method="post" action="options.php">
    <?php settings_fields( 'mshield_ai' ); ?>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'AI Detection', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Uses an AI model to review orders that look legitimate to the rule-based layers. It targets stolen-card orders shipped to real, deliverable addresses, where every attribute passes on its own and only the pattern across them is suspicious.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Enable AI Detection', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_ai_enabled" value="no" />
                        <input type="checkbox" name="mshield_ai_enabled" value="yes" <?php checked( settings::get( 'mshield_ai_enabled' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Send orders to an AI model for fraud review.', 'mighty-shield' ); ?>
                    </label>
                    <p class="description"><?php esc_html_e( 'Requires valid API credentials below. Every review costs a request to your AI provider.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'AI credentials', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Choose a provider and enter its connection details.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Provider', 'mighty-shield' ); ?></th>
                <td>
                    <?php admin_page::radios( 'mshield_ai_provider', [
                        'anthropic' => __( 'Anthropic (Claude)', 'mighty-shield' ),
                        'openai'    => __( 'OpenAI', 'mighty-shield' ),
                        'gemini'    => __( 'Google Gemini', 'mighty-shield' ),
                    ], $provider ); ?>
                    <p class="description"><?php esc_html_e( 'Only the selected provider\'s credentials are used. Keys for the others stay saved if you switch back.', 'mighty-shield' ); ?></p>
                </td>
            </tr>

            <?php $has_key = ! empty( settings::get( 'mshield_ai_anthropic_key' ) ); ?>
            <tr class="mshield-ai-p-anthropic"<?php echo $hide_p( 'anthropic' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- returns '' or the literal style attribute defined at the top of this file ?>>
                <th scope="row"><?php esc_html_e( 'Anthropic API key', 'mighty-shield' ); ?></th>
                <td>
                    <input type="password" name="mshield_ai_anthropic_key" value="" class="regular-text" autocomplete="off" placeholder="<?php echo $has_key ? esc_attr__( 'saved, leave blank to keep', 'mighty-shield' ) : ''; ?>" />
                </td>
            </tr>
            <tr class="mshield-ai-p-anthropic"<?php echo $hide_p( 'anthropic' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- returns '' or the literal style attribute defined at the top of this file ?>>
                <th scope="row"><?php esc_html_e( 'Model', 'mighty-shield' ); ?></th>
                <td>
                    <?php $model_select( 'anthropic' ); ?>
                </td>
            </tr>

            <?php $has_key = ! empty( settings::get( 'mshield_ai_openai_key' ) ); ?>
            <tr class="mshield-ai-p-openai"<?php echo $hide_p( 'openai' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- returns '' or the literal style attribute defined at the top of this file ?>>
                <th scope="row"><?php esc_html_e( 'OpenAI API key', 'mighty-shield' ); ?></th>
                <td>
                    <input type="password" name="mshield_ai_openai_key" value="" class="regular-text" autocomplete="off" placeholder="<?php echo $has_key ? esc_attr__( 'saved, leave blank to keep', 'mighty-shield' ) : ''; ?>" />
                </td>
            </tr>
            <tr class="mshield-ai-p-openai"<?php echo $hide_p( 'openai' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- returns '' or the literal style attribute defined at the top of this file ?>>
                <th scope="row"><?php esc_html_e( 'Organization ID', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_ai_openai_org" value="<?php echo esc_attr( settings::get( 'mshield_ai_openai_org' ) ); ?>" class="regular-text" />
                    <p class="description"><?php esc_html_e( 'Optional. Only needed if your key belongs to more than one organization.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr class="mshield-ai-p-openai"<?php echo $hide_p( 'openai' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- returns '' or the literal style attribute defined at the top of this file ?>>
                <th scope="row"><?php esc_html_e( 'Model', 'mighty-shield' ); ?></th>
                <td>
                    <?php $model_select( 'openai' ); ?>
                </td>
            </tr>

            <?php $has_key = ! empty( settings::get( 'mshield_ai_gemini_key' ) ); ?>
            <tr class="mshield-ai-p-gemini"<?php echo $hide_p( 'gemini' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- returns '' or the literal style attribute defined at the top of this file ?>>
                <th scope="row"><?php esc_html_e( 'Gemini API key', 'mighty-shield' ); ?></th>
                <td>
                    <input type="password" name="mshield_ai_gemini_key" value="" class="regular-text" autocomplete="off" placeholder="<?php echo $has_key ? esc_attr__( 'saved, leave blank to keep', 'mighty-shield' ) : ''; ?>" />
                </td>
            </tr>
            <tr class="mshield-ai-p-gemini"<?php echo $hide_p( 'gemini' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- returns '' or the literal style attribute defined at the top of this file ?>>
                <th scope="row"><?php esc_html_e( 'Model', 'mighty-shield' ); ?></th>
                <td>
                    <?php $model_select( 'gemini' ); ?>
                </td>
            </tr>

            <tr>
                <th scope="row"><?php esc_html_e( 'Test connection', 'mighty-shield' ); ?></th>
                <td>
                    <?php admin_page::test_button( 'ai' ); ?>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Reviewing', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'A review costs money and adds a couple of seconds to checkout, so it runs only on the risk levels you choose and only during checkout, where its verdict can still change what happens to the order.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Send to review', 'mighty-shield' ); ?></th>
                <td>
                    <div class="mshield-level-pills">
                        <?php foreach( \MightyShield\Includes\risk_levels::AI_REVIEWABLE as $ai_level ) :

                            $ai_on = \MightyShield\Includes\risk_levels::ai_review_setting( $ai_level );
                            ?>
                            <?php /* A real checkbox, hidden behind the pill rather than
                                     replaced by one: it keeps keyboard focus, the label
                                     association and the form post that a div would all
                                     have to be rebuilt in JavaScript. The paired hidden
                                     field is what makes UNCHECKING submit anything at
                                     all -- an unchecked box sends nothing, and nothing
                                     is indistinguishable from "never rendered". */ ?>
                            <input type="hidden" name="mshield_level_<?php echo esc_attr( $ai_level ); ?>_ai" value="no" />
                            <label class="mshield-level-pill s-<?php echo esc_attr( $ai_level ); ?>">
                                <input type="checkbox"
                                       name="mshield_level_<?php echo esc_attr( $ai_level ); ?>_ai"
                                       value="yes" <?php checked( $ai_on ); ?> />
                                <span><?php echo esc_html( \MightyShield\Includes\risk_levels::label( $ai_level ) ); ?></span>
                            </label>
                        <?php endforeach; ?>
                    </div>
                    <?php if( ! \MightyShield\Includes\ai_client::is_ready() ) : ?>
                        <p class="description">
                            <strong><?php esc_html_e( 'No reviews will run until a provider is set up above.', 'mighty-shield' ); ?></strong>
                            <?php esc_html_e( 'Your choice here is remembered and takes effect as soon as one is.', 'mighty-shield' ); ?>
                        </p>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Rating effect', 'mighty-shield' ); ?></th>
                <td>
                    <?php admin_page::radios( 'mshield_ai_direction', [
                        'lower' => __( 'Only lower the trust rating', 'mighty-shield' ),
                        'both'  => __( 'Lower or raise the trust rating', 'mighty-shield' ),
                    ], settings::get( 'mshield_ai_direction' ) ); ?>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Customer details', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="mshield_ai_redact_pii" value="yes"
                               <?php checked( settings::get( 'mshield_ai_redact_pii' ) === 'yes' ); ?> />
                        <?php esc_html_e( 'Do not send customers\' personal details to the AI provider', 'mighty-shield' ); ?>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'The review still sees what it needs, without specific customer information. Slightly less accurate.', 'mighty-shield' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Daily limit', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" min="0" step="1" style="width:110px;"
                           name="mshield_ai_daily_cap"
                           value="<?php echo esc_attr( (int) settings::get( 'mshield_ai_daily_cap' ) ); ?>" />
                    <p class="description">
                        <?php
                        printf(
                            /* translators: %d: reviews used today. */
                            esc_html__( 'Most reviews to run in one day. 0 means no limit. Used today: %d. Once the limit is reached, orders carry on as normal without a review, and a note is added to your logs.', 'mighty-shield' ),
                            (int) \MightyShield\Includes\ai_client::calls_today()
                        );
                        ?>
                    </p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Notifications', 'mighty-shield' ); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Send alerts', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_ai_notify_admin" value="no" />
                        <input type="checkbox" name="mshield_ai_notify_admin" value="yes" <?php checked( settings::get( 'mshield_ai_notify_admin' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Email me when MightyShield needs attention.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
            <tr class="mshield-ai-notify-only"<?php echo $hide_notify; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- '' or the literal style attribute defined at the top of this file ?>>
                <th scope="row"><?php esc_html_e( 'Send to', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_ai_notify_emails" value="<?php echo esc_attr( settings::get( 'mshield_ai_notify_emails' ) ); ?>" class="regular-text" />
                    <p class="description"><?php esc_html_e( 'Comma-separated. Leave blank to use the site admin address.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <?php submit_button(); ?>
</form>

<script>
( function() {
    var providers = [ 'anthropic', 'openai', 'gemini' ];

    function show( el, on ) { el.style.display = on ? '' : 'none'; }

    function syncProvider() {
        var checked = document.querySelector( 'input[name="mshield_ai_provider"]:checked' );
        var value   = checked ? checked.value : 'anthropic';
        providers.forEach( function( key ) {
            document.querySelectorAll( '.mshield-ai-p-' + key ).forEach( function( row ) {
                show( row, key === value );
            } );
        } );
    }


    // The recipients row stays visible whatever the checkbox says; the
    // low-rating alert uses the same list.
    function syncNotify() {}

    document.querySelectorAll( 'input[name="mshield_ai_provider"]' ).forEach( function( input ) {
        input.addEventListener( 'change', syncProvider );
    } );

    var notify = document.querySelector( 'input[type="checkbox"][name="mshield_ai_notify_admin"]' );
    if ( notify ) { notify.addEventListener( 'change', syncNotify ); }

    syncProvider();
    syncNotify();
} )();
</script>
