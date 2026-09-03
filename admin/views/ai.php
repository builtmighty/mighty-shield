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
$hide_notify = settings::get( 'mshield_ai_notify_admin' ) === 'yes' ? '' : $hide;

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
        <h2><?php esc_html_e( 'AI Credentials', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Choose a provider and enter its connection details. Small, fast models are the right tier here. Reviews run inline with checkout, so latency and per-order cost matter more than raw capability.', 'mighty-shield' ); ?></p>
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
            <tr class="mshield-ai-p-anthropic"<?php echo $hide_p( 'anthropic' ); ?>>
                <th scope="row"><?php esc_html_e( 'Anthropic API Key', 'mighty-shield' ); ?></th>
                <td>
                    <input type="password" name="mshield_ai_anthropic_key" value="" class="regular-text" <?php echo $has_key ? 'placeholder="••••••••"' : ''; ?> />
                    <p class="description"><?php echo $has_key ? esc_html__( 'Key is saved. Leave blank to keep existing key.', 'mighty-shield' ) : esc_html__( 'Your Anthropic API key.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr class="mshield-ai-p-anthropic"<?php echo $hide_p( 'anthropic' ); ?>>
                <th scope="row"><?php esc_html_e( 'Model', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_ai_anthropic_model" value="<?php echo esc_attr( settings::get( 'mshield_ai_anthropic_model' ) ); ?>" class="regular-text" />
                    <p class="description"><?php esc_html_e( 'Default: claude-haiku-4-5, the fastest and lowest cost Claude model, well suited to per-order scoring.', 'mighty-shield' ); ?></p>
                </td>
            </tr>

            <?php $has_key = ! empty( settings::get( 'mshield_ai_openai_key' ) ); ?>
            <tr class="mshield-ai-p-openai"<?php echo $hide_p( 'openai' ); ?>>
                <th scope="row"><?php esc_html_e( 'OpenAI API Key', 'mighty-shield' ); ?></th>
                <td>
                    <input type="password" name="mshield_ai_openai_key" value="" class="regular-text" <?php echo $has_key ? 'placeholder="••••••••"' : ''; ?> />
                    <p class="description"><?php echo $has_key ? esc_html__( 'Key is saved. Leave blank to keep existing key.', 'mighty-shield' ) : esc_html__( 'Your OpenAI API key.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr class="mshield-ai-p-openai"<?php echo $hide_p( 'openai' ); ?>>
                <th scope="row"><?php esc_html_e( 'Organization ID', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_ai_openai_org" value="<?php echo esc_attr( settings::get( 'mshield_ai_openai_org' ) ); ?>" class="regular-text" />
                    <p class="description"><?php esc_html_e( 'Optional. Only needed if your key belongs to more than one organization.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr class="mshield-ai-p-openai"<?php echo $hide_p( 'openai' ); ?>>
                <th scope="row"><?php esc_html_e( 'Model', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_ai_openai_model" value="<?php echo esc_attr( settings::get( 'mshield_ai_openai_model' ) ); ?>" class="regular-text" />
                    <p class="description"><?php esc_html_e( 'Use a small, fast model. Check your provider\'s current model list, because model IDs change over time.', 'mighty-shield' ); ?></p>
                </td>
            </tr>

            <?php $has_key = ! empty( settings::get( 'mshield_ai_gemini_key' ) ); ?>
            <tr class="mshield-ai-p-gemini"<?php echo $hide_p( 'gemini' ); ?>>
                <th scope="row"><?php esc_html_e( 'Gemini API Key', 'mighty-shield' ); ?></th>
                <td>
                    <input type="password" name="mshield_ai_gemini_key" value="" class="regular-text" <?php echo $has_key ? 'placeholder="••••••••"' : ''; ?> />
                    <p class="description"><?php echo $has_key ? esc_html__( 'Key is saved. Leave blank to keep existing key.', 'mighty-shield' ) : esc_html__( 'Your Google AI Studio API key.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr class="mshield-ai-p-gemini"<?php echo $hide_p( 'gemini' ); ?>>
                <th scope="row"><?php esc_html_e( 'Model', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_ai_gemini_model" value="<?php echo esc_attr( settings::get( 'mshield_ai_gemini_model' ) ); ?>" class="regular-text" />
                    <p class="description"><?php esc_html_e( 'Use a Flash-tier model. Check your provider\'s current model list, because model IDs change over time.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Reviewing', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'A review costs money and adds a couple of seconds to checkout, so it runs only on the risk levels you choose and only during checkout, where its verdict can still change what happens to the order.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Rating Effect', 'mighty-shield' ); ?></th>
                <td>
                    <?php admin_page::radios( 'mshield_ai_direction', [
                        'lower' => __( 'Only lower the rating', 'mighty-shield' ),
                        'both'  => __( 'Lower or raise the rating', 'mighty-shield' ),
                    ], settings::get( 'mshield_ai_direction' ) ); ?>
                    <p class="description">
                        <?php esc_html_e( 'The review returns its own rating from 1 to 100, judging the whole order. Lowering only means it can veto trust the checks granted, but never hand any back. Allowing it to raise lets a model that recognises an ordinary customer rescue an order the checks were too harsh on, at the cost of letting one confident wrong answer do the same. Either way it cannot push an order into Trusted; that still takes a clean order history.', 'mighty-shield' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Customer Details', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="mshield_ai_redact_pii" value="yes"
                               <?php checked( settings::get( 'mshield_ai_redact_pii' ) === 'yes' ); ?> />
                        <?php esc_html_e( 'Do not send customers\' personal details to the AI provider', 'mighty-shield' ); ?>
                    </label>
                    <p class="description">
                        <?php esc_html_e( 'The review still sees what it needs: the email domain, whether the address looks plausible, the city and postcode, and the network the order came from. It sees but not the street address, mailbox name, phone number or exact IP. Slightly less accurate, and worth turning on if you would rather those details never left your site.', 'mighty-shield' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Daily Limit', 'mighty-shield' ); ?></th>
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
                <th scope="row"><?php esc_html_e( 'Notification', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_ai_notify_admin" value="no" />
                        <input type="checkbox" name="mshield_ai_notify_admin" value="yes" <?php checked( settings::get( 'mshield_ai_notify_admin' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Email me when a review comes back badly rated.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
            <tr class="mshield-ai-notify-only"<?php echo $hide_notify; ?>>
                <th scope="row"><?php esc_html_e( 'Notification Email(s)', 'mighty-shield' ); ?></th>
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


    function syncNotify() {
        var box = document.querySelector( 'input[type="checkbox"][name="mshield_ai_notify_admin"]' );
        document.querySelectorAll( '.mshield-ai-notify-only' ).forEach( function( el ) {
            show( el, !! ( box && box.checked ) );
        } );
    }

    document.querySelectorAll( 'input[name="mshield_ai_provider"]' ).forEach( function( input ) {
        input.addEventListener( 'change', syncProvider );
    } );

    var notify = document.querySelector( 'input[type="checkbox"][name="mshield_ai_notify_admin"]' );
    if ( notify ) { notify.addEventListener( 'change', syncNotify ); }

    syncProvider();
    syncNotify();
} )();
</script>
