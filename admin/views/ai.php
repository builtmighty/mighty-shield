<?php
/**
 * AI Detection settings view.
 *
 * @package MightyShield
 * @since   1.9.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\settings;
use MightyShield\Includes\ai_detection;
use MightyShield\Includes\ai_capture;
use MightyShield\Admin\admin_page;

$provider    = settings::get( 'mshield_ai_provider' );
$suspicious  = settings::get( 'mshield_ai_method' ) === 'suspicious';

// Hide rows that do not apply to the current selection. Rendered server-side so
// there is no flash of the wrong fields before the inline script runs.
$hide        = ' style="display:none;"';
$hide_p      = function( $key ) use ( $provider, $hide ) { return $provider === $key ? '' : $hide; };
$hide_susp   = $suspicious ? '' : $hide;
$hide_notify = settings::get( 'mshield_ai_notify_admin' ) === 'yes' ? '' : $hide;

// Authorize needs a gateway that can reserve funds without capturing. Gated
// here and again in the sanitize callback, so a stale POST or a gateway being
// disabled later cannot leave the store on a setting it cannot honor.
$can_authorize    = ai_capture::any_gateway_supports_auth_only();
$verdict_disabled = $can_authorize ? [] : [ 'authorize' ];
$verdict_action   = $can_authorize ? settings::get( 'mshield_ai_verdict_action' ) : 'flag';

// Signal weights, so the copy below and the runtime never drift apart.
$w_velocity  = ai_detection::weight( 'address_velocity' );
$w_email     = ai_detection::weight( 'email_mismatch' );
$w_value     = ai_detection::weight( 'high_value' );
$w_ip        = ai_detection::weight( 'ip_mismatch' );

/* translators: %s: score a signal contributes, e.g. 2.5 */
$adds        = __( 'Adds %s to the suspicion score.', 'mighty-shield' );
?>

<form method="post" action="options.php">
    <?php settings_fields( 'mshield_ai' ); ?>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'AI Detection', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Uses an AI model to review orders that look legitimate to the rule-based layers. Targets stolen-card orders shipped to real, deliverable addresses — where every attribute passes on its own and only the pattern across them is suspicious.', 'mighty-shield' ); ?></p>
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
        <p class="description"><?php esc_html_e( 'Choose a provider and enter its connection details. Small, fast models are the right tier here — reviews run inline with checkout, so latency and per-order cost matter more than raw capability.', 'mighty-shield' ); ?></p>
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
                    <p class="description"><?php esc_html_e( 'Default: claude-haiku-4-5 — the fastest, lowest-cost Claude model, well suited to per-order scoring.', 'mighty-shield' ); ?></p>
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
                    <p class="description"><?php esc_html_e( 'Use a small, fast model. Check your provider\'s current model list — model IDs change over time.', 'mighty-shield' ); ?></p>
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
                    <p class="description"><?php esc_html_e( 'Use a Flash-tier model. Check your provider\'s current model list — model IDs change over time.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Detection Method', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Whether every order is reviewed, or only those that trip enough suspicious signals to be worth the cost of a review.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Method', 'mighty-shield' ); ?></th>
                <td>
                    <?php admin_page::radios( 'mshield_ai_method', [
                        'all'        => __( 'Monitor All', 'mighty-shield' ),
                        'suspicious' => __( 'Monitor Suspicious', 'mighty-shield' ),
                    ], settings::get( 'mshield_ai_method' ) ); ?>
                    <p class="description"><?php esc_html_e( 'Monitor All reviews every order — the broadest coverage and the highest cost. Monitor Suspicious scores each order first and only escalates the ones above your sensitivity threshold.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr class="mshield-ai-suspicious-only"<?php echo $hide_susp; ?>>
                <th scope="row"><?php esc_html_e( 'Sensitivity', 'mighty-shield' ); ?></th>
                <td>
                    <?php admin_page::radios( 'mshield_ai_sensitivity', [
                        'low'    => sprintf( __( 'Low (score >= %s — all four signals)', 'mighty-shield' ), ai_detection::THRESHOLDS['low'] ),
                        'medium' => sprintf( __( 'Medium (score >= %s — any two signals)', 'mighty-shield' ), ai_detection::THRESHOLDS['medium'] ),
                        'high'   => sprintf( __( 'High (score >= %s — any single signal)', 'mighty-shield' ), ai_detection::THRESHOLDS['high'] ),
                    ], settings::get( 'mshield_ai_sensitivity' ) ); ?>
                    <p class="description"><?php printf(
                        esc_html__( 'Each enabled signal below adds its rating to the order\'s suspicion score, up to a maximum of %s. Higher sensitivity reviews more orders and catches more fraud, at a higher per-order cost.', 'mighty-shield' ),
                        esc_html( ai_detection::max_score() )
                    ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'AI Verdict', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'The AI returns a rating from 1 (fraudulent) to 10 (squeaky clean). Orders at or below your threshold are authorized but not captured, and placed On-hold for review.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Hold Threshold', 'mighty-shield' ); ?></th>
                <td>
                    <?php esc_html_e( 'Hold orders rated at or below', 'mighty-shield' ); ?>
                    <input type="number" name="mshield_ai_rating_threshold" value="<?php echo esc_attr( settings::get( 'mshield_ai_rating_threshold' ) ); ?>" min="1" max="10" step="1" class="small-text" />
                    <span><?php esc_html_e( '/ 10', 'mighty-shield' ); ?></span>
                    <p class="description"><?php esc_html_e( 'A held order has an authorization but no capture — the funds are reserved, nothing is settled, and the order cannot be fulfilled until you approve it. Authorizations expire (about 7 days on Stripe), so work the On-hold queue: an authorization you never capture is a sale you lose. Default: 4', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Verdict Action', 'mighty-shield' ); ?></th>
                <td>
                    <?php admin_page::radios( 'mshield_ai_verdict_action', [
                        'flag'      => __( 'Flag the order', 'mighty-shield' ),
                        'authorize' => __( 'Authorize the order', 'mighty-shield' ),
                    ], $verdict_action, $verdict_disabled ); ?>
                    <p class="description"><?php esc_html_e( 'Both place the order On-hold — they differ in whether the money moves. Flag lets the payment capture normally, then holds the order for review. Authorize reserves the funds without capturing them, so denying an order releases the money instead of requiring a refund.', 'mighty-shield' ); ?></p>
                    <?php if ( ! empty( $verdict_disabled ) ) : ?>
                        <p class="description"><strong><?php esc_html_e( 'Authorize is unavailable:', 'mighty-shield' ); ?></strong>
                        <?php esc_html_e( 'none of the payment methods enabled at checkout support authorizing without capturing. Supported gateways are Stripe (official and Payment Plugins), WooPayments, Square, Authorize.Net, and Braintree. Note that WooCommerce PayPal Payments cannot be used here — it fixes the capture decision before the order reaches MightyShield.', 'mighty-shield' ); ?></p>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Notification', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_ai_notify_admin" value="no" />
                        <input type="checkbox" name="mshield_ai_notify_admin" value="yes" <?php checked( settings::get( 'mshield_ai_notify_admin' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Email a notification whenever an order is held.', 'mighty-shield' ); ?>
                    </label>
                    <p class="description"><?php esc_html_e( 'Recommended. Held orders need a human decision, and nothing else surfaces them.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr class="mshield-ai-notify-only"<?php echo $hide_notify; ?>>
                <th scope="row"><?php esc_html_e( 'Notification Email(s)', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_ai_notify_emails" value="<?php echo esc_attr( settings::get( 'mshield_ai_notify_emails' ) ); ?>" class="large-text" placeholder="ops@example.com, fraud@example.com" />
                    <p class="description"><?php esc_html_e( 'Comma-separated. Leave blank to use the site admin email. Invalid addresses are dropped on save, so check the field after saving if one disappears.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section mshield-ai-suspicious-only"<?php echo $hide_susp; ?>>
        <h2><?php esc_html_e( 'Suspicious Signals', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Signals used to score an order under Monitor Suspicious. Each one is a pattern that looks ordinary on a single order but reads as reshipping fraud across many.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Address Velocity', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_ai_sig_address_velocity" value="no" />
                        <input type="checkbox" name="mshield_ai_sig_address_velocity" value="yes" <?php checked( settings::get( 'mshield_ai_sig_address_velocity' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Flag shipping addresses reused across many orders.', 'mighty-shield' ); ?>
                    </label>
                    <p class="description"><?php printf(
                        esc_html( $adds . ' ' . __( 'Catches drop addresses, where one location receives orders placed by many different buyers.', 'mighty-shield' ) ),
                        esc_html( $w_velocity )
                    ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Velocity Threshold', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_ai_velocity_orders" value="<?php echo esc_attr( settings::get( 'mshield_ai_velocity_orders' ) ); ?>" min="2" max="100" step="1" class="small-text" />
                    <span><?php esc_html_e( 'orders within', 'mighty-shield' ); ?></span>
                    <input type="number" name="mshield_ai_velocity_days" value="<?php echo esc_attr( settings::get( 'mshield_ai_velocity_days' ) ); ?>" min="1" max="365" step="1" class="small-text" />
                    <span><?php esc_html_e( 'days', 'mighty-shield' ); ?></span>
                    <p class="description"><?php esc_html_e( 'A rolling window. The signal trips when one shipping address exceeds this many orders inside it. Default: 3 orders within 30 days.', 'mighty-shield' ); ?></p>
                </td>
            </tr>

            <tr>
                <th scope="row"><?php esc_html_e( 'Email-Name Mismatch', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_ai_sig_email_mismatch" value="no" />
                        <input type="checkbox" name="mshield_ai_sig_email_mismatch" value="yes" <?php checked( settings::get( 'mshield_ai_sig_email_mismatch' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Flag orders where the shipping name does not appear in the email address.', 'mighty-shield' ); ?>
                    </label>
                    <p class="description"><?php printf(
                        esc_html( $adds . ' ' . __( 'Trips when no part of the shipping name overlaps the email local part (the portion before the @).', 'mighty-shield' ) ),
                        esc_html( $w_email )
                    ); ?></p>
                </td>
            </tr>

            <tr>
                <th scope="row"><?php esc_html_e( 'High Value Item', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_ai_sig_high_value" value="no" />
                        <input type="checkbox" name="mshield_ai_sig_high_value" value="yes" <?php checked( settings::get( 'mshield_ai_sig_high_value' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Flag orders above a set value.', 'mighty-shield' ); ?>
                    </label>
                    <p class="description"><?php printf(
                        esc_html( $adds . ' ' . __( 'Resale-driven fraud favours high-value, easily resold goods.', 'mighty-shield' ) ),
                        esc_html( $w_value )
                    ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'High Value Threshold', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_ai_high_value_amount" value="<?php echo esc_attr( settings::get( 'mshield_ai_high_value_amount' ) ); ?>" min="0" step="0.01" class="small-text" />
                    <span><?php echo esc_html( get_woocommerce_currency() ); ?></span>
                    <p class="description"><?php esc_html_e( 'Order totals at or above this amount trip the signal. Set relative to your average order value, not to an absolute figure. Default: 500.00', 'mighty-shield' ); ?></p>
                </td>
            </tr>

            <tr>
                <th scope="row"><?php esc_html_e( 'IP-Shipping Mismatch', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_ai_sig_ip_mismatch" value="no" />
                        <input type="checkbox" name="mshield_ai_sig_ip_mismatch" value="yes" <?php checked( settings::get( 'mshield_ai_sig_ip_mismatch' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Flag orders where the buyer\'s IP location is far from the shipping address.', 'mighty-shield' ); ?>
                    </label>
                    <p class="description"><?php printf(
                        esc_html( $adds . ' ' . __( 'Uses the existing IP location data (city, region, country) that MightyShield already caches for each IP — no extra lookup service is needed. Expect false positives from VPNs and travelling customers, which is why this is one signal among several rather than a block on its own.', 'mighty-shield' ) ),
                        esc_html( $w_ip )
                    ); ?></p>
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

    function syncMethod() {
        var checked = document.querySelector( 'input[name="mshield_ai_method"]:checked' );
        var on      = ! checked || checked.value === 'suspicious';
        document.querySelectorAll( '.mshield-ai-suspicious-only' ).forEach( function( el ) {
            show( el, on );
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
    document.querySelectorAll( 'input[name="mshield_ai_method"]' ).forEach( function( input ) {
        input.addEventListener( 'change', syncMethod );
    } );

    var notify = document.querySelector( 'input[type="checkbox"][name="mshield_ai_notify_admin"]' );
    if ( notify ) { notify.addEventListener( 'change', syncNotify ); }

    syncProvider();
    syncMethod();
    syncNotify();
} )();
</script>
