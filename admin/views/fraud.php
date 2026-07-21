<?php
/**
 * Fraud Checks settings view.
 *
 * @package MightyShield
 * @since   1.0.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\settings;
?>

<form method="post" action="options.php">
    <?php settings_fields( 'mshield_fraud' ); ?>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Email Domain Blocking', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Block checkout attempts using disposable/temporary email services. A built-in list of ~160 domains is always active.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Additional Blocked Domains', 'mighty-shield' ); ?></th>
                <td>
                    <textarea name="mshield_blocked_email_domains" rows="10" class="large-text code"><?php echo esc_textarea( settings::get( 'mshield_blocked_email_domains' ) ); ?></textarea>
                    <p class="description"><?php esc_html_e( 'Enter one domain per line (e.g., spammer-domain.com). These are added to the built-in disposable email list.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Order Amount Validation', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Detect suspiciously small order amounts commonly used for card testing.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Minimum Order Amount', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_min_order_amount" value="<?php echo esc_attr( settings::get( 'mshield_min_order_amount' ) ); ?>" class="small-text" />
                    <p class="description"><?php esc_html_e( 'Orders below this amount will be flagged/blocked. Set to 0 to disable. Default: 1.00', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Action on Suspicious Amount', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_suspicious_amount_action">
                        <option value="flag" <?php selected( settings::get( 'mshield_suspicious_amount_action' ), 'flag' ); ?>><?php esc_html_e( 'Flag (add order note)', 'mighty-shield' ); ?></option>
                        <option value="block" <?php selected( settings::get( 'mshield_suspicious_amount_action' ), 'block' ); ?>><?php esc_html_e( 'Block (cancel order)', 'mighty-shield' ); ?></option>
                        <option value="notify" <?php selected( settings::get( 'mshield_suspicious_amount_action' ), 'notify' ); ?>><?php esc_html_e( 'Flag + notify admin via email', 'mighty-shield' ); ?></option>
                    </select>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Address Validation', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Score-based detection of fake or nonsensical billing addresses. Checks for single-character names, repeated-digit ZIPs, known fake patterns, etc.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Sensitivity', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_address_sensitivity">
                        <option value="low" <?php selected( settings::get( 'mshield_address_sensitivity' ), 'low' ); ?>><?php esc_html_e( 'Low (score >= 10 to block)', 'mighty-shield' ); ?></option>
                        <option value="medium" <?php selected( settings::get( 'mshield_address_sensitivity' ), 'medium' ); ?>><?php esc_html_e( 'Medium (score >= 7 to block)', 'mighty-shield' ); ?></option>
                        <option value="high" <?php selected( settings::get( 'mshield_address_sensitivity' ), 'high' ); ?>><?php esc_html_e( 'High (score >= 5 to block)', 'mighty-shield' ); ?></option>
                    </select>
                    <p class="description"><?php esc_html_e( 'Higher sensitivity catches more suspicious addresses but may increase false positives.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Smarty Address Verification (US Only)', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Verify US billing addresses against USPS data via Smarty\'s API. Catches fake, non-existent, and undeliverable addresses. Falls back to ZIP/State mismatch check if API is unavailable.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Enable Smarty Verification', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_smarty_enabled" value="no" />
                        <input type="checkbox" name="mshield_smarty_enabled" value="yes" <?php checked( settings::get( 'mshield_smarty_enabled' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Enable USPS address verification via Smarty API.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Auth ID', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_smarty_auth_id" value="<?php echo esc_attr( settings::get( 'mshield_smarty_auth_id' ) ); ?>" class="regular-text" />
                    <p class="description"><?php esc_html_e( 'Your Smarty auth-id. Get credentials at smarty.com/account.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Auth Token', 'mighty-shield' ); ?></th>
                <td>
                    <?php $has_token = ! empty( settings::get( 'mshield_smarty_auth_token' ) ); ?>
                    <input type="password" name="mshield_smarty_auth_token" value="" class="regular-text" <?php echo $has_token ? 'placeholder="••••••••"' : ''; ?> />
                    <p class="description"><?php echo $has_token ? esc_html__( 'Token is saved. Leave blank to keep existing token.', 'mighty-shield' ) : esc_html__( 'Your Smarty auth-token.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Action on Failed Verification', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_smarty_action">
                        <option value="flag" <?php selected( settings::get( 'mshield_smarty_action' ), 'flag' ); ?>><?php esc_html_e( 'Flag (add order note)', 'mighty-shield' ); ?></option>
                        <option value="block" <?php selected( settings::get( 'mshield_smarty_action' ), 'block' ); ?>><?php esc_html_e( 'Block (prevent checkout)', 'mighty-shield' ); ?></option>
                        <option value="notify" <?php selected( settings::get( 'mshield_smarty_action' ), 'notify' ); ?>><?php esc_html_e( 'Flag + notify admin via email', 'mighty-shield' ); ?></option>
                    </select>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'ZIP/State Mismatch (US Only)', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Detect US orders where the billing ZIP code does not match the billing state. No external API required. Also used as a fallback when Smarty API is unavailable.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Enable ZIP/State Check', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_zip_state_enabled" value="no" />
                        <input type="checkbox" name="mshield_zip_state_enabled" value="yes" <?php checked( settings::get( 'mshield_zip_state_enabled' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Block orders where the billing ZIP prefix does not match the billing state.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Action on Mismatch', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_zip_state_action">
                        <option value="block" <?php selected( settings::get( 'mshield_zip_state_action' ), 'block' ); ?>><?php esc_html_e( 'Block (prevent checkout)', 'mighty-shield' ); ?></option>
                        <option value="flag" <?php selected( settings::get( 'mshield_zip_state_action' ), 'flag' ); ?>><?php esc_html_e( 'Flag (add order note)', 'mighty-shield' ); ?></option>
                        <option value="notify" <?php selected( settings::get( 'mshield_zip_state_action' ), 'notify' ); ?>><?php esc_html_e( 'Flag + notify admin via email', 'mighty-shield' ); ?></option>
                    </select>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Honeypot Field', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Adds an invisible field to the checkout form. Bots fill it in, humans never see it. Zero false positives, no API required.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Enable Honeypot', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_honeypot_enabled" value="no" />
                        <input type="checkbox" name="mshield_honeypot_enabled" value="yes" <?php checked( settings::get( 'mshield_honeypot_enabled' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Add a hidden honeypot field to the checkout form.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Action when triggered', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_honeypot_action">
                        <option value="block" <?php selected( settings::get( 'mshield_honeypot_action' ), 'block' ); ?>><?php esc_html_e( 'Block (prevent checkout)', 'mighty-shield' ); ?></option>
                        <option value="flag" <?php selected( settings::get( 'mshield_honeypot_action' ), 'flag' ); ?>><?php esc_html_e( 'Flag (add order note)', 'mighty-shield' ); ?></option>
                        <option value="notify" <?php selected( settings::get( 'mshield_honeypot_action' ), 'notify' ); ?>><?php esc_html_e( 'Flag + notify admin via email', 'mighty-shield' ); ?></option>
                    </select>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Checkout Timing', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Measures how long a shopper takes to submit checkout. Bots and scripted card-runners submit far faster than a human can. IP- and content-agnostic, so it is unaffected by VPN rotation or changing products.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Enable Checkout Timing', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_timing_enabled" value="no" />
                        <input type="checkbox" name="mshield_timing_enabled" value="yes" <?php checked( settings::get( 'mshield_timing_enabled' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Detect implausibly fast (automated) checkout submissions.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Minimum Seconds', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_timing_min_seconds" value="<?php echo esc_attr( settings::get( 'mshield_timing_min_seconds' ) ); ?>" min="0" step="1" class="small-text" />
                    <p class="description"><?php esc_html_e( 'Submissions faster than this many seconds after the form loads are treated as automated. Default: 4. Keep it conservative (3–5) to avoid catching fast, legitimate shoppers.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Action on Fast Submission', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_timing_action">
                        <option value="block" <?php selected( settings::get( 'mshield_timing_action' ), 'block' ); ?>><?php esc_html_e( 'Block (prevent checkout)', 'mighty-shield' ); ?></option>
                        <option value="flag" <?php selected( settings::get( 'mshield_timing_action' ), 'flag' ); ?>><?php esc_html_e( 'Flag (add order note)', 'mighty-shield' ); ?></option>
                        <option value="notify" <?php selected( settings::get( 'mshield_timing_action' ), 'notify' ); ?>><?php esc_html_e( 'Flag + notify admin via email', 'mighty-shield' ); ?></option>
                    </select>
                    <p class="description"><?php esc_html_e( 'Defaults to Flag so you can watch the logs before enforcing.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Action on Missing Token', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_timing_missing_action">
                        <option value="flag" <?php selected( settings::get( 'mshield_timing_missing_action' ), 'flag' ); ?>><?php esc_html_e( 'Flag only (safe default)', 'mighty-shield' ); ?></option>
                        <option value="block" <?php selected( settings::get( 'mshield_timing_missing_action' ), 'block' ); ?>><?php esc_html_e( 'Block (stops scripted checkouts)', 'mighty-shield' ); ?></option>
                    </select>
                    <p class="description"><?php esc_html_e( 'What to do when the timing token is missing or invalid — the signature of a scripted checkout that never rendered the form. Flag by default to guard against page caching stripping the field; set to Block when under active bot attack (only takes effect when the action above is Block).', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Device Fingerprinting', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Collects browser metadata (timezone, language, screen size) at checkout to detect automated browsers and geographic mismatches with billing address.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Enable Fingerprinting', 'mighty-shield' ); ?></th>
                <td>
                    <label>
                        <input type="hidden" name="mshield_fingerprint_enabled" value="no" />
                        <input type="checkbox" name="mshield_fingerprint_enabled" value="yes" <?php checked( settings::get( 'mshield_fingerprint_enabled' ), 'yes' ); ?> />
                        <?php esc_html_e( 'Detect automated browsers and timezone/country mismatches.', 'mighty-shield' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Action on Suspicious Device', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_fingerprint_action">
                        <option value="block" <?php selected( settings::get( 'mshield_fingerprint_action' ), 'block' ); ?>><?php esc_html_e( 'Block (prevent checkout)', 'mighty-shield' ); ?></option>
                        <option value="flag" <?php selected( settings::get( 'mshield_fingerprint_action' ), 'flag' ); ?>><?php esc_html_e( 'Flag (add order note)', 'mighty-shield' ); ?></option>
                        <option value="notify" <?php selected( settings::get( 'mshield_fingerprint_action' ), 'notify' ); ?>><?php esc_html_e( 'Flag + notify admin via email', 'mighty-shield' ); ?></option>
                    </select>
                    <p class="description"><?php esc_html_e( 'Governs automated-browser and timezone/country-mismatch detections.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Action on Missing Fingerprint', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_fingerprint_missing_action">
                        <option value="flag" <?php selected( settings::get( 'mshield_fingerprint_missing_action' ), 'flag' ); ?>><?php esc_html_e( 'Flag only (safe default)', 'mighty-shield' ); ?></option>
                        <option value="block" <?php selected( settings::get( 'mshield_fingerprint_missing_action' ), 'block' ); ?>><?php esc_html_e( 'Block (stops non-JS bots)', 'mighty-shield' ); ?></option>
                    </select>
                    <p class="description"><?php esc_html_e( 'What to do when no fingerprint is submitted (JavaScript did not run) — the signature of a scripted, non-interactive checkout. Flag by default to accommodate rare no-JS shoppers; set to Block when under active card-testing attack, since real payment already requires JavaScript. Only takes effect when the action above is Block.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Device Velocity Threshold', 'mighty-shield' ); ?></th>
                <td>
                    <input type="number" name="mshield_fingerprint_velocity_threshold" value="<?php echo esc_attr( settings::get( 'mshield_fingerprint_velocity_threshold' ) ); ?>" min="0" step="1" class="small-text" />
                    <p class="description"><?php esc_html_e( 'Max checkout attempts allowed per device within the checkout rate window (Rate Limits tab), regardless of IP. Catches attackers rotating IPs via VPN. Set to 0 to disable. Uses the "Action on Suspicious Device" setting above.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
        </table>
    </div>

    <div class="mshield-section">
        <h2><?php esc_html_e( 'Bot Challenge (CAPTCHA)', 'mighty-shield' ); ?></h2>
        <p class="description"><?php esc_html_e( 'Add an invisible bot challenge to checkout. Cloudflare Turnstile is free and privacy-friendly (recommended); reCAPTCHA v3 is score-based. Strong against automated card-runners and unaffected by IP rotation.', 'mighty-shield' ); ?></p>
        <table class="form-table">
            <tr>
                <th scope="row"><?php esc_html_e( 'Provider', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_captcha_provider">
                        <option value="off" <?php selected( settings::get( 'mshield_captcha_provider' ), 'off' ); ?>><?php esc_html_e( 'Off', 'mighty-shield' ); ?></option>
                        <option value="turnstile" <?php selected( settings::get( 'mshield_captcha_provider' ), 'turnstile' ); ?>><?php esc_html_e( 'Cloudflare Turnstile (recommended)', 'mighty-shield' ); ?></option>
                        <option value="recaptcha_v3" <?php selected( settings::get( 'mshield_captcha_provider' ), 'recaptcha_v3' ); ?>><?php esc_html_e( 'Google reCAPTCHA v3', 'mighty-shield' ); ?></option>
                    </select>
                    <p class="description"><?php esc_html_e( 'Requires both a site key and secret key below. Turnstile keys: dash.cloudflare.com. reCAPTCHA keys: google.com/recaptcha/admin.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Site Key', 'mighty-shield' ); ?></th>
                <td>
                    <input type="text" name="mshield_captcha_site_key" value="<?php echo esc_attr( settings::get( 'mshield_captcha_site_key' ) ); ?>" class="regular-text" />
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Secret Key', 'mighty-shield' ); ?></th>
                <td>
                    <?php $has_captcha_secret = ! empty( settings::get( 'mshield_captcha_secret_key' ) ); ?>
                    <input type="password" name="mshield_captcha_secret_key" value="" class="regular-text" <?php echo $has_captcha_secret ? 'placeholder="••••••••"' : ''; ?> />
                    <p class="description"><?php echo $has_captcha_secret ? esc_html__( 'Secret is saved. Leave blank to keep existing secret.', 'mighty-shield' ) : esc_html__( 'Your provider secret key.', 'mighty-shield' ); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php esc_html_e( 'Action on Failed Challenge', 'mighty-shield' ); ?></th>
                <td>
                    <select name="mshield_captcha_action">
                        <option value="block" <?php selected( settings::get( 'mshield_captcha_action' ), 'block' ); ?>><?php esc_html_e( 'Block (prevent checkout)', 'mighty-shield' ); ?></option>
                        <option value="flag" <?php selected( settings::get( 'mshield_captcha_action' ), 'flag' ); ?>><?php esc_html_e( 'Flag (add order note)', 'mighty-shield' ); ?></option>
                        <option value="notify" <?php selected( settings::get( 'mshield_captcha_action' ), 'notify' ); ?>><?php esc_html_e( 'Flag + notify admin via email', 'mighty-shield' ); ?></option>
                    </select>
                </td>
            </tr>
        </table>
    </div>

    <?php submit_button(); ?>
</form>
