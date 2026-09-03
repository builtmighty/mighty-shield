<?php
/**
 * Payment Intelligence tab.
 *
 * What MightyShield can actually learn from each payment method you accept.
 *
 * Read-only on purpose. There is nothing to configure — capability is decided
 * by what each processor exposes, not by a setting — and the useful thing is
 * knowing which of your methods give you which protections, so you are never
 * surprised by a check that quietly does nothing on one of your stores.
 *
 * @package MightyShield
 * @since   1.9.0
 */

if( ! defined( 'WPINC' ) ) { die; }

use MightyShield\Includes\gateways;
use MightyShield\Includes\settings;

$report    = gateways::capability_report();
$supported = gateways::supported_report();
?>

<div class="mshield-section">

    <div class="mshield-eyebrow"><?php esc_html_e( 'Supported', 'mighty-shield' ); ?></div>

    <h2><?php esc_html_e( 'Processors', 'mighty-shield' ); ?></h2>

    <p class="description">
        <?php esc_html_e( 'MightyShield supports these payment processors specifically, so it can ask for extra card verification, hold an authorization without taking the money, or read back the card checks. Every other processor still gets the full scoring pipeline and the full response ladder.', 'mighty-shield' ); ?>
    </p>

    <?php
    // Real brand marks, served as <img> rather than inlined. authorize.svg
    // carries its own <style> block using generic class names (.st0 and
    // friends); inlined, those would leak into the page and collide with
    // anything else that happens to use them. An <img> renders the file in its
    // own document, so its styles stay inside it.
    //
    // Braintree and PayPal share a mark on purpose: Braintree is PayPal's
    // enterprise product and is branded as such.
    $logos = [
        'stripe'        => 'stripe.svg',
        'woopayments'   => 'woo.svg',
        'square'        => 'square.svg',
        'authorize_net' => 'authorize.svg',
        'braintree'     => 'paypal.svg',
        'paypal'        => 'paypal.svg',
    ];
    ?>

    <div class="mshield-supported">
        <?php foreach( $supported as $brand => $row ) : ?>
            <div class="mshield-supcard<?php echo $row['active'] ? ' is-active' : ''; ?>">

                <?php if( isset( $logos[ $brand ] ) ) : ?>
                    <?php /* The name is right below it, so the mark is decoration and
                             takes an empty alt rather than repeating the label to a
                             screen reader. */ ?>
                    <span class="ms-logo">
                        <img src="<?php echo esc_url( MSHIELD_URI . 'assets/svgs/' . $logos[ $brand ] ); ?>"
                             alt="" aria-hidden="true" loading="lazy" />
                    </span>
                <?php endif; ?>

                <span class="ms-name"><?php echo esc_html( $row['label'] ); ?></span>

                <?php /* Both states carry a pill so the tiles stay the same height and
                         the capability line below them stays on one baseline. */ ?>
                <?php if( $row['active'] ) : ?>
                    <span class="mshield-pill is-ok"><span class="dot"></span><?php esc_html_e( 'Active', 'mighty-shield' ); ?></span>
                <?php else : ?>
                    <span class="mshield-pill is-muted"><span class="dot"></span><?php esc_html_e( 'Inactive', 'mighty-shield' ); ?></span>
                <?php endif; ?>

                <span class="ms-caps">
                    <?php
                    $caps = [];
                    if( $row['3ds'] )          $caps[] = __( '3-D Secure', 'mighty-shield' );
                    if( $row['auth_only'] )    $caps[] = __( 'Authorize & hold', 'mighty-shield' );
                    if( $row['card_signals'] ) $caps[] = __( 'Card checks', 'mighty-shield' );
                    echo $caps ? esc_html( implode( ' · ', $caps ) ) : esc_html__( 'Partial', 'mighty-shield' );
                    ?>
                </span>

                <?php if( $row['note'] !== '' ) : ?>
                    <span class="mshield-hint"><?php echo esc_html( $row['note'] ); ?></span>
                <?php endif; ?>

            </div>
        <?php endforeach; ?>
    </div>


</div>

<div class="mshield-section">

    <h2><?php esc_html_e( 'Payment Methods', 'mighty-shield' ); ?></h2>

    <p class="description">
        <?php esc_html_e( 'Everything on the Scoring and Blocking tabs works the same on every payment method, because it is judged before the payment is taken. The two things below depend on what the payment provider itself is willing to tell us, so they vary.', 'mighty-shield' ); ?>
    </p>

    <?php if( empty( $report ) ) : ?>

        <p class="description">
            <?php esc_html_e( 'No payment methods are currently enabled at checkout, so there is nothing to report.', 'mighty-shield' ); ?>
        </p>

    <?php else : ?>

        <table class="mshield-table">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Payment method', 'mighty-shield' ); ?></th>
                    <th style="width:190px;"><?php esc_html_e( 'Extra card verification', 'mighty-shield' ); ?></th>
                    <th style="width:190px;"><?php esc_html_e( 'Card checks', 'mighty-shield' ); ?></th>
                    <th style="width:190px;"><?php esc_html_e( 'Authorize without charging', 'mighty-shield' ); ?></th>
                </tr>
            </thead>
            <tbody>

            <?php foreach( $report as $id => $row ) : ?>

                <tr>
                    <td>
                        <span class="mshield-sig-name"><?php echo esc_html( $row['title'] ); ?></span><br />
                        <code class="mshield-sig-key"><?php echo esc_html( $id ); ?></code>
                    </td>

                    <td>
                        <?php if( $row['3ds'] ) : ?>
                            <span class="mshield-pill is-ok"><span class="dot"></span><?php esc_html_e( 'Available', 'mighty-shield' ); ?></span>
                        <?php else : ?>
                            <span class="mshield-pill is-muted"><span class="dot"></span><?php esc_html_e( 'Not available', 'mighty-shield' ); ?></span>
                            <span class="mshield-hint">
                                <?php esc_html_e( 'This provider has no way to ask for it on a single order. Challenged orders go through as normal.', 'mighty-shield' ); ?>
                            </span>
                        <?php endif; ?>
                    </td>

                    <td>
                        <?php if( $row['card_signals'] ) : ?>
                            <span class="mshield-pill is-ok"><span class="dot"></span><?php esc_html_e( 'Available', 'mighty-shield' ); ?></span>
                            <span class="mshield-hint">
                                <?php esc_html_e( 'Billing address and security code results are read after payment. This needs webhooks set up in your provider\'s dashboard. Without them the results never arrive and the checks are simply skipped.', 'mighty-shield' ); ?>
                            </span>
                        <?php else : ?>
                            <span class="mshield-pill is-muted"><span class="dot"></span><?php esc_html_e( 'Not available', 'mighty-shield' ); ?></span>
                        <?php endif; ?>
                    </td>

                    <td>
                        <?php if( $row['auth_only'] ) : ?>
                            <span class="mshield-pill is-ok"><span class="dot"></span><?php esc_html_e( 'Available', 'mighty-shield' ); ?></span>
                            <span class="mshield-hint">
                                <?php esc_html_e( 'Funds can be reserved and released without ever being taken.', 'mighty-shield' ); ?>
                            </span>
                        <?php else : ?>
                            <span class="mshield-pill is-muted"><span class="dot"></span><?php esc_html_e( 'Not available', 'mighty-shield' ); ?></span>
                            <span class="mshield-hint">
                                <?php esc_html_e( 'This provider cannot authorize without charging. Orders set to be authorized and held are held before payment instead, so nothing is taken.', 'mighty-shield' ); ?>
                            </span>
                        <?php endif; ?>
                    </td>
                </tr>

            <?php endforeach; ?>

            </tbody>
        </table>

    <?php endif; ?>

</div>
