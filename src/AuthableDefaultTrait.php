<?php

namespace Firehed\Auth;

use BadMethodCallException;
use Firehed\Security\Secret;

trait AuthableDefaultTrait {

    /**
     * By default, assume no factors are expired. Override this and return
     * a DateTime to trigger an expiration
     */
    public function getAuthFactorNotValidBeforeTime()/*: ?DateTime*/ {
        return null;
    } // getAuthFactorNotValidBeforeTime

    /**
     * By default, assume knowledge factors (e.g. passwords) are exclusively
     * supported. Override this to support MFA.
     * @return array<Factors\FactorType>
     */
    public function getRequiredAuthenticationFactors(): array {
        return [Factors\FactorType::KNOWLEDGE()];
    } // getRequiredAuthenticationFactors

    /**
     * Implement all three factor type validation, but reject any attempt to
     * use them. This is done strictly to implement the Authable interface
     * without having to write no-op methods for unsupported factors (your
     * application probably does not support biometrics, for example)
     *
     * @return bool
     */
    public function validateInherenceFactor(Secret $secret): bool {
        // There don't appear to be any common standards for biometric
        // authentication, but should one emerge, this would probably be
        // implemented by using `hash_equals` to compare a known hash against
        // one provided from a device output
        throw new BadMethodCallException(
            'The default implementation does not support inherence factors. '.
            'Override this method to support them.');
    } // validateInherenceFactor

    public function validateKnowledgeFactor(Secret $secret): bool {
        // Your implementation will likely look something like this:
        // return \password_verify($secret->reveal(), $this->getHashFromDB());
        throw new BadMethodCallException(
            'The default implementation does not support knowledge factors. '.
            'Override this method to support them.');
    } // validateKnowledgeFactor

    public function validatePossessionFactor(Secret $secret): bool {
        // Your implemenation may look as follows if you use the
        // firehed/security package (https://github.com/Firehed/Security)
        //
        // $key = $this->getOTPKey(); // binary string >= 128 bits
        // $opts = []; // Configurable to have a longer output and better
        //             // hashing algos, but Google Authenticator only supports
        //             // 6-digit SHA-1 outputs.
        // return \hash_equals(TOTP($key, $opts), $secret->reveal());
        throw new BadMethodCallException(
            'The default implementation does not support possession factors. '.
            'Override this method to support them.');
    } // validatePossessionFactor

}
