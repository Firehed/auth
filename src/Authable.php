<?php

namespace Firehed\Auth;

use DateTime;
use Firehed\Security\Secret;

interface Authable {

    // This is used to expire old authentication factors. Any factor
    // authenticated before the returned time will be treated as invalid.
    // This allows for a primative form of "log out everywhere" by recording
    // the user's logout time and then returning that value. Any other sessions
    // will be invalidated.
    public function getAuthFactorNotValidBeforeTime(): DateTime;

    public function getID()/*: mixed */;

    public function getRequiredAuthenticationFactors(): array/*<Factors\FactorType>*/;

    public function validateInherenceFactor(Secret $secret): bool;

    public function validateKnowledgeFactor(Secret $secret): bool;

    public function validatePossessionFactor(Secret $secret): bool;

}
