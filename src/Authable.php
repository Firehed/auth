<?php

namespace Firehed\Auth;

use Firehed\Security\Secret;

interface Authable {

    // This is used to expire old authentication factors. When returning
    // a non-null value, any factor authenticated before the returned time will
    // be treated as invalid.
    // This allows for a primative form of "log out everywhere" by recording
    // the user's logout time and then returning that value. Any other sessions
    // will be invalidated.
    public function getAuthFactorNotValidBeforeTime()/*: ?\DateTime*/;

    public function getID()/*: string */;

    public function getRequiredAuthenticationFactors()/*: array<Factors\FactorType>*/;

    public function validateInherenceFactor(Secret $factor)/*: bool*/;

    public function validateKnowledgeFactor(Secret $factor)/*: bool*/;

    public function validatePossessionFactor(Secret $factor)/*: bool*/;

}
