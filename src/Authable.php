<?php

namespace Firehed\Auth;

use Firehed\Security\Secret;

interface Authable {

    public function getAuthFactorNotValidBeforeTime()/*: ?\DateTime*/;

    public function getID()/*: string */;

    public function getRequiredAuthenticationFactors()/*: array<Factors\FactorType>*/;

    public function validateInherenceFactor(Secret $factor)/*: bool*/;

    public function validateKnowledgeFactor(Secret $factor)/*: bool*/;

    public function validatePossessionFactor(Secret $factor)/*: bool*/;

}
