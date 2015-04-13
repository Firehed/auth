<?php

namespace Firehed\Auth;

use Firehed\Common\OpaqueEnvelope as OE;
use Firehed\Auth\Factors as F;

interface Authable {

    public function getID()/*: string */;

    public function getSupportedAuthenticationFactors()/*: array<factor>*/;

    public function getRequiredAuthenticationFactors()/*: array<factor>*/;

    public function getAuthFactorNotValidBeforeTime()/*: ?\DateTime*/;

    public function validateInherenceFactor(OE $factor)/*: bool*/;

    public function validateKnowledgeFactor(OE $factor)/*: bool*/;

    public function validatePossessionFactor(OE $factor)/*: bool*/;

}
