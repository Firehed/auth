<?php

namespace Firehed\Auth;

use Firehed\Common\OpaqueEnvelope as OE;

interface Authable {

    public function getAuthFactorNotValidBeforeTime()/*: ?\DateTime*/;

    public function getID()/*: string */;

    public function getRequiredAuthenticationFactors()/*: array<Factors\FactorType>*/;

    public function validateInherenceFactor(OE $factor)/*: bool*/;

    public function validateKnowledgeFactor(OE $factor)/*: bool*/;

    public function validatePossessionFactor(OE $factor)/*: bool*/;

}
