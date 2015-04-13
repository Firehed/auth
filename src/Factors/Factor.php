<?php

namespace Firehed\Auth\Factors;

use DateTime;
use Firehed\Common\OpaqueEnvelope;

abstract class Factor {

    private $expiration;

    abstract public function getType()/*: FactorType*/;

    public function __construct(OpaqueEnvelope $secret) {
        $this->secret = $secret;
    } // __construct

    public function getSecret()/*: OpaqueEnvelope*/ {
        return $this->secret;
    } // getSecret

    public function getExpiration()/*: ?DateTime*/ {
        return $this->expiration;
    } // getExpiration

    public function setExpiration(DateTime $expiration)/*: this*/ {
        $this->expiration = $expiration;
        return $this;
    } // setExpiration

}
