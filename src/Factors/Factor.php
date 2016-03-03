<?php

namespace Firehed\Auth\Factors;

use DateTime;
use Firehed\Security\Secret;

abstract class Factor {

    private $expiration;

    abstract public function getType()/*: FactorType*/;

    public function __construct(Secret $secret) {
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
