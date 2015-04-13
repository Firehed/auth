<?php

namespace Firehed\Auth\Exceptions;

class AuthenticationRequiredException extends AuthException {

    private $missing_factors = [];
    public function __construct(array $missing_factors) {
        parent::__construct(); // TODO this
        $this->missing_factors = $missing_factors;
    }

}
