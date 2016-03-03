<?php

namespace Firehed\Auth\Factors;

trait SecretTrait {

    private function getEnvelope($secret = '') {
        return new \Firehed\Security\Secret($secret);
    } // getEnvelope

}

