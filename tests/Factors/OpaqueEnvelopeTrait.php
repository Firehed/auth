<?php

namespace Firehed\Auth\Factors;

trait OpaqueEnvelopeTrait {

    private function getEnvelope($secret = '') {
        return new \Firehed\Common\OpaqueEnvelope($secret);
    } // getEnvelope

}

