<?php

namespace Firehed\Auth\Factors;

class PossessionFactor extends Factor {

    public function getType() {
        return FactorType::POSSESSION();
    } // getType

}
