<?php

namespace Firehed\Auth\Factors;

class PossessionFactor extends Factor {

    public function getType(): FactorType {
        return FactorType::POSSESSION();
    } // getType

}
