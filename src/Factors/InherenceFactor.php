<?php

namespace Firehed\Auth\Factors;

class InherenceFactor extends Factor {

    public function getType(): FactorType {
        return FactorType::INHERENCE();
    } // getType

}
