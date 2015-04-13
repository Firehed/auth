<?php

namespace Firehed\Auth\Factors;

class InherenceFactor extends Factor {

    public function getType() {
        return FactorType::INHERENCE();
    } // getType

}
