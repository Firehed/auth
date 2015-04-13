<?php

namespace Firehed\Auth\Factors;

class KnowledgeFactor extends Factor {

    public function getType() {
        return FactorType::KNOWLEDGE();
    } // getType

}
