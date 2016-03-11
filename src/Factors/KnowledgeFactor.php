<?php

namespace Firehed\Auth\Factors;

class KnowledgeFactor extends Factor {

    public function getType(): FactorType {
        return FactorType::KNOWLEDGE();
    } // getType

}
