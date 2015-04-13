<?php

namespace Firehed\Auth\Factors;

/**
 * @coversDefaultClass Firehed\Auth\Factors\PossessionFactor
 * @covers ::<protected>
 * @covers ::<private>
 */
class PossessionFactorTest extends \PHPUnit_Framework_TestCase {

    use OpaqueEnvelopeTrait;

    /**
     * @covers ::getType
     */
    public function testGetType() {
        $factor = new PossessionFactor($this->getEnvelope());

        $type = $factor->getType();
        $this->assertInstanceOf('Firehed\Common\Enum', $type,
            'getType did not return an Enum object');
        $this->assertSame(FactorType::POSSESSION, $type->getValue(),
            'getType returned the wrong type');
    } // testGetType

}
