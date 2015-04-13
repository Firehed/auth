<?php

namespace Firehed\Auth\Factors;

/**
 * @coversDefaultClass Firehed\Auth\Factors\InherenceFactor
 * @covers ::<protected>
 * @covers ::<private>
 */
class InherenceFactorTest extends \PHPUnit_Framework_TestCase {

    use OpaqueEnvelopeTrait;

    /**
     * @covers ::getType
     */
    public function testGetType() {
        $factor = new InherenceFactor($this->getEnvelope());

        $type = $factor->getType();
        $this->assertInstanceOf('Firehed\Common\Enum', $type,
            'getType did not return an Enum object');
        $this->assertSame(FactorType::INHERENCE, $type->getValue(),
            'getType returned the wrong type');
    } // testGetType

}
