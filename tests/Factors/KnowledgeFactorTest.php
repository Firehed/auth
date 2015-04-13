<?php

namespace Firehed\Auth\Factors;

/**
 * @coversDefaultClass Firehed\Auth\Factors\KnowledgeFactor
 * @covers ::<protected>
 * @covers ::<private>
 */
class KnowledgeFactorTest extends \PHPUnit_Framework_TestCase {

    use OpaqueEnvelopeTrait;

    /**
     * @covers ::getType
     */
    public function testGetType() {
        $factor = new KnowledgeFactor($this->getEnvelope());

        $type = $factor->getType();
        $this->assertInstanceOf('Firehed\Common\Enum', $type,
            'getType did not return an Enum object');
        $this->assertSame(FactorType::KNOWLEDGE, $type->getValue(),
            'getType returned the wrong type');
    } // testGetType

}
