<?php

namespace Firehed\Auth\Factors;

use DateTime;

/**
 * @coversDefaultClass Firehed\Auth\Factors\Factor
 * @covers ::<protected>
 * @covers ::<private>
 */
class FactorTest extends \PHPUnit_Framework_TestCase {

    /**
     * @covers ::__construct
     */
    public function testConstruct() {
        $factor = new ConcreteFactor($this->getEnvelope());
        $this->assertInstanceOf('Firehed\Auth\Factors\Factor', $factor);
    } // testConstruct

    /**
     * @covers ::getSecret
     */
    public function testGetSecret() {
        $secret = $this->getEnvelope();
        $factor = new ConcreteFactor($secret);
        $this->assertSame($secret, $factor->getSecret(),
            'getSecret did not return the secret passed to the constructor.');
    } // testGetSecret

    /**
     * @covers ::getExpiration
     */
    public function testGetExpirationDefaultsToNull() {
        $factor = new ConcreteFactor($this->getEnvelope());
        $this->assertNull($factor->getExpiration(),
            'A factor where the expiration was not set returned a non-null '.
            'expiration value.');
    } // testGetExpirationDefaultsToNull

    /**
     * @covers ::getExpiration
     */
    public function testGetExpirationAfterSet() {
        $factor = new ConcreteFactor($this->getEnvelope());
        $exp = new DateTime();
        $factor->setExpiration($exp);
        $this->assertEquals($exp, $factor->getExpiration(),
            'getExpiration did not return the set timestamp');
    } // testGetExpirationAfterSet

    /**
     * @covers ::setExpiration
     */
    public function testSetExpirationIsChainable() {
        $factor = new ConcreteFactor($this->getEnvelope());
        $exp = new DateTime();
        $this->assertSame($factor, $factor->setExpiration($exp),
            'setExpiration did not return $this');
    } // testSetExpirationIsChainable

    private function getEnvelope($secret = '') {
        return new \Firehed\Common\OpaqueEnvelope($secret);
    } // getEnvelope

}

class ConcreteFactor extends Factor {
    public function getType() { }
}

