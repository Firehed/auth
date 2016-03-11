<?php
declare(strict_types=1);

namespace Firehed\Auth;

use BadMethodCallException;
use DateTime;
use DateInterval;

use Firehed\Security\Secret;
use Firehed\JWT\{
    Algorithm,
    JWT,
    KeyContainer
};
use Prophecy\Argument;
use Prophecy\Prophecy\MethodProphecy;
use Firehed\Auth\Factors\FactorType as Type;


/**
 * @coversDefaultClass Firehed\Auth\Auth
 * @covers ::<protected>
 * @covers ::<private>
 */
class AuthTest extends \PHPUnit_Framework_TestCase {

    /**
     * @covers ::__construct
     */
    public function testConstruct() {
        $this->assertInstanceOf('Firehed\Auth\Auth', new Auth());
    } // testConstruct

    /**
     * @covers ::validateFactor
     * @dataProvider factors
     */
    public function testValidateFactor(Factors\Factor $f) {
        $a = new Auth();
        $a->setUser($this->getUser(['k' => true,
                                    'i' => true,
                                    'p' => true])->reveal());
        $this->assertSame($a, $a->validateFactor($f),
            'validateFactor did not return $this');
    } // testValidateFactor

    public function testGetUserWithNoData() {
        $a = new Auth();
        $this->expectException(Exceptions\UserNotFoundException::class);
        $a->getUser();
    }

    /**
     * @covers ::isMissingKnowledgeFactor
     * @covers ::isMissingPossessionFactor
     * @covers ::isMissingInherenceFactor
     */
    public function testMissingChecks() {
        $a = new Auth();
        $user = $this->getUser(['k' => true,
                                'i' => true,
                                'p' => true]);
        $user->getRequiredAuthenticationFactors()
            ->willReturn([
                Type::KNOWLEDGE(),
                Type::POSSESSION(),
                Type::INHERENCE()]);

        $a->setUser($user->reveal());
        $this->assertTrue($a->isMissingKnowledgeFactor(),
            'Should be missing knowledge factor');
        $this->assertTrue($a->isMissingPossessionFactor(),
            'Should be missing possession factor');
        $this->assertTrue($a->isMissingInherenceFactor(),
            'Should be missing inherence factor');

        $a->validateFactor($this->getFactor(Type::KNOWLEDGE())->reveal());
        $this->assertFalse($a->isMissingKnowledgeFactor(),
            'Should not be missing knowledge factor');
        $this->assertTrue($a->isMissingPossessionFactor(),
            'Should be missing possession factor');
        $this->assertTrue($a->isMissingInherenceFactor(),
            'Should be missing inherence factor');

        $a->validateFactor($this->getFactor(Type::POSSESSION())->reveal());
        $this->assertFalse($a->isMissingKnowledgeFactor(),
            'Should not be missing knowledge factor');
        $this->assertFalse($a->isMissingPossessionFactor(),
            'Should not be missing possession factor');
        $this->assertTrue($a->isMissingInherenceFactor(),
            'Should be missing inherence factor');

        $a->validateFactor($this->getFactor(Type::INHERENCE())->reveal());
        $this->assertFalse($a->isMissingKnowledgeFactor(),
            'Should not be missing knowledge factor');
        $this->assertFalse($a->isMissingPossessionFactor(),
            'Should not be missing possession factor');
        $this->assertFalse($a->isMissingInherenceFactor(),
            'Should not be missing inherence factor');

    }

    /**
     * @covers ::validateFactor
     * @dataProvider factors
     * @expectedException Firehed\Auth\Exceptions\AuthenticationFailedException
     */
    public function testValidateFactorFailure(Factors\Factor $f) {
        $a = new Auth();
        $a->setUser($this->getUser()->reveal());
        $a->validateFactor($f);
    } // testValidateFactorFailure


    /**
     * @covers ::setRequiredLevel
     * @dataProvider levels
     */
    public function testSetRequiredLevelIsChainable(Level $level) {
        $a = new Auth();
        $this->assertSame($a, $a->setRequiredLevel($level),
            'setRequiredLevel did not return $this');
    } // testSetRequiredLevelIsChainable

    /**
     * @covers ::setLoader
     */
    public function testSetLoaderIsChainable() {
        $a = new Auth();
        $this->assertSame($a, $a->setLoader(function() {}),
            'setLoader did not return $this');
    } // testSetLoaderIsChainable

    /**
     * @covers ::getEncodedToken
     */
    public function testGetToken() {
        $uid = 'some user id';

        $u = $this->getUser(['k' => true]);
        $u->getID()
            ->willReturn($uid);

        $a = new Auth();
        $a->setUser($u->reveal());
        $a->validateFactor($this->getFactor(Type::KNOWLEDGE())->reveal());
        $a->setKeys($this->getKeyContainer());

        $tok = $a->getEncodedToken();
        $this->assertTrue(is_string($tok), 'Encoded token was not a string');

        return [$tok, $uid];
    } // testGetToken

    /**
     * @covers ::getUser
     * @covers ::setEncodedToken
     * @depends testGetToken
     */
    public function testGetUserReturnsUserFromToken(array $params) {
        list($tok, $known_uid) = $params;
        $user = $this->getUser()->reveal();
        $loader = function($uid) use ($known_uid, $user) {
            $this->assertSame($known_uid, $uid,
                'loader did not receive correct UID');
            return $user;
        };
        $a = new Auth();
        $u = $a->setKeys($this->getKeyContainer())
            ->setEncodedToken($tok)
            ->setLoader($loader)
            ->getUser();
        $this->assertSame($user, $u,
            'Incorrect user');
    } // testGetUserReturnsUserFromToken

    /**
     * @covers ::getUser
     */
    public function testGetUserFromExistingToken() {
        $claims = [
            'uid' => '6dbf8cbb2900acd8ba853410830e1c0d',
            'ifct' => null,
            'ifet' => null,
            'kfct' => '2015-04-13T00:55:05+0000',
            'kfet' => null,
            'pfct' => null,
            'pfet' => null,
            'hst' => null,
        ];
        $str = $this->getTokenFromClaims($claims);

        $user = $this->getUser()->reveal();
        $a = new Auth();
        $a->setKeys($this->getKeyContainer());
        $this->assertSame($user,
            $a->setEncodedToken($str)
                ->setLoader(function($uid) use ($claims, $user) {
                    $this->assertSame($claims['uid'], $uid,
                        'Loader was passed the wrong UID');
                    return $user;
                })
                ->getUser(),
            'The wrong user was returned from getUser');
    } // testGetUserFromExistingToken

    /**
     * @covers ::setUser
     * @covers ::getUser
     * @expectedException Firehed\Auth\Exceptions\AuthenticationRequiredException
     */
    public function testGetUserThatWasSetFailsWithoutFactors() {
        $a = new Auth();
        $u = $this->getUser()->reveal();
        $a->setUser($u)
            ->setRequiredLevel(Level::LOGIN())
            ->getUser();
    } // testGetUserThatWasSetFailsWithoutFactors

    /**
     * @covers ::getUser
     * @covers ::isMissingUser
     */
    public function testGetUserThrowsWhenInPartialMode() {
        $a = new Auth();
        $a->setLoader(function() {})
            ->setRequiredLevel(Level::PARTIAL());
        try {
            $a->getUser();
            $this->fail('Expected exception not thrown');
        } catch (Exceptions\UserNotFoundException $e) {
            $this->assertTrue($a->isMissingUser());
        }
    }

    /**
     * @covers ::getUser
     */
    public function testGetUserDoesNotThrowWhenUnauthUserIsPresentInPartialMode() {
        $a = new Auth();
        $a->setUser($this->getUser(['k' => true])->reveal());
        $a->setRequiredLevel(Level::PARTIAL());
        $this->assertNull($a->getUser());

    }

    /**
     * @dataProvider factors
     * @covers ::validateFactor
     */
    public function testValidateFactorThrowsWithNoUser(Factors\Factor $factor) {
        $a = new Auth();
        $a->setLoader(function() {})
            ->setRequiredLevel(Level::PARTIAL());
        $this->expectException(BadMethodCallException::class);
        $a->validateFactor($factor);
    }

    /**
     * @covers ::setUser
     * @covers ::getUser
     * @expectedException Firehed\Auth\Exceptions\AuthenticationRequiredException
     */
    public function testSetUserWipesExistingAuth() {
        $a = new Auth();
        $u = $this->getUser(['k' => true])->reveal();
        $kf = $this->getFactor(Type::KNOWLEDGE())->reveal();
        try {
            $a->setUser($u)
                ->validateFactor($kf)
                ->getUser();
        } catch (Exceptions\AuthException $e) {
            $this->fail('Sanity check failed; initial auth should have worked');
        }
        $new_user = $this->getUser(['k' => true])->reveal();
        $a->setUser($new_user)
            ->getUser();
    } // testSetUserWipesExistingAuth

    ///////////////////////////////////

    /**
     * @covers ::getUser
     * @expectedException Firehed\Auth\Exceptions\HighSecurityAuthenticationRequiredException
     */
    public function testGetUserEnforcesHighSecurityRequirement() {
        $factor = $this->getFactor(Type::KNOWLEDGE());
        $user = $this->getUser(['k' => true]);

        $a = new Auth();
        $a->setRequiredLevel(Level::HISEC())
            ->setUser($user->reveal())
            ->validateFactor($factor->reveal())
            ->getUser();
    }

    public function testGetUserReturnsUserWhenFactorsAreValid() {
        $factor = $this->getFactor(Type::KNOWLEDGE());
        $user = $this->getUser(['k' => true]);

        $a = new Auth();
        $a->setRequiredLevel(Level::LOGIN())
            ->setUser($user->reveal())
            ->validateFactor($factor->reveal())
            ->getUser();
    }

    /**
     * @covers ::expireFactor
     * @dataProvider factors
     */
    public function testExpireFactor(Factors\Factor $f) {
        $u = $this->getUser(['i' => true, 'k' => true, 'p' => true]);
        $u->getRequiredAuthenticationFactors()
            ->willReturn([$f->getType()]);

        $a = new Auth();
        $a->setUser($u->reveal())
            ->validateFactor($f)
            ->getUser(); // Watch for an exception as a sanity check

        $this->setExpectedException(
            'Firehed\Auth\Exceptions\AuthenticationRequiredException');
        $a->expireFactor($f->getType());
        $a->getUser();
    } // testExpireFactor


    /**
     * @covers ::enterHighSecurity
     */
    public function testEnterHighSecurity() {
        $kf = $this->getFactor(Type::KNOWLEDGE());
        $pf = $this->getFactor(Type::POSSESSION());
        $user = $this->getUser(['k' => true, 'p' => true]);
        $user->getRequiredAuthenticationFactors()
            ->willReturn([Type::KNOWLEDGE(), Type::POSSESSION()]);
        $user = $user->reveal();

        $a = new Auth();
        $a->setUser($user)
            ->validateFactor($kf->reveal())
            ->validateFactor($pf->reveal())
            ->getUser(); // This is more of a sanity check

        $a->setRequiredLevel(Level::HISEC());

        try {
            $a->getUser();
            $this->fail('A HighSecurity exception should have been thrown');
        } catch (Exceptions\HighSecurityAuthenticationRequiredException $e) {
            // Good
        }

        $kf2 = $this->getFactor(Type::KNOWLEDGE());
        $a->enterHighSecurity($kf2->reveal());

        $this->assertSame($user, $a->getUser(),
            'getUser should have worked after entering high security mode');
        return $a;
    }
    /**
     * @covers ::exitHighSecurity
     * @depends testEnterHighSecurity
     * @expectedException Firehed\Auth\Exceptions\HighSecurityAuthenticationRequiredException
     */
    public function testExitHighSecurity(Auth $a) {

        try {
            $a->getUser();
        } catch (Exceptions\HighSecurityAuthenticationRequiredException $e) {
            $this->fail(
                'getUser should work until high security mode has been exited');
        }
        $a->exitHighSecurity();
        $a->getUser();
    }


    public function testResumingHighSecuritySession() {
        // Simluate a hisec session that expires in 15 min
        $claims = [
            'uid' => '6dbf8cbb2900acd8ba853410830e1c0d',
            'ifct' => null,
            'ifet' => null,
            'kfct' => '2015-04-13T00:55:05+0000',
            'kfet' => null,
            'pfct' => null,
            'pfet' => null,
            'hst' => $this->getDateTime('P15M')->format(DateTime::ISO8601),
        ];
        $str = $this->getTokenFromClaims($claims);

        $user = $this->getUser()->reveal();

        $a = new Auth();
        $a->setKeys($this->getKeyContainer());

        $this->assertSame($user,
            $a->setEncodedToken($str)
                ->setRequiredLevel(Level::HISEC())
                ->setLoader(function($uid) use ($claims, $user) {
                    $this->assertSame($claims['uid'], $uid,
                        'Loader was passed the wrong UID');
                    return $user;
                })
                ->getUser(),
            'The wrong user was returned from getUser');

    } // testResumingHighSecuritySession


    /**
     * @expectedException Firehed\Auth\Exceptions\HighSecurityAuthenticationRequiredException
     */
    public function testResumingExpiredHighSecuritySession() {
        // Simluate a hisec session that expires in 15 min
        $claims = [
            'uid' => '6dbf8cbb2900acd8ba853410830e1c0d',
            'ifct' => null,
            'ifet' => null,
            'kfct' => '2015-04-13T00:55:05+0000',
            'kfet' => null,
            'pfct' => null,
            'pfet' => null,
            'hst' => $this->getDateTime('-P15M')->format(DateTime::ISO8601),
        ];
        $str = $this->getTokenFromClaims($claims);

        $user = $this->getUser()->reveal();

        $a = new Auth();
        $a->setKeys($this->getKeyContainer());
        $this->assertSame($user,
            $a->setEncodedToken($str)
                ->setRequiredLevel(Level::HISEC())
                ->setLoader(function($uid) use ($claims, $user) {
                    $this->assertSame($claims['uid'], $uid,
                        'Loader was passed the wrong UID');
                    return $user;
                })
                ->getUser(),
            'The wrong user was returned from getUser');

    } // testResumingHighSecuritySession

    /**
     */
    public function testResumingPartialAuthOfMFAUser() {
        // This is typically what happens between the password and OTP pages in
        // a common login flow. This checks that the resumed auth session is
        // still invalid until the second factor is validated.
        $claims = [
            'uid' => '6dbf8cbb2900acd8ba853410830e1c0d',
            'ifct' => null,
            'ifet' => null,
            'kfct' => '2015-04-13T00:55:05+0000',
            'kfet' => null,
            'pfct' => null,
            'pfet' => null,
            'hst' => null,
        ];
        $str = $this->getTokenFromClaims($claims);

        $user = $this->getUser(['p' => true]); // knowledge is already validated
        $user->getRequiredAuthenticationFactors()
            ->willReturn([Type::KNOWLEDGE(), Type::POSSESSION()]);
        $user = $user->reveal();


        $a = new Auth();
        $a->setKeys($this->getKeyContainer())
            ->setEncodedToken($str)
            ->setLoader(function($uid) use ($claims, $user) {
                $this->assertSame($claims['uid'], $uid,
                    'Loader was passed the wrong UID');
                return $user;
            });
        try {
            $a->getUser();
            $this->fail('An AuthRequiredException was not thrown');
        }
        catch (Exceptions\AuthenticationRequiredException $e) {
            // OK
            return [$a, $user];
        }
    }

    /**
     * @depends testResumingPartialAuthOfMFAUser
     */
    public function testValidationOfMFA(array $params) {
        list($a, $user) = $params;

        $pf = $this->getFactor(Type::POSSESSION());
        $a->validateFactor($pf->reveal());
        $this->assertSame($user, $a->getUser());

    }


    /**
     * @covers ::getUser
     */
    public function testGetUserAlwaysReturnsNullAtAnonymousLevel() {
        $a = new Auth();
        $user = $a->setUser($this->getUser()->reveal())
            ->setRequiredLevel(Level::ANONYMOUS())
            ->getUser();
        $this->assertNull($user,
            'getUser did not return null for anonymous auth');
    }



    /**
     * @expectedException Firehed\Auth\Exceptions\FactorExpiredException
     */
    public function testExpiredFactorFails() {
        $user = $this->getUser(['k' => true])->reveal();
        $kf = $this->getFactor(Type::KNOWLEDGE(),
            (new DateTime())->sub(new DateInterval('PT10M')));

        $a = new Auth();
        $a->setUser($user)
            ->validateFactor($kf->reveal())
            ->getUser();
        // create+validate a factor where expiration time is in the past
        // attempt to getuser with it
    }
    /**
     * @expectedException Firehed\Auth\Exceptions\FactorExpiredException
     */
    public function testInvalidationOfExistingFactors() {
        $a = new Auth();
        $u = $this->getUser(['k' => true]);
        $u->getAuthFactorNotValidBeforeTime()
            ->willReturn((new DateTime())->add(new DateInterval('PT1M')));
        $kf = $this->getFactor(Type::KNOWLEDGE());
//        $kf->getExpiration()
//            ->willReturn((new DateTime())->sub(new DateInterval('PT1M')));
        $a->setUser($u->reveal())
            ->validateFactor($kf->reveal())
            ->getUser();

        // create valid auth and factor
        // change user behavior to return NVBT in the past
        // call getUser
    }


    /**
     * @expectedException Firehed\Auth\Exceptions\AuthenticationRequiredException
     */
    public function testAllFactorsAreRequiredForMFAUser() {
        $user = $this->getUser(['k' => true, 'i' => true, 'p' => true]);
        // Ultra-sec user requires three factor auth
        $user->getRequiredAuthenticationFactors()
            ->willReturn([Type::KNOWLEDGE(),
                Type::POSSESSION(),
                Type::INHERENCE()]);

        $kf = $this->getFactor(Type::KNOWLEDGE());
        $pf = $this->getFactor(Type::POSSESSION());
        // Inherence is missing

        $a = new Auth();
        $a->setUser($user->reveal());
        try {
            $a->validateFactor($kf->reveal())
            ->validateFactor($pf->reveal());
        }
        catch (Exceptions\AuthException $e) {
            $this->fail('No exception should have been thrown while '.
                'validating the knowledge factor');
        }

        $a->getUser();
    }

    /**
     * @dataProvider factors
     */
    public function testValidityNeverLeaksThrough(Factors\Factor $factor) {
        $a = new Auth();
        $user = $this->getUser(); // fail validation
        $user->getRequiredAuthenticationFactors()
            ->willReturn([Type::KNOWLEDGE(),
                Type::POSSESSION(),
                Type::INHERENCE()]);

        $a->setUser($user->reveal());

        $this->assertTrue($a->isMissingKnowledgeFactor());
        $this->assertTrue($a->isMissingPossessionFactor());
        $this->assertTrue($a->isMissingInherenceFactor());

        try {
            $a->validateFactor($factor);
            $this->fail("Factor should have failed validation");
        } catch (Exceptions\AuthException $e) {}
        $this->assertTrue($a->isMissingKnowledgeFactor(),
            'Knowledge factor leaked');
        $this->assertTrue($a->isMissingPossessionFactor(),
            'Possession factor leaked');
        $this->assertTrue($a->isMissingInherenceFactor(),
            'Inherence factor leaked');

    }

    // -( DataProviders )------------------------------------------------------

    public function factors() {
        $out = [];
        $types = [Type::INHERENCE(), Type::KNOWLEDGE(), Type::POSSESSION()];
        foreach ($types as $type) {
            $out[] = [$this->getFactor($type)->reveal()];
        }
        return $out;
    } // factors

    public function levels() {
        return [
            [Level::ANONYMOUS()],
            [Level::LOGIN()],
            [Level::HISEC()],
        ];
    } // levels

    // -( Helpers )------------------------------------------------------------

    /**
     * @return Prophecy\Prophecy\ObjectProphecy
     */
    private function getUser(array $values = []) {
        $values = $values + [
            'k' => false,
            'i' => false,
            'p' => false,
        ];
        $type = Argument::type('Firehed\Security\Secret');
        $user = $this->prophesize('Firehed\Auth\Authable');
        $user->validateInherenceFactor($type)
            ->willReturn($values['i']);
        $user->validateKnowledgeFactor($type)
            ->willReturn($values['k']);
        $user->validatePossessionFactor($type)
            ->willReturn($values['p']);
        $user->getID()
            ->willReturn('user_id');
        $user->getAuthFactorNotValidBeforeTime()
            ->willReturn(new DateTime('@0')); // Unixtime 0
        // Default user behavior is password-only
        $user->getRequiredAuthenticationFactors()
            ->willReturn([Type::KNOWLEDGE()]);
        return $user;
    } // getUser

    /**
     * @return Prophecy\Prophecy\ObjectProphecy
     */
    private function getFactor(Type $type, DateTime $exp = null) {
        switch ($type->getValue()) {
        case Type::INHERENCE:
            $name = 'InherenceFactor';
            break;
        case Type::KNOWLEDGE:
            $name = 'KnowledgeFactor';
            break;
        case Type::POSSESSION:
            $name = 'PossessionFactor';
            break;
        }
        $factor = $this->prophesize('Firehed\Auth\Factors\\'.$name);
        $factor->getType()->willReturn($type);
        $factor->getExpiration()->willReturn($exp);
        $factor->getSecret()->willReturn(new Secret(''));
        return $factor;
    } // getFactor

    private function getDateTime($offset = ''): DateTime {
        $dt = new DateTime();
        if ($offset) {
            if ($offset[0] == '-') {
                $dt->sub(new DateInterval(substr($offset, 1)));
            }
            else {
                $dt->add(new DateInterval($offset));
            }
        }
        return $dt;
    } // getDateTime

    private function getKeyContainer(): KeyContainer {
        $kc = new KeyContainer();
        $kc->addKey(1, Algorithm::HMAC_SHA_256(), new Secret('top secret'));
        return $kc;
    }

    private function getTokenFromClaims(array $claims): string {
        return (new JWT($claims))
            ->setKeys($this->getKeyContainer())
            ->getEncoded();
    }
}
