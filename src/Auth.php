<?php

namespace Firehed\Auth;

use DateTime;
use Firehed\Auth\Factors\Factor;
use Firehed\Auth\Factors\FactorType;
use Firehed\Auth\Exceptions as AE;
use Firehed\JWT\JWT;
use BadMethodCallException;

class Auth {
    const RET_OK = 0;
    const RET_EXP = 1;
    const RET_UNAUTH = 2;

    // userid
    private $uid = '';
    // Factor timestamps (factor create time, factor expire time)
    private $kfct, $kfet;
    private $pfct, $pfet;
    private $ifct, $ifet;
    // High security timeout
    private $hst;

    private $loader;

    private $required_level;

    private $required_factors = [];
    private $nvbt; // not valid before time

    private $time;

    private $user;

    public function __construct() {
        // Store the instanciation time so that "for the rest of this request"
        // stuff can work as expected on requests that take >1s
        $this->time = new DateTime();

        // Assume by default that we want a normally logged-in user
        $this->setRequiredLevel(Level::LOGIN());
    } // __construct

    // -( Accessors )----------------------------------------------------------

    /**
     * @return Firehed\JWT\JWT
     */
    public function getToken() {
        return new JWT($this->getDataForJWT());
    } // getToken

    public function getUser()/*: ?Authable */ {
        if ($this->required_level->is(Level::ANONYMOUS)) {
            return;
        }
        $this->loadUser();
        if (!$this->user) {
            throw new AE\UserNotFoundException();
        }
        if ($this->required_level->is(Level::PARTIAL)) {
            return null;
        }
        $this->assertFactorTimestamps()
            ->assertHighSecurity();
        return $this->user;
    } // getUser

    // -( Setters )------------------------------------------------------------

    public function setLoader(callable $loader)/*: this*/ {
        // loader signature: function(string $uid): Authable
        $this->loader = $loader;
        return $this;
    } // setLoader

    public function setRequiredLevel(Level $level)/*: this*/ {
        $this->required_level = $level;
        return $this;
    } // setRequiredLevel

    public function setToken(JWT $jwt)/*: this*/ {
        $claims = $jwt->getClaims();
        $this->uid = $claims['uid'];
        // Override any previously-set user to re-perform validation
        $this->user = null;
        // Restore timestamps
        $dt = function($idx) use ($claims) {
            return isset($claims[$idx]) ? new DateTime($claims[$idx]) : null;
        };
        $this->ifct = $dt('ifct');
        $this->ifet = $dt('ifet');
        $this->kfct = $dt('kfct');
        $this->kfet = $dt('kfet');
        $this->pfct = $dt('pfct');
        $this->pfet = $dt('pfet');
        $this->hst = $dt('hst');
        return $this;
    } // setToken

    public function setUser(Authable $user)/*: this*/ {
        $this->user = $user;
        $this->required_factors = $user->getRequiredAuthenticationFactors();
        $this->nvbt = $user->getAuthFactorNotValidBeforeTime();
        $this->uid = $user->getID();
        $this->expireAllFactors();
        return $this;
    } // setUser

    // -( High-security mode )-------------------------------------------------

    public function enterHighSecurity(Factor $factor)/*: this*/ {
        $this->validateFactor($factor);
        // ensure that a null time still works for the rest of the request,
        // enabling password change and similar stuff
        $this->hst = $factor->getExpiration() ? : clone $this->time;
        return $this;
    } // enterHighSecurity

    public function exitHighSecurity() {
        $this->hst = null;
    } // exitHighSecurity

    // -( Authentication )-----------------------------------------------------

    public function validateFactor(Factor $factor)/*: this*/ {
        $success = false;
        $ct = clone $this->time;
        $et = $factor->getExpiration();
        $this->loadUser();
        if (!$this->user) {
            throw new BadMethodCallException(
                'Trying to validate a factor with no user to validate aagainst. '.
                'Provide a user with setUser() or setToken() first');
        }

        switch ($factor->getType()->getValue()) {
        case FactorType::INHERENCE:
            $success = $this->user
                ->validateInherenceFactor($factor->getSecret());
            break;
        case FactorType::KNOWLEDGE:
            $success = $this->user
                ->validateKnowledgeFactor($factor->getSecret());
            break;
        case FactorType::POSSESSION:
            $success = $this->user
                ->validatePossessionFactor($factor->getSecret());
            break;
        }
        if (!$success) {
            throw new Exceptions\AuthenticationFailedException();
        }
        switch ($factor->getType()->getValue()) {
        case FactorType::INHERENCE:
            $this->ifct = $ct;
            $this->ifet = $et;
            break;
        case FactorType::KNOWLEDGE:
            $this->kfct = $ct;
            $this->kfet = $et;
            break;
        case FactorType::POSSESSION:
            $this->pfct = $ct;
            $this->pfet = $et;
            break;
        }
        return $this;
    } // validateFactor


    public function isMissingUser() {
        $this->loadUser();
        return $this->user === null;
    }

    public function isMissingKnowledgeFactor() {
        return $this->isMissingFactor(FactorType::KNOWLEDGE(),
            $this->kfct,
            $this->kfet);
    }
    public function isMissingPossessionFactor() {
        return $this->isMissingFactor(FactorType::POSSESSION(),
            $this->pfct,
            $this->pfet);
    }
    public function isMissingInherenceFactor() {
        return $this->isMissingFactor(FactorType::INHERENCE(),
            $this->ifct,
            $this->ifet);
    }

    private function isMissingFactor(
        FactorType $type,
        DateTime $create = null,
        DateTime $expire = null
    ) {
        return $this->validateType($type, $create, $expire) !== self::RET_OK;
    }
    // -( Logout )-------------------------------------------------------------

    public function expireFactor(FactorType $factor)/*: this*/ {
        switch ($factor->getValue()) {
        case FactorType::INHERENCE:
            $this->ifct = null;
            $this->ifet = null;
            break;
        case FactorType::KNOWLEDGE:
            $this->kfct = null;
            $this->kfet = null;
            break;
        case FactorType::POSSESSION:
            $this->pfct = null;
            $this->pfet = null;
            break;
        }
        return $this;
    } // expireFactor

    public function expireAllFactors() {
        $this->ifct = null;
        $this->ifet = null;
        $this->kfct = null;
        $this->kfet = null;
        $this->pfct = null;
        $this->pfet = null;
        $this->hst = null;
        return $this;
    }

    public function destroy() {
        $this->user = null;
        $this->uid = '';
        $this->expireAllFactors();
        return $this;
    }

    // -( Internals )----------------------------------------------------------

    // -( Internals:Accessors )------------------------------------------------

    private function getDataForJWT()/*: array*/ {
        $fmt = function(DateTime $dt = null) {
            return $dt ? $dt->format(DateTime::ISO8601) : null;
        };
        return [
            'uid' => $this->uid,
            'ifct' => $fmt($this->ifct),
            'ifet' => $fmt($this->ifet),
            'kfct' => $fmt($this->kfct),
            'kfet' => $fmt($this->kfet),
            'pfct' => $fmt($this->pfct),
            'pfet' => $fmt($this->pfet),
            'hst' =>  $fmt($this->hst),
        ];
    } // getDataForJWT

    // -( Internals:Validation )-----------------------------------------------

    private function assertFactorTimestamps()/*: this*/ {
        $data = [
            [FactorType::KNOWLEDGE(),  $this->kfct, $this->kfet],
            [FactorType::POSSESSION(), $this->pfct, $this->pfet],
            [FactorType::INHERENCE(),  $this->ifct, $this->ifet],
        ];
        foreach ($data as $types) {
            list($type, $create, $exp) = $types;
            $validation = $this->validateType($type, $create, $exp);
            switch ($validation) {
            case self::RET_OK:
                break;
            case self::RET_UNAUTH:
                throw new AE\AuthenticationRequiredException([]);
            case self::RET_EXP:
                throw new AE\FactorExpiredException([]);
            }
        }
        return $this;
    } // assertFactorTimestamps

    private function assertHighSecurity() {
        if ($this->required_level->is(Level::HISEC)) {
            if (!$this->hst || $this->hst < $this->time) {
                throw new AE\HighSecurityAuthenticationRequiredException([]);
            }
        }
        return $this;
    }

    private function validateType(
        FactorType $type,
        DateTime $create = null,
        DateTime $expire = null
    ) {
        $this->loadUser();
        if ($this->required_level->is(Level::ANONYMOUS)) {
            return self::RET_OK;
        }
        if (!in_array($type, $this->required_factors)) {
            return self::RET_OK;
        }
        if ($create === null) {
            return self::RET_UNAUTH;
        }
        if ($this->nvbt && $create < $this->nvbt) {
            return self::RET_EXP;
        }
        if ($expire === null) {
            // Does not expire
            return self::RET_OK;
        }
        if ($expire > $this->time) {
            // Expires in future
            return self::RET_OK;
        }
        return self::RET_EXP;
    }


    // -( Internals:Misc )-----------------------------------------------------

    private function loadUser() {
        if ($this->required_level->is(Level::ANONYMOUS)) {
            return;
        }
        if (!$this->user) {
            if (!$this->uid) {
                return null;
            }
            if (!$this->loader) {
                throw new BadMethodCallException(
                    'Provide a loader before calling getUser');
            }
            $this->user = ($this->loader)($this->uid);
            $this->required_factors = $this->user->getRequiredAuthenticationFactors();
            $this->nvbt = $this->user->getAuthFactorNotValidBeforeTime();
        }
        return $this->user;
    } // loadUser

}
