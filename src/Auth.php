<?php

namespace Firehed\Auth;

use DateTime;
use Firehed\Auth\Factors\Factor;
use Firehed\Auth\Factors\FactorType;
use Firehed\Auth\Exceptions as AE;
use Firehed\JWT\JWT;
use BadMethodCallException;

class Auth {

    // userid
    private $uid;
    // Factor timestamps (factor create time, factor expire time)
    private $kfct, $kfet;
    private $pfct, $pfet;
    private $ifct, $ifet;
    // High security timeout
    private $hst;

    private $loader;

    private $required_level;

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

    public function getUser()/*: Authable */ {
        if ($this->required_level->is(Level::ANONYMOUS)) {
            return;
        }
        $this->loadUser();
        $this->enforceValidations();
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
        $this->uid = $user->getID();
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

        switch ($factor->getType()->getValue()) {
        case FactorType::INHERENCE:
            $success = $this->user
                ->validateInherenceFactor($factor->getSecret());
            $this->ifct = $ct;
            $this->ifet = $et;
            break;
        case FactorType::KNOWLEDGE:
            $success = $this->user
                ->validateKnowledgeFactor($factor->getSecret());
            $this->kfct = $ct;
            $this->kfet = $et;
            break;
        case FactorType::POSSESSION:
            $success = $this->user
                ->validatePossessionFactor($factor->getSecret());
            $this->pfct = $ct;
            $this->pfet = $et;
            break;
        }
        if ($success) {
            return $this;
        }
        else {
            throw new Exceptions\AuthenticationFailedException();
        }
    } // validateFactor

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

    private function getUID()/*: string*/ {
        return $this->uid;
    }

    // -( Internals:Validation )-----------------------------------------------

    private function enforceValidations()/*: void*/ {
        $this->validateFactorTimes()
            ->validateAuthLevel();
    } // enforceValidations

    private function validateFactorTimes()/*: this*/ {
        $not_valid_before_timestamp =
            $this->loadUser()->getAuthFactorNotValidBeforeTime();
        $required_factors =
            $this->loadUser()->getRequiredAuthenticationFactors();
        $factor_timestamps = [];
        foreach ($required_factors as $factor) {
            switch ($factor->getValue()) {
            case FactorType::INHERENCE:
                $factor_timestamps[] = [$this->ifct, $this->ifet];
                break;
            case FactorType::KNOWLEDGE:
                $factor_timestamps[] = [$this->kfct, $this->kfet];
                break;
            case FactorType::POSSESSION:
                $factor_timestamps[] = [$this->pfct, $this->pfet];
                break;
            }
        }
        // Convert $required_factors into the timestamp values
        // Throw an an AuthenticationRequiredException if the create time is
        // absent
        foreach ($factor_timestamps as $factor_timestamp) {
            list($create, $expire) = $factor_timestamp;
            if (null === $create) {
                throw new AE\AuthenticationRequiredException([]);
            }
            // Fail if it was created before the minimum
            if ($not_valid_before_timestamp
                && $create < $not_valid_before_timestamp) {
                throw new AE\FactorExpiredException([]);
            }
            if (null === $expire) {
                continue;
            }
            // Fail if we are after the expiration time
            if (new DateTime() > $expire) {
                throw new AE\FactorExpiredException([]);
            }
        }
        return $this;
    } // validateFactorTimes

    private function validateAuthLevel()/*: this*/ {
        switch ($this->required_level->getValue()) {
        case Level::ANONYMOUS:
            //
            break;
        case Level::LOGIN:
            break;
        case Level::HISEC:
            if (!$this->hst || $this->hst < $this->time) {
                throw new AE\HighSecurityAuthenticationRequiredException([]);
            }
        }
        return $this;
    } // validateAuthLevel

    // -( Internals:Misc )-----------------------------------------------------

    private function loadUser() {
        if (!$this->user) {
            if (!$this->loader) {
                throw new BadMethodCallException(
                    'Provide a loader before calling getUser');
            }
            $this->user = (call_user_func($this->loader, $this->getUID()));
        }
        return $this->user;
    } // loadUser

}
