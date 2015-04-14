<?php

use Firehed\JWT;
use Firehed\Common\OpaqueEnvelope;

// Common error handling code. Normally this stuff would be handled very early
// in your framework's stack; this illustrates the type of things you'll need
// to handle

set_error_handler(function($a, $b, $c, $d) {
    // Don't promote errors when the code used @shutup
    if (!error_reporting()) {
        return;
    }
    throw new ErrorException($b, 0, $a, $c, $d);
}, -1);

set_exception_handler(function(Exception $e) {
    if ($e instanceof Firehed\Auth\Exceptions\AuthException) {
        handleAuthException($e);
    }
    if ($e instanceof JWT\JWTException) {
        handleJWTException($e);
    }
    // Log, 404, whatever.
});

function handleAuthException($e) {
    // hisec required exception: redirect to login_hisec.php
    //
    // factor expired exception: redirect to login.php
    //
    // auth required exception: examine $e->getMissingFactors() and send to an
    // appropriate login page
    //
    // auth failed exception: display an "invalid username or password" type
    // message and show the form again.
}

function handleJWTException($e) {
    // this is probably a tampering attempt, but it may be some sort of generic
    // expiration or formatting issue. if it's invalid, perform normal handling
    // (delete the cookie, abort the request, etc). expirations can be
    // refreshed, etc.
}

function getJWT() {
    // This is a poor example; your application secret and encoded string
    // should be function parameters.
    $your_application_secret = 'XXXXXXXX';
    $jwt = JWT\JWT::decode($_COOKIE['auth'], JWT\Algorithm::HMAC_SHA_256(),
        $your_application_secret);
    // Alternately, do the validation as a two-step process based on data
    // contained within
    return $jwt;
}
function sendAuthToken(JWT\JWT $jwt) {
    $your_application_secret = 'XXXXXXXX';
    $token_string = $jwt->setAlgorithm(JWT\Algorithm::HMAC_SHA_256())
        ->encode($your_application_secret);
    setcookie('auth',
        $token_string,
        time()+(60*60*24*365*50), // 50 years
        '/',
        'yourdomain.com',
        isset($_SERVER['HTTPS']), // If your site doesn't support https, you are
                                  // probably vulnerable to session fixation!
        true); // HTTPONLY
}

function seal($secret) {
    return new OpaqueEnvelope($secret);
}

function loadUserById($id) {
    return User::loadById($id);
}
