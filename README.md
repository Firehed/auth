# Auth

Auth is a library designed to take the complexity out of multi-factor and
high-security authentication in PHP projects. Data is stored in
[JWTs](http://jwt.io) which are tamper-resistant, permitting authentication
information to be stored completely client-side without the need for
a database[^db].

By implementing a single interface, your existing PHP app can flexibly support
MFA without being tied to a specific provider or implementation. Thanks to
being based on open standards, the authentication data can be used with any
framework, and even ported to other programming languages.

## A simple example
```
<?php
use Firehed\Auth;
use Firehed\JWT;

$auth = new Auth\Auth();
$user = $auth->setRequiredLevel(Auth\Level::LOGIN())
  ->setLoader(function($uid) { return (new User())->find($uid); })
  ->setToken(JWT\JWT::decode($_COOKIE['auth'],
                             JWT\Algorithm::HMAC_SHA_256(),
                             'jwt_signing_key'))
  ->getUser();
```

## Installation

Installation is supported through Composer:

    composer require firehed/auth

For more information, please visit [the Composer
website](https://getcomposer.org/doc/00-intro.md#installation-linux-unix-osx)

## API

### setToken(Firehed\JWT\JWT $token): $this
Restore an authentication session from a decoded JWT. This method will be
mostly used on logged-in pages.

### setUser(Firehed\Auth\Authable $user): $this
Start an authentication session for a new user. This method will be mostly used
during the start of a login flow.

### setLoader(callable $loader): $this
Provide a callback that will return a Firehed\Auth\Authable object provided
a unique identifier. This will be used alongside `setToken` to allow `getUser`
to function on restored sessions.

### setRequiredLevel(Firehed\Auth\Level $level): $this
Provide the authentication level required for `getUser` to return a user. This
defaults to `Level::LOGIN`.

### getToken
Get a JWT containing the authentication data for the current user. This does
not contain sensitive data, and is tamper-resistant thanks to signing. You
SHOULD store the encoded token client-side, so long as transmission is done
securely (this applies to any session identifier).

### getUser
Get the authenticated user. If the user is insufficiently authenticated, this
will throw an exception, preventing accidental access.

### enterHighSecurity(Firehed\Auth\Factors\Factor $factor): $this
Use the provided factor to start a high-security session. It will last until
the expiration time on the factor. If no expiration time is set, it will only
last until the end of the request.

### exitHighSecurity(): void
Exit high-security mode regardless of the time remaining.

### validateFactor(Firehed\Auth\Factors\Factor $factor): $this
Authenticate the user with the provided factor.

### expireFactor(Firehed\Auth\Factors\FactorType $type): $this
Remove the authentication data provided by the specified factor type. Most
commonly, this will be used to log the user out.



## Core concepts

* Authentication: the act of verifying identity
* Factor: a method of authentication. There are three different factors:
  * Inherence: something a user *is*, such as a fingerprint
  * Knowledge: something a user *knows*, such as a passphrase
  * Possession: something a user *has*, such as a OTP token
* High-security mode: conceptually similar to `sudo`, this is a way to protect
  especially-sensitive actions (password change, credit card management, etc.)
  by requiring a fresh authentication.
* Levels: there are three authentication levels that a page can require:
  * `ANONYMOUS`: Users are not authenticated at all, nor will one be returned
    by `getUser`
  * `LOGIN`: Users require all of their factors to be present
  * `HISEC`: In addition to all factors being present, one must have been
    explicitly re-verified via the `enterHighSecurity` API

## Examples

Included are examples of various scenarios. Note that in all `POST` handling,
necessary tasks such as CSRF protection are not covered.

### Checking Validity
* ~ `home_anon.php`: Example page not requiring any authenticated user~
* ~ `home_user.php`: Example page requiring a normally-authenticated user~
* ~ `change_pass.php`: Example high-security page~

### Login and logout pages
* `login.php`: How to use a typical username/password login
* `login_otp.php`: How to add a second factor (e.g. TOTP a.k.a. Google
  Authenticator)
* `login_combined.php`: Put the two factors on the same page (this would only
  be practical if MFA is required for all users)
* `logout.php`: How to log out a user
* ~`logout_all.php`: ~
* ~`forget.php`: In an environment supporting MFA, forget the saved trust in the
  device (require re-confirming the device in the next session) ~

[^db]: Of course, you will still need to securely store password hashes, OTP
shared secrets, etc. What you will not need to do is muck around with existing
session storage and handling.
