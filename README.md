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
```php
<?php
use Firehed\Auth;
use Firehed\JWT;
use Firehed\Security\Secret;

// General setup
$keys = new JWT\KeyContainer();
$keys->addKey('20130101',
    JWT\Algorithm::HMAC_SHA_256(),
    new Secret('some randomly-generated secret');

$auth = new Auth\Auth();
$auth->setKeys($keys)
    ->setLoader(function($uid): Auth\Authable {
        return (new User())->find($uid);
    });

// Authenticating a user
$user = User::findByEmail($_POST['email']);
$password = new Auth\Factors\KnowledgeFactor(new Secret($_POST['password'));
$auth->setUser($user);
try {
    $auth->validateFactor($password);
    setcookie('auth_token',
        $auth->getEncodedToken(),
        time()+(86400*90),
        '/',
        'yourdomain.com',
        true,
        true);
} catch (Auth\Exceptions\AuthException $e) {
    // password was incorrect
}

// Accessing a previously-authenticated user
try {
    $user = $auth->setEncodedToken($_COOKIE['auth_token'])
        ->setRequiredLevel(Auth\Level::LOGIN())
        ->getUser();
} catch (Auth\Exceptions\AuthException $e) {
    // Authentication failed, prompt for login
    header('Location: /login');
}
```

## Installation

Installation is supported through Composer:

    composer require firehed/auth

For more information, please visit [the Composer
website](https://getcomposer.org/doc/00-intro.md#installation-linux-unix-osx)

## API

### setEncodedToken(string $token): self
Restore an authentication session from an encoded JWT. This method will be
mostly used on logged-in pages.

### setUser(Firehed\Auth\Authable $user): self
Start an authentication session for a new user. This method will be mostly used
during the start of a login flow.

### setLoader(callable $loader): self
Provide a callback that will return a Firehed\Auth\Authable object provided
a unique identifier. This will be used alongside `setEncodedToken` to allow
`getUser` to function on restored sessions.

It must have the following signature:
```php
function($uid): Firehed\Auth\Authable
```

### setRequiredLevel(Firehed\Auth\Level $level): self
Provide the authentication level required for `getUser` to return a user. This
defaults to `Level::LOGIN`.

### getEncodedToken(): string
Get a JWT containing the authentication data for the current user. This does
not contain sensitive data, and is tamper-resistant thanks to signing. You
SHOULD store the encoded token client-side, so long as transmission is done
securely (this applies to any session identifier). Note that this does include
the user's own ID.

### getUser(): Firehed\Auth\Authable
Get the authenticated user. If the user is insufficiently authenticated, this
will throw an exception, preventing accidental access.

### enterHighSecurity(Firehed\Auth\Factors\Factor $factor): self
Use the provided factor to start a high-security session. It will last until
the expiration time on the factor. If no expiration time is set, it will only
last until the end of the request.

### exitHighSecurity(): void
Exit high-security mode regardless of the time remaining.

### validateFactor(Firehed\Auth\Factors\Factor $factor): self
Authenticate the user with the provided factor.

### expireFactor(Firehed\Auth\Factors\FactorType $type): self
Remove the authentication data provided by the specified factor type. Most
commonly, this will be used to log the user out.

### setKeys(Firehed\JWT\KeyContainer $keys): self
Provides a KeyContainer that's used internally for JWT handling. This allows
key rotation to be seamless and nearly-automatic

## Core concepts

* Authentication: the act of verifying identity
* Factor: a method of authentication. There are three different factors:
  * Inherence: something a user *is*, such as a fingerprint
  * Knowledge: something a user *knows*, such as a passphrase
  * Possession: something a user *has*, such as a OTP token
* High-security mode: conceptually similar to `sudo`, this is a way to protect
  especially-sensitive actions (password change, credit card management, etc.)
  by requiring a fresh authentication.
* Levels: there are four authentication levels that a page can require:
  * `ANONYMOUS`: Users are not authenticated at all, nor will one be returned
    by `getUser`
  * `PARTIAL`: Allows getUser() to return a user by ID regardless of how many
    authentication factors are present. This SHOULD NOT be used outside of an
    autentication upgrade flow; i.e. providing their OTP code or token.
  * `LOGIN`: Users require all of their factors to be present
  * `HISEC`: In addition to all factors being present, one must have been
    explicitly re-verified via the `enterHighSecurity` API

## Examples

(new examples coming soon)

[^db]: Of course, you will still need to securely store password hashes, OTP
shared secrets, etc. What you will not need to do is muck around with existing
session storage and handling.
