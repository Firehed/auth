<?php

use Firehed\Auth\Auth;
use Firehed\Auth\Factors\FactorType as Type;

include 'head.php';

$auth = new Auth();
$token = $auth->setToken(getJWT())
    ->expireFactor(Type::KNOWLEDGE())
    ->getToken();

sendToken($token);
header('Location: /');

