<?php
use Firehed\Auth;
include 'head.php';
$a = new Auth\Auth();
$user = $a->setToken(getJWT())
    ->setLoader('loadUserById')
    ->setRequiredLevel(Auth\Level::LOGIN())
    ->getUser();

// If an exception was not thrown, all is well
