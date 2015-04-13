<?php

use Firehed\Auth\Auth;
use Firehed\Auth\Factors\KnowledgeFactor;
use Firehed\Auth\Factors\PossessionFactor;

include 'head.php';

if ($_POST) {
    $kf = new KnowledgeFactor(seal($_POST['password']));
    $pf = new PossessionFactor(seal($_POST['otp']));
    // If the remember box was checked, don't expire this factor for ten years.
    // It's not truly indefinitely, but the user will certainly end up clearing
    // their cookies well before then.
    if ($_POST['remember']) {
        $exp = (new DateTime())->add(new DateInterval('P10Y'));
        $kf->setExpiration($exp);
        $exp = (new DateTime())->add(new DateInterval('P30D'));
        $pf->setExpiration($exp);
    }
    // implicit: else { lasts for session only }

    // this would be a real function in your codebase somewhere
    $user_to_authenticate = User::getByEmailAddress($_POST['email']);

    $auth = new Auth();
    $token = $auth->setUser($user_to_authenticate)
        ->validateFactor($kf)
        ->validateFactor($pf)
        ->getToken();
    sendToken($token);
    // Login complete, redirect to logged-in home. If either factor is
    // incorrect,
    header('Location: /home');
}
else {
    // render form
?>
<form method="post">
    <label>Email:
        <input type="email" name="email"></label><br>
    <label>Password:
        <input type="password" name="password"></label><br>
    <label>Generated code:
        <input type="text" name="otp" placeholder="00000000"></label><br>
    <label>Remember me?
        <input type="checkbox" name="remember" value="1"></label><br>
    <input type="submit">
</form>
<?php
}
