<?php

use Firehed\Auth\Auth;
use Firehed\Auth\Factors\KnowledgeFactor;

include 'head.php';

if ($_POST) {
    $kf = new KnowledgeFactor(seal($_POST['password']));
    // If the remember box was checked, don't expire this factor for ten years.
    // It's not truly indefinitely, but the user will certainly end up clearing
    // their cookies well before then.
    if ($_POST['remember']) {
        $exp = (new DateTime())->add(new DateInterval('P10Y'));
        $kf->setExpiration($exp);
    }
    // implicit: else { lasts for session only }

    // this would be a real function in your codebase somewhere
    $user_to_authenticate = User::getByEmailAddress($_POST['email']);

    $auth = new Auth();
    $token = $auth->setUser($user_to_authenticate)
        ->validateFactor($kf)
        ->getToken();
    sendToken($token);
    // Login complete, redirect to logged-in home. If MFA is required, that
    // page will trigger redirection into the MFA prompt screen. You could
    // optimize this by checking for any missing factors and redirecting to
    // either home or the appropriate MFA prompt page. For simplicity, that's
    // excluded here.
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
    <label>Remember me?
        <input type="checkbox" name="remember" value="1"></label><br>
    <input type="submit">
</form>
<?php
}
