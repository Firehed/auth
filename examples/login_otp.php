<?php

use Firehed\Auth\Auth;
use Firehed\Auth\Factors\PossessionFactor;

include 'head.php';

if ($_POST) {
    $pf = new PossessionFactor(seal($_POST['otp']));
    if ($_POST['remember']) {
        $exp = (new DateTime())->add(new DateInterval('P30D'));
        $pf->setExpiration($exp);
    }
    // implicit: else { lasts for the session only }


}
else {
    // render form
?>
<form method="post">
    <label>Generated code:
        <input type="text" name="otp" placeholder="00000000"></label><br>
    <label>Remember for 30 days?
        <input type="checkbox" name="remember" value="1"></label><br>
    <input type="submit">
</form>
<?php
}
