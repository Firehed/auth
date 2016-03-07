<?php

namespace Firehed\Auth;

use Firehed\Common\Enum;

class Level extends Enum {

    const ANONYMOUS = 0;
    const PARTIAL = 1;
    const LOGIN = 2;
    const HISEC = 3;

}
