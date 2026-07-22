<?php

declare(strict_types=1);

namespace Securized\Ssrf\Exceptions;

use RuntimeException;

/** Base of the hierarchy: catching this catches every validation failure. */
class SsrfException extends RuntimeException {}
