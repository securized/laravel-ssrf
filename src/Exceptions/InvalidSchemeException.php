<?php

declare(strict_types=1);

namespace Securized\Ssrf\Exceptions;

/**
 * Thrown when the URL scheme is not permitted (e.g. file://, gopher://).
 */
class InvalidSchemeException extends InvalidUrlException {}
