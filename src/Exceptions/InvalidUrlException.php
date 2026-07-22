<?php

declare(strict_types=1);

namespace Securized\Ssrf\Exceptions;

/**
 * Thrown when a URL cannot be parsed, is empty, or contains
 * credentials when credentials are disabled.
 */
class InvalidUrlException extends SsrfException {}
