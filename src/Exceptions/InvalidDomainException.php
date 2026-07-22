<?php

declare(strict_types=1);

namespace Securized\Ssrf\Exceptions;

/**
 * Thrown when the URL hostname is not permitted, is blacklisted,
 * or does not resolve to any IP address.
 */
class InvalidDomainException extends InvalidUrlException {}
