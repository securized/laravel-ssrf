<?php

declare(strict_types=1);

namespace Securized\Ssrf\Exceptions;

/**
 * Thrown when the resolved IP address(es) of the URL hostname
 * are not permitted or match a blacklisted range.
 */
class InvalidIpException extends InvalidUrlException {}
