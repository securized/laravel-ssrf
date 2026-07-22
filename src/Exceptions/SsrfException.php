<?php

declare(strict_types=1);

namespace Securized\Ssrf\Exceptions;

use RuntimeException;

/**
 * Base exception for all SSRF validation failures.
 *
 * Catching this catches all subclasses, making it easy to handle
 * any SSRF validation failure with a single catch block:
 *
 *   try {
 *       ssrf_safe_url($url);
 *   } catch (SsrfException $e) {
 *       // URL is not safe
 *   }
 */
class SsrfException extends RuntimeException {}
