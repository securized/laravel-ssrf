<?php

declare(strict_types=1);

namespace Securized\Ssrf\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

/**
 * Laravel validation rule that checks a URL for SSRF safety.
 *
 * Usage in a controller or FormRequest:
 *
 *   $request->validate([
 *       'webhook_url' => ['required', 'url', new SsrfSafeUrl()],
 *   ]);
 *
 * Usage with custom options (e.g. enforce DNS pinning for this field):
 *
 *   $request->validate([
 *       'webhook_url' => [
 *           'required', 'url',
 *           new SsrfSafeUrl(SsrfOptions::fromConfig(config('ssrf'))->withPinDns()),
 *       ],
 *   ]);
 *
 * The validation failure message intentionally does not reveal internal
 * network details (resolved IPs, CIDR ranges) to end users.
 */
class SsrfSafeUrl implements ValidationRule
{
    public function __construct(
        private readonly ?SsrfOptions $options = null,
    ) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value)) {
            $fail('The :attribute must be a string URL.');

            return;
        }

        $validator = $this->options
            ? new SsrfValidator($this->options)
            : app(SsrfValidator::class);

        try {
            $validator->validate($value);
        } catch (SsrfException) {
            $fail('The :attribute contains a URL that is not permitted.');
        }
    }
}
