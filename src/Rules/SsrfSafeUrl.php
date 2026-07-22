<?php

declare(strict_types=1);

namespace Securized\Ssrf\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

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
            // Deliberately generic: the exception message names resolved IPs and
            // CIDR ranges, which must not reach an end user.
            $fail('The :attribute contains a URL that is not permitted.');
        }
    }
}
