"""Password policy definition and evaluation (step 1: policy criteria)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuleResult:
    """Outcome of a single policy rule."""

    rule: str
    passed: bool
    requirement: str
    hint: str
    fatal: bool = False  # fatal failures (length) cap the strength at "Weak"


@dataclass(frozen=True, slots=True)
class Policy:
    """Configurable password policy.

    Defaults follow common enterprise guidance: 12+ characters and all four
    character classes. Every class rule can be disabled (e.g. for passphrases).
    """

    min_length: int = 12
    max_length: int = 128
    require_lowercase: bool = True
    require_uppercase: bool = True
    require_digit: bool = True
    require_special: bool = True

    def __post_init__(self) -> None:
        if self.min_length < 1:
            raise ValueError("min_length must be >= 1")
        if self.max_length < self.min_length:
            raise ValueError("max_length must be >= min_length")

    def evaluate(self, password: str) -> tuple[RuleResult, ...]:
        """Check ``password`` against every enabled rule (single pass over the string)."""
        has_lower = has_upper = has_digit = has_special = False
        for ch in password:
            if ch.islower():
                has_lower = True
            elif ch.isupper():
                has_upper = True
            elif ch.isdecimal():
                has_digit = True
            elif not ch.isalnum() and not ch.isspace():
                has_special = True

        n = len(password)
        results = [
            RuleResult(
                "min_length",
                n >= self.min_length,
                f"At least {self.min_length} characters",
                f"Make it at least {self.min_length} characters long (currently {n}).",
                fatal=True,
            ),
            RuleResult(
                "max_length",
                n <= self.max_length,
                f"At most {self.max_length} characters",
                f"Shorten it to at most {self.max_length} characters (currently {n}).",
                fatal=True,
            ),
        ]
        optional = (
            (self.require_lowercase, "lowercase", has_lower, "a lowercase letter (a-z)"),
            (self.require_uppercase, "uppercase", has_upper, "an uppercase letter (A-Z)"),
            (self.require_digit, "digit", has_digit, "a digit (0-9)"),
            (self.require_special, "special", has_special, "a special character (e.g. !@#$%)"),
        )
        for enabled, name, ok, what in optional:
            if enabled:
                results.append(RuleResult(name, ok, f"Contains {what}", f"Add {what}."))
        return tuple(results)
