"""Actionable feedback generation (step 4)."""

from __future__ import annotations

import math

from .entropy import (
    KIND_DICTIONARY,
    KIND_KEYBOARD,
    KIND_REPEAT,
    KIND_SEQUENCE,
    KIND_YEAR,
    EntropyEstimate,
)
from .policy import RuleResult

_PATTERN_ADVICE = {
    KIND_DICTIONARY: (
        "Avoid common words, names and predictable substitutions (like '@' for 'a'); "
        "attackers try these first."
    ),
    KIND_SEQUENCE: "Avoid sequences such as 'abcd' or '4321'.",
    KIND_KEYBOARD: "Avoid keyboard patterns such as 'qwerty' or '1qaz2wsx'.",
    KIND_REPEAT: "Avoid repeated characters or blocks such as 'aaaa' or 'abab'.",
    KIND_YEAR: "Avoid years and dates; they are among the first guesses.",
}


def build_feedback(
    *,
    estimate: EntropyEstimate,
    rules: tuple[RuleResult, ...],
    known_compromised: bool,
    breach_count: int | None,
    next_target_bits: float | None,
    is_top_level: bool,
) -> tuple[str, ...]:
    """Return an ordered list of concrete suggestions (most important first)."""
    tips: list[str] = []

    if breach_count:
        tips.append(
            f"This password was found {breach_count:,} times in known data breaches. "
            "Never use it again, anywhere."
        )
    elif known_compromised:
        tips.append(
            "This is a very common password (or a trivial variation of one). "
            "Choose something completely different."
        )

    tips.extend(rule.hint for rule in rules if not rule.passed)

    seen_kinds = {m.kind for m in estimate.matches}
    for kind, advice in _PATTERN_ADVICE.items():
        if kind in seen_kinds:
            tips.append(advice)

    if (
        next_target_bits is not None
        and estimate.length
        and next_target_bits > estimate.effective_bits
    ):
        per_char = math.log2(max(estimate.pool_size, 26))
        missing = next_target_bits - estimate.effective_bits
        extra_chars = max(math.ceil(missing / per_char), 1)
        tips.append(
            f"Adding about {extra_chars} more random character(s) would reach the next level."
        )

    if not is_top_level:
        tips.append(
            "Best approach: a passphrase of 4-5 unrelated random words, or a 16+ character "
            "password produced by a password manager."
        )
    elif not tips:
        tips.append(
            "Excellent password. Keep it unique per account and enable multi-factor authentication."
        )

    return tuple(dict.fromkeys(tips))  # de-duplicate, keep order
