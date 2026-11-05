"""Strength classification (step 3) and the high-level analyzer."""

from __future__ import annotations

import enum
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .breach import BreachCheckError
from .dictionary import WordList, default_wordlist
from .entropy import EntropyEstimate, PatternMatch, estimate_entropy
from .feedback import build_feedback
from .policy import Policy, RuleResult

MAX_ANALYSIS_LENGTH = 1024
GUESSES_PER_SECOND = 1e10  # offline attack on a fast hash with a GPU cluster
THRESHOLDS = (40, 60, 80)  # score boundaries: Moderate, Strong, Exceptional
_WEAK_CAP, _MODERATE_CAP = THRESHOLDS[0] - 1, THRESHOLDS[1] - 1
_CONTEXT_SPLIT = re.compile(r"[^0-9a-z]+")


class Strength(enum.IntEnum):
    WEAK = 0
    MODERATE = 1
    STRONG = 2
    EXCEPTIONAL = 3

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_score(cls, score: int) -> Strength:
        level = sum(score >= t for t in THRESHOLDS)
        return cls(level)

    @classmethod
    def parse(cls, text: str) -> Strength:
        try:
            return cls[text.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown strength level: {text!r}") from None


def estimate_crack_seconds(bits: float) -> float:
    """Average time to guess a secret of ``bits`` entropy at ``GUESSES_PER_SECOND``."""
    return float(2.0 ** min(bits, 1000.0)) / 2.0 / GUESSES_PER_SECOND


_UNITS = (
    ("year", 31_557_600), ("month", 2_629_800), ("day", 86_400),
    ("hour", 3_600), ("minute", 60), ("second", 1),
)  # fmt: skip


def format_duration(seconds: float) -> str:
    """Human-friendly duration, e.g. ``"3 days"`` or ``"millions of years"``."""
    year = _UNITS[0][1]
    if seconds < 1:
        return "instantly"
    if seconds >= year * 1e9:
        return "over a billion years"
    if seconds >= year * 1e6:
        return "millions of years"
    if seconds >= year * 1e3:
        return "thousands of years"
    for name, size in _UNITS:
        if seconds >= size:
            value = round(seconds / size)
            return f"{value} {name}{'' if value == 1 else 's'}"
    return "instantly"  # pragma: no cover


@dataclass(frozen=True, slots=True)
class Assessment:
    """Immutable result of analysing one password (never stores the password)."""

    length: int
    pool_size: int
    naive_bits: float
    effective_bits: float
    score: int
    strength: Strength
    rules: tuple[RuleResult, ...]
    known_compromised: bool
    breach_count: int | None
    matches: tuple[PatternMatch, ...]
    crack_time_seconds: float
    crack_time: str
    feedback: tuple[str, ...]
    warnings: tuple[str, ...] = field(default=())

    @property
    def policy_passed(self) -> bool:
        return all(r.passed for r in self.rules)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "length": self.length,
            "strength": self.strength.label,
            "score": self.score,
            "entropy_bits": {
                "naive": round(self.naive_bits, 2),
                "effective": round(self.effective_bits, 2),
            },
            "character_pool": self.pool_size,
            "estimated_crack_time": self.crack_time,
            "policy": {
                "passed": self.policy_passed,
                "rules": [
                    {"rule": r.rule, "passed": r.passed, "requirement": r.requirement}
                    for r in self.rules
                ],
            },
            "known_compromised": self.known_compromised,
            "breach_count": self.breach_count,
            "patterns": [
                {"kind": m.kind, "start": m.start, "end": m.end, "bits": round(m.bits, 2)}
                for m in self.matches
            ],
            "feedback": list(self.feedback),
            "warnings": list(self.warnings),
        }


class PasswordAnalyzer:
    """Combine policy, entropy, dictionary and (optional) breach checks.

    Classification rules
    --------------------
    ``score = min(100, floor(effective_bits))`` mapped to Weak (<40), Moderate (<60),
    Strong (<80), Exceptional (>=80). The score is then capped:

    * known-compromised password or violated length rule -> at most Weak
    * any other violated policy rule -> at most Moderate
    """

    def __init__(
        self,
        policy: Policy | None = None,
        wordlist: WordList | None = None,
        breach_checker: Callable[[str], int] | None = None,
    ) -> None:
        self.policy = policy or Policy()
        self.wordlist = wordlist or default_wordlist()
        self.breach_checker = breach_checker

    @staticmethod
    def _context_words(context: Iterable[str]) -> dict[str, int]:
        words: dict[str, int] = {}
        for item in context:
            lowered = item.lower()
            for part in (lowered, *_CONTEXT_SPLIT.split(lowered)):
                if len(part) >= 3:
                    words.setdefault(part, 1)
        return words

    def analyze(self, password: str, context: Iterable[str] = ()) -> Assessment:
        """Analyse ``password``; ``context`` holds user-specific words (name, e-mail...)."""
        if len(password) > MAX_ANALYSIS_LENGTH:
            raise ValueError(f"password longer than {MAX_ANALYSIS_LENGTH} characters")

        rules = self.policy.evaluate(password)
        estimate: EntropyEstimate = estimate_entropy(
            password, self.wordlist, self._context_words(context)
        )

        compromised = bool(password) and self.wordlist.lookup(password) is not None
        breach_count: int | None = None
        warnings: list[str] = []
        if self.breach_checker and password:
            try:
                breach_count = self.breach_checker(password)
            except BreachCheckError as exc:
                warnings.append(str(exc))
            else:
                compromised = compromised or breach_count > 0

        score = min(100, int(estimate.effective_bits))
        if compromised or any(r.fatal and not r.passed for r in rules):
            score = min(score, _WEAK_CAP)
        elif not all(r.passed for r in rules):
            score = min(score, _MODERATE_CAP)
        strength = Strength.from_score(score)

        crack_seconds = 0.0 if compromised else estimate_crack_seconds(estimate.effective_bits)
        top = strength is Strength.EXCEPTIONAL
        feedback = build_feedback(
            estimate=estimate,
            rules=rules,
            known_compromised=compromised,
            breach_count=breach_count,
            next_target_bits=None if top else float(THRESHOLDS[strength]),
            is_top_level=top,
        )
        return Assessment(
            length=estimate.length,
            pool_size=estimate.pool_size,
            naive_bits=estimate.naive_bits,
            effective_bits=estimate.effective_bits,
            score=score,
            strength=strength,
            rules=rules,
            known_compromised=compromised,
            breach_count=breach_count,
            matches=estimate.matches,
            crack_time_seconds=crack_seconds,
            crack_time=format_duration(crack_seconds),
            feedback=feedback,
            warnings=tuple(warnings),
        )
