"""pwstrength - password strength evaluation via entropy, policy and dictionary checks."""

from __future__ import annotations

from .breach import BreachCheckError, hibp_pwned_count
from .dictionary import WordList, default_wordlist
from .entropy import EntropyEstimate, PatternMatch, estimate_entropy, naive_entropy, pool_size
from .policy import Policy, RuleResult
from .scoring import Assessment, PasswordAnalyzer, Strength

__version__ = "1.0.1"

__all__ = [
    "Assessment",
    "BreachCheckError",
    "EntropyEstimate",
    "PasswordAnalyzer",
    "PatternMatch",
    "Policy",
    "RuleResult",
    "Strength",
    "WordList",
    "__version__",
    "default_wordlist",
    "estimate_entropy",
    "hibp_pwned_count",
    "naive_entropy",
    "pool_size",
]
