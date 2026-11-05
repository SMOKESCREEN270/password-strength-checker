"""Common-password dictionary with rank lookup and leetspeak normalisation."""

from __future__ import annotations

import functools
from collections.abc import Iterable
from importlib import resources
from pathlib import Path

_LEET_BASE = {
    "@": "a", "4": "a", "3": "e", "0": "o", "$": "s",
    "5": "s", "7": "t", "+": "t", "!": "i", "8": "b",
}  # fmt: skip
_TABLE_I = str.maketrans({**_LEET_BASE, "1": "i"})
_TABLE_L = str.maketrans({**_LEET_BASE, "1": "l"})
LEET_CHARS = frozenset("@430$57+!81")
_COMMENT_PREFIX = "##"


def deleet_variants(text: str) -> list[tuple[str, int]]:
    """Return ``(plain_text, substitution_count)`` for each leetspeak reading of ``text``."""
    if LEET_CHARS.isdisjoint(text):
        return []
    out: list[tuple[str, int]] = []
    for table in (_TABLE_I, _TABLE_L):
        plain = text.translate(table)
        if plain != text and all(plain != seen for seen, _ in out):
            out.append((plain, sum(a != b for a, b in zip(text, plain, strict=True))))
    return out


class WordList:
    """Ordered collection of known-weak passwords/words; rank 1 = most common."""

    __slots__ = ("_ranks", "max_length")

    def __init__(self, words: Iterable[str]) -> None:
        ranks: dict[str, int] = {}
        for word in words:
            key = word.rstrip("\r\n").lower()
            if key:
                ranks.setdefault(key, len(ranks) + 1)
        self._ranks = ranks
        self.max_length = max(map(len, ranks), default=0)

    @classmethod
    def from_file(cls, path: str | Path) -> WordList:
        """Load one entry per line; lines starting with ``##`` are comments."""
        with open(path, encoding="utf-8", errors="replace") as fh:
            return cls(line for line in fh if not line.startswith(_COMMENT_PREFIX))

    def __len__(self) -> int:
        return len(self._ranks)

    def __contains__(self, word: object) -> bool:
        return isinstance(word, str) and word.lower() in self._ranks

    def rank(self, word: str) -> int | None:
        """Exact (case-insensitive) rank of ``word`` or ``None``."""
        return self._ranks.get(word.lower())

    def lookup(self, password: str) -> int | None:
        """Rank of the whole password, also trying leetspeak-normalised readings."""
        low = password.lower()
        found = self._ranks.get(low)
        if found is not None:
            return found
        for plain, _ in deleet_variants(low):
            found = self._ranks.get(plain)
            if found is not None:
                return found
        return None


@functools.cache
def default_wordlist() -> WordList:
    """Bundled list of very common passwords and words (loaded once)."""
    text = resources.files("pwstrength").joinpath("data/common_passwords.txt").read_text("utf-8")
    return WordList(line for line in text.splitlines() if not line.startswith(_COMMENT_PREFIX))
