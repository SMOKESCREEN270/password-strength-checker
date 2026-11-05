"""Entropy estimation (step 2).

Two figures are produced:

* **naive entropy** - ``length * log2(pool)``; what the password would be worth
  if every character were chosen uniformly at random from the character classes used.
* **effective entropy** - the cheapest way an attacker could generate the password
  using realistic strategies (dictionary words with case/leetspeak mutations,
  sequences, keyboard walks, repeats, years, otherwise brute force). It is found with
  a shortest-path dynamic programme over the string in O(n * W) where W is a small
  constant (max dictionary word length considered).
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from .dictionary import WordList, deleet_variants

MIN_WORD_LENGTH = 4  # shortest substring matched against the dictionary
MAX_WORD_WINDOW = 64  # longest dictionary substring considered
SEQUENCE_BASE_BITS = 5.0  # ~32 plausible starting characters
KEYBOARD_BASE_BITS = 6.5  # ~90 (row, offset, direction) starting points
YEAR_BITS = 7.0  # ~ 200 plausible years (1900-2099)

KIND_DICTIONARY = "dictionary"
KIND_SEQUENCE = "sequence"
KIND_KEYBOARD = "keyboard"
KIND_REPEAT = "repeat"
KIND_YEAR = "year"

_KEY_ROWS = (
    "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "!@#$%^&*()",
    "1qaz2wsx3edc4rfv", "qazwsxedcrfv", "1q2w3e4r5t6y7u8i9o0p",
    "qwertyuiopasdfghjklzxcvbnm",
)  # fmt: skip
_KEYBOARD = _KEY_ROWS + tuple(row[::-1] for row in _KEY_ROWS)


def pool_size(password: str) -> int:
    """Size of the character pool implied by the classes present in ``password``."""
    lower = upper = digit = symbol = other = False
    for ch in password:
        if "a" <= ch <= "z":
            lower = True
        elif "A" <= ch <= "Z":
            upper = True
        elif "0" <= ch <= "9":
            digit = True
        elif ch.isascii():
            symbol = True  # punctuation, space, control
        else:
            other = True
    return 26 * lower + 26 * upper + 10 * digit + 33 * symbol + 100 * other


def naive_entropy(password: str) -> float:
    """``len * log2(pool)`` in bits (0 for the empty string)."""
    pool = pool_size(password)
    return len(password) * math.log2(pool) if pool else 0.0


@dataclass(frozen=True, slots=True)
class PatternMatch:
    """A predictable substring found in the password."""

    kind: str
    start: int
    end: int  # exclusive
    bits: float


@dataclass(frozen=True, slots=True)
class EntropyEstimate:
    length: int
    pool_size: int
    naive_bits: float
    effective_bits: float
    matches: tuple[PatternMatch, ...]


# --------------------------------------------------------------------------- helpers
def _safe_lower(text: str) -> str:
    """``str.lower`` that never changes the string length (keeps indices aligned)."""
    return "".join(c.lower() if len(c.lower()) == 1 else c for c in text)


def _case_bits(fragment: str) -> float:
    letters = [c for c in fragment if c.isalpha()]
    if not letters or all(c.islower() for c in letters):
        return 0.0
    if all(c.isupper() for c in letters) or (
        letters[0].isupper() and all(c.islower() for c in letters[1:])
    ):
        return 1.0
    return 1.0 + math.log2(len(letters))


def _word_rank(
    fragment: str, wordlist: WordList, extra: Mapping[str, int]
) -> tuple[int, int] | None:
    """Return ``(rank, leet_substitutions)`` for a lower-cased fragment, or ``None``."""
    rank = extra.get(fragment) or wordlist.rank(fragment)
    if rank:
        return rank, 0
    for plain, subs in deleet_variants(fragment):
        rank = extra.get(plain) or wordlist.rank(plain)
        if rank:
            return rank, subs
    return None


def _dictionary_tokens(
    pw: str, low: str, i: int, wordlist: WordList, extra: Mapping[str, int], window: int
) -> Iterator[tuple[int, float, str]]:
    n = len(pw)
    for j in range(i + MIN_WORD_LENGTH, min(n, i + window) + 1):
        hit = _word_rank(low[i:j], wordlist, extra)
        if hit is None:
            continue
        rank, subs = hit
        bits = math.log2(rank + 1) + _case_bits(pw[i:j])
        if subs:
            bits += 1.0 + math.log2(1 + subs)
        yield j, bits, KIND_DICTIONARY


def _sequence_tokens(pw: str, i: int) -> Iterator[tuple[int, float, str]]:
    n = len(pw)
    if i + 2 >= n or not (pw[i].isascii() and pw[i].isalnum()):
        return
    step = ord(pw[i + 1]) - ord(pw[i])
    if step not in (1, -1):
        return
    j = i
    while (
        j + 1 < n
        and pw[j + 1].isascii()
        and pw[j + 1].isalnum()
        and ord(pw[j + 1]) - ord(pw[j]) == step
    ):
        j += 1
    length = j - i + 1
    if length >= 3:
        yield j + 1, SEQUENCE_BASE_BITS + math.log2(length), KIND_SEQUENCE


def _keyboard_tokens(low: str, i: int) -> Iterator[tuple[int, float, str]]:
    n = len(low)
    if i + 4 > n:
        return
    seed = low[i : i + 4]
    best = 0
    for row in _KEYBOARD:
        idx = row.find(seed)
        if idx < 0:
            continue
        length = 4
        while i + length < n and idx + length < len(row) and row[idx + length] == low[i + length]:
            length += 1
        best = max(best, length)
    if best:
        yield i + best, KEYBOARD_BASE_BITS + math.log2(best), KIND_KEYBOARD


def _repeat_tokens(pw: str, i: int, char_bits: float) -> Iterator[tuple[int, float, str]]:
    n = len(pw)
    for size in range(1, 5):
        if i + 2 * size > n:
            break
        block = pw[i : i + size]
        if i >= size and pw.startswith(block, i - size):
            continue  # inside a run that started earlier
        count, pos = 1, i + size
        while pw.startswith(block, pos):
            count += 1
            pos += size
        if count >= (3 if size == 1 else 2):
            yield pos, size * char_bits + math.log2(count), KIND_REPEAT


def _year_tokens(pw: str, i: int) -> Iterator[tuple[int, float, str]]:
    chunk = pw[i : i + 4]
    if len(chunk) == 4 and chunk.isascii() and chunk.isdigit() and chunk[:2] in ("19", "20"):
        yield i + 4, YEAR_BITS, KIND_YEAR


# --------------------------------------------------------------------------- public API
def estimate_entropy(
    password: str,
    wordlist: WordList,
    extra_words: Mapping[str, int] | None = None,
) -> EntropyEstimate:
    """Estimate how many bits of work an attacker needs to guess ``password``.

    ``extra_words`` maps lower-case context words (username, e-mail parts...) to a rank.
    """
    n = len(password)
    pool = pool_size(password)
    if n == 0:
        return EntropyEstimate(0, 0, 0.0, 0.0, ())

    extra = extra_words or {}
    char_bits = math.log2(pool)
    naive = n * char_bits
    low = _safe_lower(password)
    window = min(MAX_WORD_WINDOW, max(wordlist.max_length, max(map(len, extra), default=0)))

    best = [math.inf] * (n + 1)
    back: list[tuple[int, str, float] | None] = [None] * (n + 1)
    best[0] = 0.0

    for i in range(n):
        base = best[i]
        cost = base + char_bits
        if cost < best[i + 1]:
            best[i + 1], back[i + 1] = cost, (i, "brute", char_bits)
        for tokens in (
            _dictionary_tokens(password, low, i, wordlist, extra, window),
            _sequence_tokens(password, i),
            _keyboard_tokens(low, i),
            _repeat_tokens(password, i, char_bits),
            _year_tokens(password, i),
        ):
            for end, bits, kind in tokens:
                cost = base + bits
                if cost < best[end]:
                    best[end], back[end] = cost, (i, kind, bits)

    matches: list[PatternMatch] = []
    pos = n
    while pos > 0:
        step = back[pos]
        assert step is not None  # brute force always reaches every position
        start, kind, bits = step
        if kind != "brute":
            matches.append(PatternMatch(kind, start, pos, bits))
        pos = start
    matches.reverse()

    return EntropyEstimate(n, pool, naive, min(best[n], naive), tuple(matches))
