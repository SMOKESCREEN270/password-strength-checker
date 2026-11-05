"""Optional online breach check using the Have I Been Pwned range API.

Uses the k-anonymity model: only the first 5 hex characters of the SHA-1 hash leave
the machine; the password and full hash are never transmitted.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from collections.abc import Callable

_API = "https://api.pwnedpasswords.com/range/"
_USER_AGENT = "pwstrength/1.0 (+k-anonymity range query)"


class BreachCheckError(RuntimeError):
    """Raised when the breach service cannot be reached or returns bad data."""


def _fetch_range(prefix: str, timeout: float) -> str:
    request = urllib.request.Request(
        _API + prefix, headers={"User-Agent": _USER_AGENT, "Add-Padding": "true"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return str(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError) as exc:
        raise BreachCheckError(f"breach lookup failed: {exc}") from exc


def hibp_pwned_count(
    password: str,
    *,
    timeout: float = 5.0,
    fetch: Callable[[str], str] | None = None,
) -> int:
    """Return how many times ``password`` appears in known breaches (0 if never seen).

    ``fetch`` receives the 5-char prefix and returns the raw API body (injectable for tests).
    """
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    body = fetch(prefix) if fetch else _fetch_range(prefix, timeout)
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip().upper() == suffix:
            try:
                return max(int(count.strip()), 0)
            except ValueError as exc:
                raise BreachCheckError("malformed response from breach service") from exc
    return 0
