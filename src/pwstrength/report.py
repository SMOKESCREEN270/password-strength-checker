"""Human-readable terminal rendering of an :class:`Assessment`."""

from __future__ import annotations

from .scoring import Assessment, Strength

_COLORS = {
    Strength.WEAK: "31",
    Strength.MODERATE: "33",
    Strength.STRONG: "32",
    Strength.EXCEPTIONAL: "36",
}
BAR_WIDTH = 20


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def render_text(
    a: Assessment, *, color: bool = False, unicode: bool = True, index: int | None = None
) -> str:
    """Render a multi-line report. The password itself is never printed."""
    full, empty, ok, bad, rule_ch, dot = (
        ("█", "░", "✓", "✗", "─", "•") if unicode else ("#", "-", "+", "x", "-", "*")
    )
    code = _COLORS[a.strength]
    filled = round(a.score / 100 * BAR_WIDTH)
    bar = full * filled + empty * (BAR_WIDTH - filled)
    title = "Password Strength Report" + (f" #{index}" if index is not None else "")

    lines = [
        _paint(title, "1", color),
        rule_ch * len(title),
        f"Password   : {'*' * min(a.length, 32)} ({a.length} characters)",
        "Strength   : " + _paint(f"{a.strength.label.upper()}  [{bar}] {a.score}/100", code, color),
        f"Entropy    : {a.effective_bits:.1f} bits effective "
        f"({a.naive_bits:.1f} bits if purely random, pool of {a.pool_size})",
        f"Crack time : {a.crack_time} (offline attack, {int(1e10):,} guesses/s)",
    ]
    if a.breach_count is not None:
        found = f"found {a.breach_count:,} times" if a.breach_count else "not found"
        lines.append(f"Breaches   : {found} (Have I Been Pwned)")
    elif a.known_compromised:
        lines.append("Dictionary : matches a known common password")

    failed = sum(not r.passed for r in a.rules)
    verdict = _paint(f"FAILED ({failed})", "31", color) if failed else _paint("PASSED", "32", color)
    lines.append(f"Policy     : {verdict}")
    for rule in a.rules:
        mark = _paint(ok, "32", color) if rule.passed else _paint(bad, "31", color)
        lines.append(f"  {mark} {rule.requirement}")

    if a.matches:
        kinds = ", ".join(sorted({m.kind for m in a.matches}))
        lines.append(f"Patterns   : {kinds}")
    for warning in a.warnings:
        lines.append(_paint(f"Warning    : {warning}", "33", color))

    lines.append("Suggestions:")
    lines.extend(f"  {dot} {tip}" for tip in a.feedback)
    return "\n".join(lines)
