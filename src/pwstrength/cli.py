"""Command-line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Iterator, Sequence
from typing import TextIO

from . import __version__
from .breach import hibp_pwned_count
from .dictionary import WordList, default_wordlist
from .policy import Policy
from .report import render_text
from .scoring import MAX_ANALYSIS_LENGTH, PasswordAnalyzer, Strength

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwstrength",
        description="Evaluate password strength using entropy, policy rules and dictionary checks.",
        epilog=(
            "The password is read from a hidden prompt by default (or from stdin when piped). "
            "Exit status: 0 = meets --min-level and policy, 1 = does not, 2 = usage/input error."
        ),
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument(
        "-p", "--password",
        help="password to check (INSECURE: visible in shell history and process list)",
    )  # fmt: skip
    src.add_argument(
        "--stdin", action="store_true", help="read one password per line from standard input"
    )

    pol = parser.add_argument_group("policy")
    pol.add_argument("--min-length", type=int, default=12, metavar="N", help="default: 12")
    pol.add_argument("--max-length", type=int, default=128, metavar="N", help="default: 128")
    for name in ("lowercase", "uppercase", "digit", "special"):
        pol.add_argument(
            f"--{name}", action=argparse.BooleanOptionalAction, default=True,
            help=f"require {name} characters (default: required)",
        )  # fmt: skip

    chk = parser.add_argument_group("checks")
    chk.add_argument(
        "--wordlist", metavar="FILE", help="custom common-password list (one per line)"
    )
    chk.add_argument(
        "--context", nargs="+", default=[], metavar="WORD",
        help="personal words (name, e-mail...) that must not appear in the password",
    )  # fmt: skip
    chk.add_argument(
        "--hibp", action="store_true",
        help="also query Have I Been Pwned via k-anonymity (needs internet)",
    )  # fmt: skip

    out = parser.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="machine-readable JSON output")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    out.add_argument(
        "--min-level", default="moderate", choices=[s.name.lower() for s in Strength],
        help="minimum strength for a zero exit status (default: moderate)",
    )  # fmt: skip
    out.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _read_masked(prompt: str, stream: TextIO, stdin: TextIO) -> str:
    """Read a password from a real terminal, echoing ``*`` for each character typed.

    Falls back to the standard hidden ``getpass`` prompt when ``stdin`` is not a real
    terminal or raw key input is unavailable.
    """
    try:
        fileno = stdin.fileno()
    except (AttributeError, OSError, ValueError):
        return getpass.getpass(prompt, stream=stream)

    chars: list[str] = []

    def echo(text: str) -> None:
        stream.write(text)
        stream.flush()

    def handle(ch: str) -> bool:
        """Process one key press; return True when input is finished."""
        if ch in ("\r", "\n"):
            return True
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch == "\x04" and not chars:
            raise EOFError
        if ch in ("\x7f", "\b"):
            if chars:
                chars.pop()
                echo("\b \b")
        elif ch.isprintable():
            chars.append(ch)
            echo("*")
        return False

    if sys.platform == "win32":  # pragma: no cover - needs a real Windows console
        import msvcrt

        echo(prompt)
        while True:
            ch = msvcrt.getwch()
            if ch in ("\x00", "\xe0"):  # arrow/function key: swallow its second code
                msvcrt.getwch()
                continue
            if handle(ch):
                break
    else:
        try:
            import termios
            import tty
        except ImportError:  # pragma: no cover
            return getpass.getpass(prompt, stream=stream)
        try:
            saved = termios.tcgetattr(fileno)
        except termios.error:
            return getpass.getpass(prompt, stream=stream)
        echo(prompt)
        try:
            tty.setcbreak(fileno)
            while not handle(stdin.read(1)):
                pass
        finally:
            termios.tcsetattr(fileno, termios.TCSADRAIN, saved)
    echo("\n")
    return "".join(chars)


def _passwords(args: argparse.Namespace, stdin: TextIO, stderr: TextIO) -> Iterator[str]:
    if args.password is not None:
        print(
            "warning: --password exposes the secret in shell history and process lists; "
            "prefer the hidden prompt or --stdin.",
            file=stderr,
        )
        yield args.password
    elif args.stdin or not stdin.isatty():
        for line in stdin:
            password = line.rstrip("\r\n")
            if password:
                yield password
    else:
        yield _read_masked("Password: ", stderr, stdin)


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the CLI and return the process exit status (streams are injectable for tests)."""
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse exits on --help/--version/usage errors
        return int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE

    try:
        policy = Policy(
            min_length=args.min_length, max_length=args.max_length,
            require_lowercase=args.lowercase, require_uppercase=args.uppercase,
            require_digit=args.digit, require_special=args.special,
        )  # fmt: skip
        wordlist: WordList = (
            WordList.from_file(args.wordlist) if args.wordlist else default_wordlist()
        )
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=stderr)
        return EXIT_USAGE

    analyzer = PasswordAnalyzer(policy, wordlist, hibp_pwned_count if args.hibp else None)
    minimum = Strength.parse(args.min_level)
    use_color = (
        not args.no_color
        and "NO_COLOR" not in os.environ
        and not args.json
        and getattr(stdout, "isatty", lambda: False)()
    )
    use_unicode = (getattr(stdout, "encoding", None) or "ascii").lower().replace("-", "") == "utf8"

    results, status = [], EXIT_OK
    try:
        for password in _passwords(args, stdin, stderr):
            try:
                assessment = analyzer.analyze(password, args.context)
            except ValueError:
                print(f"error: password exceeds {MAX_ANALYSIS_LENGTH} characters", file=stderr)
                return EXIT_USAGE
            results.append(assessment)
            if assessment.strength < minimum or not assessment.policy_passed:
                status = EXIT_FAIL
    except (EOFError, KeyboardInterrupt):
        print("\naborted.", file=stderr)
        return 130

    if not results:
        print("error: no password supplied", file=stderr)
        return EXIT_USAGE

    if args.json:
        payload = [r.to_dict() for r in results]
        json.dump(payload[0] if len(payload) == 1 else payload, stdout, indent=2)
        stdout.write("\n")
    else:
        many = len(results) > 1
        blocks = (
            render_text(r, color=use_color, unicode=use_unicode, index=i if many else None)
            for i, r in enumerate(results, 1)
        )
        stdout.write("\n\n".join(blocks) + "\n")
    return status


def run() -> None:
    """Console-script entry point."""
    sys.exit(main())
