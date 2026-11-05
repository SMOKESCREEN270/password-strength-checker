import io
import json
import os
import tempfile
import unittest
from unittest import mock

from pwstrength import cli


class FakeTTY(io.StringIO):
    def isatty(self):
        return True


def run(*argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), stdin=io.StringIO(stdin), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_strong_password_exit_zero(self):
        code, out, err = run("--stdin", "--no-color", stdin="Xk9#mQ2$vL7!pR4z\n")
        self.assertEqual(code, 0)
        self.assertIn("EXCEPTIONAL", out)
        self.assertNotIn("Xk9#", out)
        self.assertEqual(err, "")

    def test_weak_password_exit_one(self):
        code, out, _ = run("--stdin", stdin="password\n")
        self.assertEqual(code, 1)
        self.assertIn("WEAK", out)

    def test_min_level_threshold(self):
        code, _, _ = run(
            "--stdin",
            "--min-level",
            "exceptional",
            "--no-special",
            "--no-digit",
            "--no-uppercase",
            stdin="xkqmvlprtzwhjbnc\n",
        )
        self.assertEqual(code, 1)

    def test_json_single_and_batch(self):
        code, out, _ = run("--json", "--stdin", stdin="Xk9#mQ2$vL7!pR4z\n")
        data = json.loads(out)
        self.assertEqual((code, data["strength"]), (0, "Exceptional"))
        _, out, _ = run("--json", "--stdin", stdin="a\nb\n\nc\n")
        self.assertEqual(len(json.loads(out)), 3)

    def test_batch_text_numbering(self):
        _, out, _ = run("--stdin", stdin="a\nb\n")
        self.assertIn("#1", out)
        self.assertIn("#2", out)

    def test_password_flag_warns(self):
        code, _, err = run("-p", "Xk9#mQ2$vL7!pR4z")
        self.assertEqual(code, 0)
        self.assertIn("warning", err)

    def test_no_input_is_usage_error(self):
        code, _, err = run("--stdin", stdin="\n\n")
        self.assertEqual(code, 2)
        self.assertIn("no password", err)

    def test_invalid_policy_and_missing_wordlist(self):
        self.assertEqual(run("-p", "x", "--min-length", "0")[0], 2)
        self.assertEqual(run("-p", "x", "--wordlist", "/nonexistent/file")[0], 2)

    def test_custom_wordlist(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("Xk9#mQ2$vL7!pR4z\n")
            path = fh.name
        try:
            code, out, _ = run("--stdin", "--wordlist", path, stdin="Xk9#mQ2$vL7!pR4z\n")
        finally:
            os.unlink(path)
        self.assertEqual(code, 1)
        self.assertIn("WEAK", out)

    def test_context_option(self):
        pw = "Johnathan#8142Zq\n"
        _, with_ctx, _ = run("--json", "--stdin", "--context", "Johnathan", stdin=pw)
        _, without, _ = run("--json", "--stdin", stdin=pw)
        self.assertLess(
            json.loads(with_ctx)["entropy_bits"]["effective"],
            json.loads(without)["entropy_bits"]["effective"],
        )

    def test_too_long_password(self):
        code, _, err = run("--stdin", stdin="a" * 2000 + "\n")
        self.assertEqual(code, 2)
        self.assertIn("exceeds", err)

    def test_hibp_flag_uses_checker(self):
        with mock.patch.object(cli, "hibp_pwned_count", side_effect=lambda p: 5):
            code, out, _ = run("--stdin", "--hibp", stdin="Xk9#mQ2$vL7!pR4z\n")
        self.assertEqual(code, 1)
        self.assertIn("5 times", out)

    def test_hidden_prompt_used_on_tty(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli.getpass, "getpass", return_value="Xk9#mQ2$vL7!pR4z") as gp:
            code = cli.main([], stdin=FakeTTY(), stdout=out, stderr=err)
        gp.assert_called_once()
        self.assertEqual(code, 0)

    def test_keyboard_interrupt(self):
        with mock.patch.object(cli.getpass, "getpass", side_effect=KeyboardInterrupt):
            code = cli.main([], stdin=FakeTTY(), stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(code, 130)

    def test_version_help_and_bad_args(self):
        self.assertEqual(run("--version")[0], 0)
        self.assertEqual(run("--help")[0], 0)
        self.assertEqual(run("--bogus")[0], 2)

    def test_ascii_fallback_rendering(self):
        class AsciiOut(io.StringIO):
            encoding = "ascii"

        out = AsciiOut()
        cli.main(["--stdin"], stdin=io.StringIO("x\n"), stdout=out, stderr=io.StringIO())
        out.getvalue().encode("ascii")  # must not raise


if __name__ == "__main__":
    unittest.main()
