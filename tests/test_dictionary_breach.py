import hashlib
import os
import tempfile
import unittest
from unittest import mock

from pwstrength import BreachCheckError, WordList, default_wordlist, hibp_pwned_count
from pwstrength import breach as breach_mod


class WordListTests(unittest.TestCase):
    def test_ranks_and_case_insensitivity(self):
        wl = WordList(["Alpha", "beta", "alpha", ""])
        self.assertEqual(len(wl), 2)
        self.assertEqual(wl.rank("ALPHA"), 1)
        self.assertEqual(wl.rank("beta"), 2)
        self.assertIsNone(wl.rank("gamma"))
        self.assertIn("BETA", wl)
        self.assertNotIn(5, wl)

    def test_lookup_handles_leetspeak(self):
        wl = WordList(["password", "illegal"])
        self.assertEqual(wl.lookup("P@ssw0rd"), 1)
        self.assertEqual(wl.lookup("1llegal"), 2)  # '1' read as 'i' or 'l'
        self.assertIsNone(wl.lookup("zzzzzz"))

    def test_from_file_skips_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
            fh.write("## comment\nfirst\r\nsecond\n")
            path = fh.name
        try:
            wl = WordList.from_file(path)
        finally:
            os.unlink(path)
        self.assertEqual((len(wl), wl.rank("second")), (2, 2))

    def test_default_wordlist_is_cached_and_populated(self):
        wl = default_wordlist()
        self.assertIs(wl, default_wordlist())
        self.assertEqual(wl.rank("123456"), 1)
        self.assertGreater(len(wl), 300)


class BreachTests(unittest.TestCase):
    @staticmethod
    def _fake(password, count):
        digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
        seen = []

        def fetch(prefix):
            seen.append(prefix)
            return f"0000000000000000000000000000000000A:3\r\n{digest[5:]}:{count}\r\n"

        return fetch, seen, digest

    def test_found_and_only_prefix_is_sent(self):
        fetch, seen, digest = self._fake("hunter2", 17_000)
        self.assertEqual(hibp_pwned_count("hunter2", fetch=fetch), 17_000)
        self.assertEqual(seen, [digest[:5]])

    def test_not_found_and_padding_entries(self):
        self.assertEqual(hibp_pwned_count("x", fetch=lambda p: "ABCDEF:2\n"), 0)
        fetch, _, _ = self._fake("padded", 0)
        self.assertEqual(hibp_pwned_count("padded", fetch=fetch), 0)

    def test_malformed_count(self):
        digest = hashlib.sha1(b"a", usedforsecurity=False).hexdigest().upper()
        with self.assertRaises(BreachCheckError):
            hibp_pwned_count("a", fetch=lambda p: f"{digest[5:]}:abc")

    def test_network_failure_is_wrapped(self):
        import urllib.error

        with (
            mock.patch.object(
                breach_mod.urllib.request, "urlopen", side_effect=urllib.error.URLError("down")
            ),
            self.assertRaises(BreachCheckError),
        ):
            hibp_pwned_count("x")

    def test_successful_network_path(self):
        resp = mock.MagicMock()
        resp.__enter__.return_value.read.return_value = b"ABCDE:1\n"
        with mock.patch.object(breach_mod.urllib.request, "urlopen", return_value=resp):
            self.assertEqual(hibp_pwned_count("x"), 0)


if __name__ == "__main__":
    unittest.main()
