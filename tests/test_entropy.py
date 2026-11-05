import math
import unittest

from pwstrength import WordList, default_wordlist, estimate_entropy, naive_entropy, pool_size
from pwstrength.entropy import (
    KIND_DICTIONARY,
    KIND_KEYBOARD,
    KIND_REPEAT,
    KIND_SEQUENCE,
    KIND_YEAR,
)

EMPTY = WordList([])


def kinds(pw, wl=EMPTY, extra=None):
    return {m.kind for m in estimate_entropy(pw, wl, extra).matches}


class PoolTests(unittest.TestCase):
    def test_pool_sizes(self):
        self.assertEqual(pool_size(""), 0)
        self.assertEqual(pool_size("abc"), 26)
        self.assertEqual(pool_size("aB"), 52)
        self.assertEqual(pool_size("aB1"), 62)
        self.assertEqual(pool_size("aB1!"), 95)
        self.assertEqual(pool_size("é"), 100)

    def test_naive_entropy(self):
        self.assertAlmostEqual(naive_entropy("abcd"), 4 * math.log2(26))
        self.assertEqual(naive_entropy(""), 0.0)


class EstimateTests(unittest.TestCase):
    def test_empty(self):
        est = estimate_entropy("", EMPTY)
        self.assertEqual((est.length, est.effective_bits), (0, 0.0))

    def test_random_looking_equals_naive(self):
        est = estimate_entropy("Xk9#mQ2$vL7!pR4z", default_wordlist())
        self.assertEqual(est.matches, ())
        self.assertAlmostEqual(est.effective_bits, est.naive_bits)

    def test_effective_never_exceeds_naive(self):
        for pw in ("aaaaaaaa", "abcdefgh", "qwertyuiop", "Password1!", "x" * 500):
            est = estimate_entropy(pw, default_wordlist())
            self.assertLessEqual(est.effective_bits, est.naive_bits + 1e-9)

    def test_sequence(self):
        self.assertIn(KIND_SEQUENCE, kinds("abcdefgh"))
        self.assertIn(KIND_SEQUENCE, kinds("9876543"))

    def test_keyboard_walk(self):
        self.assertIn(KIND_KEYBOARD, kinds("qwertyuiop"))
        self.assertIn(KIND_KEYBOARD, kinds("poiuytrewq"))

    def test_repeats(self):
        self.assertIn(KIND_REPEAT, kinds("aaaaaaaa"))
        self.assertIn(KIND_REPEAT, kinds("abababab"))
        self.assertLess(
            estimate_entropy("aaaaaaaa", EMPTY).effective_bits,
            estimate_entropy("aaaaaaaa", EMPTY).naive_bits / 2,
        )

    def test_year(self):
        self.assertIn(KIND_YEAR, kinds("Zq1990"))
        self.assertNotIn(KIND_YEAR, kinds("Zq3190"))

    def test_dictionary_with_case_and_leet(self):
        wl = WordList(["password", "dragon"])
        self.assertIn(KIND_DICTIONARY, kinds("password", wl))
        self.assertIn(KIND_DICTIONARY, kinds("PaSsWoRd", wl))
        leet = estimate_entropy("p@ssw0rd", wl)
        plain = estimate_entropy("password", wl)
        self.assertIn(KIND_DICTIONARY, {m.kind for m in leet.matches})
        self.assertGreater(leet.effective_bits, plain.effective_bits)
        self.assertLess(leet.effective_bits, leet.naive_bits)

    def test_higher_rank_costs_more(self):
        wl = WordList(["alpha", "bravo", "charlie", "delta"])
        self.assertLess(
            estimate_entropy("alpha", wl).effective_bits,
            estimate_entropy("delta", wl).effective_bits,
        )

    def test_extra_context_words(self):
        pw = "johnsmith!Q9"
        without = estimate_entropy(pw, EMPTY).effective_bits
        with_ctx = estimate_entropy(pw, EMPTY, {"johnsmith": 1}).effective_bits
        self.assertLess(with_ctx, without - 10)

    def test_match_positions_are_valid(self):
        pw = "xxdragon1234yy"
        est = estimate_entropy(pw, WordList(["dragon"]))
        for m in est.matches:
            self.assertTrue(0 <= m.start < m.end <= len(pw))

    def test_linear_time_on_pathological_input(self):
        import time

        start = time.perf_counter()
        estimate_entropy("a" * 1024, default_wordlist())
        estimate_entropy("ab" * 512, default_wordlist())
        self.assertLess(time.perf_counter() - start, 2.0)

    def test_length_changing_lowercase_is_safe(self):
        estimate_entropy("İstanbul1!", default_wordlist())


if __name__ == "__main__":
    unittest.main()
