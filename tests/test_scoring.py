import unittest

from pwstrength import BreachCheckError, PasswordAnalyzer, Policy, Strength
from pwstrength.scoring import MAX_ANALYSIS_LENGTH, estimate_crack_seconds, format_duration


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = PasswordAnalyzer()

    def test_common_password_is_weak_and_instant(self):
        a = self.analyzer.analyze("password")
        self.assertIs(a.strength, Strength.WEAK)
        self.assertTrue(a.known_compromised)
        self.assertEqual(a.crack_time, "instantly")

    def test_leet_variant_is_still_compromised(self):
        self.assertTrue(self.analyzer.analyze("P@ssw0rd").known_compromised)

    def test_trivial_mutation_is_weak(self):
        self.assertIs(self.analyzer.analyze("Password1!").strength, Strength.WEAK)

    def test_short_random_password_capped_weak_by_length(self):
        a = self.analyzer.analyze("Xk9#mQ2$")
        self.assertIs(a.strength, Strength.WEAK)
        self.assertFalse(a.policy_passed)

    def test_policy_failure_caps_at_moderate(self):
        a = self.analyzer.analyze("xkqmvlprtzwhjbnc")  # strong entropy, no upper/digit/special
        self.assertGreaterEqual(a.effective_bits, 60)
        self.assertIs(a.strength, Strength.MODERATE)

    def test_strong_and_exceptional(self):
        self.assertIs(self.analyzer.analyze("Xk9#mQ2$vL7!pR4z").strength, Strength.EXCEPTIONAL)
        mid = self.analyzer.analyze("Xk9#mQ2$vL7!")
        self.assertIn(mid.strength, (Strength.STRONG, Strength.MODERATE))

    def test_thresholds(self):
        self.assertEqual(
            [Strength.from_score(s) for s in (0, 39, 40, 59, 60, 79, 80, 100)],
            [
                Strength.WEAK,
                Strength.WEAK,
                Strength.MODERATE,
                Strength.MODERATE,
                Strength.STRONG,
                Strength.STRONG,
                Strength.EXCEPTIONAL,
                Strength.EXCEPTIONAL,
            ],
        )

    def test_passphrase_policy_without_classes(self):
        pol = Policy(
            min_length=16, require_uppercase=False, require_digit=False, require_special=False
        )
        a = PasswordAnalyzer(pol).analyze("vqzjxkhwpmbtgfdnrslc")
        self.assertTrue(a.policy_passed)
        self.assertGreaterEqual(a.strength, Strength.STRONG)

    def test_context_words_lower_score(self):
        pw = "Johnathan#8142Zq"
        base = self.analyzer.analyze(pw)
        ctx = self.analyzer.analyze(pw, context=["johnathan@example.com"])
        self.assertLess(ctx.effective_bits, base.effective_bits)

    def test_empty_password(self):
        a = self.analyzer.analyze("")
        self.assertEqual((a.score, a.strength), (0, Strength.WEAK))
        self.assertTrue(a.feedback)

    def test_too_long_is_rejected(self):
        with self.assertRaises(ValueError):
            self.analyzer.analyze("a" * (MAX_ANALYSIS_LENGTH + 1))


class BreachIntegrationTests(unittest.TestCase):
    def test_breach_hit_forces_weak(self):
        a = PasswordAnalyzer(breach_checker=lambda p: 42).analyze("Xk9#mQ2$vL7!pR4z")
        self.assertIs(a.strength, Strength.WEAK)
        self.assertEqual(a.breach_count, 42)
        self.assertIn("42", a.feedback[0])

    def test_breach_clean(self):
        a = PasswordAnalyzer(breach_checker=lambda p: 0).analyze("Xk9#mQ2$vL7!pR4z")
        self.assertEqual(a.breach_count, 0)
        self.assertIs(a.strength, Strength.EXCEPTIONAL)

    def test_breach_failure_degrades_gracefully(self):
        def boom(_):
            raise BreachCheckError("offline")

        a = PasswordAnalyzer(breach_checker=boom).analyze("Xk9#mQ2$vL7!pR4z")
        self.assertIsNone(a.breach_count)
        self.assertEqual(a.warnings, ("offline",))


class HelpersTests(unittest.TestCase):
    def test_format_duration(self):
        self.assertEqual(format_duration(0.1), "instantly")
        self.assertEqual(format_duration(1), "1 second")
        self.assertEqual(format_duration(90), "2 minutes")
        self.assertEqual(format_duration(86_400 * 3), "3 days")
        self.assertEqual(format_duration(31_557_600 * 50), "50 years")
        self.assertEqual(format_duration(31_557_600 * 5e3), "thousands of years")
        self.assertEqual(format_duration(31_557_600 * 5e6), "millions of years")
        self.assertEqual(format_duration(31_557_600 * 5e10), "over a billion years")

    def test_crack_seconds_monotonic_and_bounded(self):
        self.assertLess(estimate_crack_seconds(30), estimate_crack_seconds(60))
        self.assertTrue(estimate_crack_seconds(1e9) < float("inf"))

    def test_parse_strength(self):
        self.assertIs(Strength.parse("Strong"), Strength.STRONG)
        with self.assertRaises(ValueError):
            Strength.parse("meh")

    def test_to_dict_never_contains_password(self):
        pw = "Xk9#mQ2$vL7!pR4z"
        a = PasswordAnalyzer().analyze(pw)
        import json

        self.assertNotIn(pw, json.dumps(a.to_dict()))


if __name__ == "__main__":
    unittest.main()
