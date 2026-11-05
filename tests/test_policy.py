import unittest

from pwstrength import Policy


class PolicyTests(unittest.TestCase):
    def test_compliant_password_passes_all_rules(self):
        results = Policy().evaluate("Abcdefgh1234!")
        self.assertTrue(all(r.passed for r in results))

    def test_each_missing_class_is_reported(self):
        failed = {r.rule for r in Policy().evaluate("abcdefghijklm") if not r.passed}
        self.assertEqual(failed, {"uppercase", "digit", "special"})

    def test_length_rules_are_fatal(self):
        by_rule = {r.rule: r for r in Policy(min_length=8).evaluate("Ab1!")}
        self.assertFalse(by_rule["min_length"].passed)
        self.assertTrue(by_rule["min_length"].fatal)

    def test_max_length(self):
        by_rule = {r.rule: r for r in Policy(min_length=1, max_length=4).evaluate("abcde")}
        self.assertFalse(by_rule["max_length"].passed)

    def test_disabled_rules_are_skipped(self):
        rules = {r.rule for r in Policy(require_special=False, require_digit=False).evaluate("x")}
        self.assertNotIn("special", rules)
        self.assertNotIn("digit", rules)

    def test_space_is_not_special_but_underscore_is(self):
        p = Policy(
            min_length=1, require_lowercase=False, require_uppercase=False, require_digit=False
        )
        self.assertFalse(next(r for r in p.evaluate("a b") if r.rule == "special").passed)
        self.assertTrue(next(r for r in p.evaluate("a_b") if r.rule == "special").passed)

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            Policy(min_length=0)
        with self.assertRaises(ValueError):
            Policy(min_length=10, max_length=5)


if __name__ == "__main__":
    unittest.main()
