import unittest


from scanner import version_matcher


class TestVersionMatcher(unittest.TestCase):
    # Unit tests for version matching functionality

    def test_parse_version_range_simple(self):
        # Testing that ">=7.0,<8.9" gets split into two separate conditions
        result = version_matcher.parse_version_range(">=7.0,<8.9")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ('>=', '7.0'))
        self.assertEqual(result[1], ('<', '8.9'))

    def test_parse_version_range_single(self):
        # Testing parsing of a range that contains only one condition
        result = version_matcher.parse_version_range(">=2.4.0")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], ('>=', '2.4.0'))

    def test_compare_versions_greater_than(self):
        #Testing greater-than-or-equal comparison between versions
        self.assertTrue(version_matcher.compare_versions("8.5", ">=", "7.0"))
        self.assertFalse(version_matcher.compare_versions("6.5", ">=", "7.0"))

    def test_compare_versions_less_than(self):
        # Testing less-than comparison
        self.assertTrue(version_matcher.compare_versions("7.5", "<", "8.0"))
        self.assertFalse(version_matcher.compare_versions("9.0", "<", "8.0"))

    def test_match_version_in_range(self):
        # Test matching version within range
        self.assertTrue(version_matcher.match_version("7.5", ">=7.0,<8.9"))
        self.assertTrue(version_matcher.match_version("8.0", ">=7.0,<8.9"))

    def test_match_version_outside_range(self):
        # Test matching version outside range
        self.assertFalse(version_matcher.match_version("6.9", ">=7.0,<8.9"))
        self.assertFalse(version_matcher.match_version("9.0", ">=7.0,<8.9"))

    def test_match_version_unknown(self):
        # Test matching with unknown version
        self.assertFalse(version_matcher.match_version("unknown", ">=7.0,<8.9"))

    def test_extract_version_from_banner(self):
        # Test extracting version from service banner
        version = version_matcher.extract_version_from_banner("OpenSSH_7.4", "ssh")
        self.assertEqual(version, "7.4")

        version = version_matcher.extract_version_from_banner("Apache/2.4.6", "http")
        self.assertEqual(version, "2.4.6")

        version = version_matcher.extract_version_from_banner("nginx/1.14.0", "http")
        self.assertEqual(version, "1.14.0")


if __name__ == '__main__':
    unittest.main()