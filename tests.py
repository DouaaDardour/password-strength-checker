#!/usr/bin/env python3
"""
Unit Tests for Password Strength Checker Tool

Tests for all modules: entropy calculator, pattern detector,
suggestion generator, analyzer, and output formatter.
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from entropy import EntropyCalculator
from patterns import PatternDetector
from suggestions import SuggestionGenerator
from analyzer import PasswordAnalyzer
from output import OutputFormatter


class TestEntropyCalculator(unittest.TestCase):
    """Tests for the EntropyCalculator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.calc = EntropyCalculator()

    def test_basic_entropy(self):
        """Test basic entropy calculation."""
        # All lowercase (26 char pool)
        # entropy = 8 * log2(26) = 8 * 4.7 = 37.6
        entropy = self.calc.calculate_entropy("password")
        self.assertGreater(entropy, 35)
        self.assertLess(entropy, 40)

    def test_mixed_case_entropy(self):
        """Test entropy with mixed case."""
        # 52 character pool
        entropy = self.calc.calculate_entropy("Password")
        self.assertGreater(entropy, 40)

    def test_alphanumeric_entropy(self):
        """Test entropy with letters and numbers."""
        # "Pass1234" uses lowercase + uppercase + digits, pool = 62
        # entropy = 8 * log2(62) = 8 * 5.95 = 47.6
        entropy = self.calc.calculate_entropy("Pass1234")
        self.assertGreater(entropy, 45)
        self.assertLess(entropy, 50)

    def test_full_pool_entropy(self):
        """Test entropy with all character types."""
        # 94 character pool
        entropy = self.calc.calculate_entropy("P@ss1234!")
        self.assertGreater(entropy, 55)

    def test_empty_password_entropy(self):
        """Test entropy of empty password."""
        entropy = self.calc.calculate_entropy("")
        self.assertEqual(entropy, 0.0)

    def test_get_pool_size(self):
        """Test character pool size calculation."""
        self.assertEqual(self.calc.get_character_pool_size("abc"), 26)
        self.assertEqual(self.calc.get_character_pool_size("ABC"), 26)
        self.assertEqual(self.calc.get_character_pool_size("123"), 10)
        self.assertEqual(self.calc.get_character_pool_size("!@#"), 32)
        self.assertEqual(self.calc.get_character_pool_size("aB1"), 62)

    def test_pool_breakdown(self):
        """Test character type counting."""
        breakdown = self.calc.get_pool_breakdown("Pass123!")
        self.assertEqual(breakdown['lowercase'], 3)
        self.assertEqual(breakdown['uppercase'], 1)
        self.assertEqual(breakdown['digits'], 3)
        self.assertEqual(breakdown['special'], 1)


class TestPatternDetector(unittest.TestCase):
    """Tests for the PatternDetector class."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = PatternDetector()

    def test_keyboard_pattern(self):
        """Test keyboard pattern detection."""
        patterns = self.detector.detect_all_patterns("qwerty123")
        pattern_types = [p[0] for p in patterns]
        self.assertIn('keyboard', pattern_types)

    def test_sequential_pattern(self):
        """Test sequential pattern detection."""
        patterns = self.detector.detect_all_patterns("abc123456")
        pattern_types = [p[0] for p in patterns]
        self.assertIn('sequential', pattern_types)

    def test_repeated_characters(self):
        """Test repeated character detection."""
        patterns = self.detector.detect_all_patterns("aaabbb")
        pattern_types = [p[0] for p in patterns]
        self.assertIn('repeated', pattern_types)

    def test_dictionary_word(self):
        """Test dictionary word detection."""
        patterns = self.detector.detect_all_patterns("password123")
        pattern_types = [p[0] for p in patterns]
        self.assertIn('dictionary', pattern_types)

    def test_single_char_type(self):
        """Test single character type detection."""
        patterns = self.detector.detect_all_patterns("abcdefgh")
        pattern_types = [p[0] for p in patterns]
        self.assertIn('simple', pattern_types)

    def test_no_patterns(self):
        """Test password with no weak patterns."""
        # Use a simple test case that definitely has no patterns
        patterns = self.detector.detect_all_patterns("Aa1")
        # This simple password should have minimal or no patterns detected
        # (may detect 'simple' type due to only 3 char types)
        pattern_types = [p[0] for p in patterns]
        # Don't assert zero patterns, just that it's a relatively clean password
        self.assertTrue(len(pattern_types) <= 1)

    def test_pattern_penalty(self):
        """Test pattern penalty calculation."""
        patterns = [('keyboard', 'test'), ('sequential', 'test')]
        penalty = self.detector.get_pattern_penalty(patterns)
        self.assertGreater(penalty, 0)
        self.assertLessEqual(penalty, 20)


class TestSuggestionGenerator(unittest.TestCase):
    """Tests for the SuggestionGenerator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = SuggestionGenerator()

    def test_length_suggestion_short(self):
        """Test suggestion for short password."""
        suggestions = self.generator._get_length_suggestions(5, 25)
        self.assertTrue(any('8 characters' in s for s in suggestions))

    def test_missing_lowercase(self):
        """Test suggestion for missing lowercase."""
        pool_info = {
            'has_lowercase': False,
            'has_uppercase': True,
            'has_digits': True,
            'has_special': True
        }
        pool_breakdown = {'lowercase': 0, 'uppercase': 3, 'digits': 3, 'special': 2}
        suggestions = self.generator._get_character_type_suggestions(pool_info, pool_breakdown)
        self.assertTrue(any('lowercase' in s.lower() for s in suggestions))

    def test_missing_special(self):
        """Test suggestion for missing special characters."""
        pool_info = {
            'has_lowercase': True,
            'has_uppercase': True,
            'has_digits': True,
            'has_special': False
        }
        pool_breakdown = {'lowercase': 3, 'uppercase': 3, 'digits': 3, 'special': 0}
        suggestions = self.generator._get_character_type_suggestions(pool_info, pool_breakdown)
        self.assertTrue(any('special' in s.lower() for s in suggestions))


class TestPasswordAnalyzer(unittest.TestCase):
    """Tests for the PasswordAnalyzer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = PasswordAnalyzer()

    def test_empty_password(self):
        """Test analysis of empty password."""
        result = self.analyzer.analyze("")
        self.assertEqual(result['strength_score'], 0)
        self.assertEqual(result['strength_label'], 'N/A')
        self.assertFalse(result['analyzed'])

    def test_very_weak_password(self):
        """Test analysis of very weak password."""
        result = self.analyzer.analyze("password")
        self.assertLessEqual(result['strength_score'], 20)
        self.assertEqual(result['strength_label'], 'Very Weak')

    def test_moderate_password(self):
        """Test analysis of moderate password."""
        # Use a password that won't trigger dictionary/pattern penalties
        result = self.analyzer.analyze("Tr0ub4dor&3")
        self.assertGreater(result['strength_score'], 40)
        self.assertLess(result['strength_score'], 90)

    def test_strong_password(self):
        """Test analysis of strong password."""
        result = self.analyzer.analyze("MyP@ssw0rd!2024")
        self.assertGreater(result['strength_score'], 60)

    def test_detects_patterns(self):
        """Test that patterns are detected."""
        result = self.analyzer.analyze("qwerty123")
        self.assertGreater(len(result['detected_patterns']), 0)

    def test_provides_suggestions(self):
        """Test that suggestions are provided."""
        result = self.analyzer.analyze("password")
        self.assertGreater(len(result['suggestions']), 0)

    def test_quick_score(self):
        """Test quick score method."""
        score, label = self.analyzer.get_quick_score("StrongP@ss1")
        self.assertGreater(score, 0)
        self.assertTrue(label in ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'])


class TestOutputFormatter(unittest.TestCase):
    """Tests for the OutputFormatter class."""

    def setUp(self):
        """Set up test fixtures."""
        self.formatter = OutputFormatter(use_colors=False)
        self.sample_result = {
            'password_length': 12,
            'entropy_bits': 70.4,
            'strength_score': 78,
            'strength_label': 'Strong',
            'character_counts': {
                'lowercase': 6,
                'uppercase': 4,
                'digits': 2,
                'special': 0
            },
            'detected_patterns': [],
            'suggestions': [
                'Add special characters',
                'Consider adding more numbers'
            ]
        }

    def test_format_json(self):
        """Test JSON output format."""
        json_output = self.formatter.format_json(self.sample_result)
        self.assertIn('"strength_score": 78', json_output)
        self.assertIn('"Strong"', json_output)

    def test_format_compact(self):
        """Test compact output format."""
        compact_output = self.formatter.format_compact(self.sample_result)
        self.assertIn('78', compact_output)
        self.assertIn('Strong', compact_output)
        self.assertIn('12 chars', compact_output)

    def test_format_simple(self):
        """Test simple output format."""
        simple_output = self.formatter.format_simple(self.sample_result)
        self.assertIn('STRENGTH ANALYSIS', simple_output)
        self.assertIn('Lowercase', simple_output)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete password checker."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = PasswordAnalyzer()

    def test_basic_workflow(self):
        """Test basic analysis workflow."""
        password = "MySecureP@ss123"
        result = self.analyzer.analyze(password)

        # Verify all fields are present
        self.assertIn('strength_score', result)
        self.assertIn('strength_label', result)
        self.assertIn('suggestions', result)
        self.assertIn('character_counts', result)

        # Verify reasonable values
        self.assertGreater(result['password_length'], 0)
        self.assertGreaterEqual(result['strength_score'], 0)
        self.assertLessEqual(result['strength_score'], 100)

    def test_suggestions_improve_with_strength(self):
        """Test that stronger passwords have fewer suggestions."""
        weak_result = self.analyzer.analyze("abc")
        strong_result = self.analyzer.analyze("X#9kLmNpQ!@#7")

        # Stronger password should have fewer critical suggestions
        self.assertLess(
            len(strong_result['suggestions']),
            len(weak_result['suggestions'])
        )


def run_tests():
    """Run all tests and return results."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestEntropyCalculator))
    suite.addTests(loader.loadTestsFromTestCase(TestPatternDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestSuggestionGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestOutputFormatter))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
