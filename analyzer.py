#!/usr/bin/env python3
"""
Password Analyzer Module

This module orchestrates the password analysis process by combining
entropy calculation, pattern detection, and scoring.
"""

from typing import Dict, List, Tuple
from entropy import EntropyCalculator
from patterns import PatternDetector
from suggestions import SuggestionGenerator


class PasswordAnalyzer:
    """
    Main analyzer that combines all analysis components.
    """

    # Strength score thresholds and labels
    STRENGTH_LABELS = {
        (0, 20): "Very Weak",
        (21, 40): "Weak",
        (41, 60): "Fair",
        (61, 80): "Strong",
        (81, 100): "Very Strong"
    }

    # Score component weights
    ENTROPY_WEIGHT = 40
    LENGTH_WEIGHT = 20
    VARIETY_WEIGHT = 20
    PATTERN_PENALTY_MAX = 20

    def __init__(self):
        """Initialize the password analyzer with all components."""
        self.entropy_calc = EntropyCalculator()
        self.pattern_detector = PatternDetector()
        self.suggestion_generator = SuggestionGenerator()

    def analyze(self, password: str) -> Dict:
        """
        Perform comprehensive password analysis.

        Args:
            password: The password to analyze

        Returns:
            Dictionary containing all analysis results
        """
        if not password or not password.strip():
            return self._empty_result()

        # Trim whitespace but preserve internal spaces
        password = password.strip()

        # Get entropy information
        entropy = self.entropy_calc.calculate_entropy(password)
        pool_size = self.entropy_calc.get_character_pool_size(password)
        pool_info = self.entropy_calc.get_pool_info(password)
        pool_breakdown = self.entropy_calc.get_pool_breakdown(password)

        # Detect patterns
        patterns = self.pattern_detector.detect_all_patterns(password)
        pattern_penalty = self.pattern_detector.get_pattern_penalty(patterns)

        # Calculate strength score
        strength_score = self._calculate_strength_score(
            entropy=entropy,
            length=len(password),
            pool_info=pool_info,
            pattern_penalty=pattern_penalty
        )

        # Get strength label
        strength_label = self._get_strength_label(strength_score)

        # Generate suggestions
        suggestions = self.suggestion_generator.generate_suggestions(
            password=password,
            pool_info=pool_info,
            pool_breakdown=pool_breakdown,
            patterns=patterns,
            entropy=entropy,
            score=strength_score
        )

        # Format pattern descriptions
        pattern_descriptions = [p[1] for p in patterns]

        return {
            'password_length': len(password),
            'entropy_bits': entropy,
            'pool_size': pool_size,
            'strength_score': strength_score,
            'strength_label': strength_label,
            'character_counts': pool_breakdown,
            'character_types': pool_info,
            'detected_patterns': pattern_descriptions,
            'pattern_types': [p[0] for p in patterns],
            'pattern_penalty': pattern_penalty,
            'suggestions': suggestions,
            'analyzed': True
        }

    def _empty_result(self) -> Dict:
        """
        Return an empty result for invalid passwords.

        Returns:
            Empty result dictionary
        """
        return {
            'password_length': 0,
            'entropy_bits': 0.0,
            'pool_size': 0,
            'strength_score': 0,
            'strength_label': 'N/A',
            'character_counts': {
                'lowercase': 0,
                'uppercase': 0,
                'digits': 0,
                'special': 0
            },
            'character_types': {
                'has_lowercase': False,
                'has_uppercase': False,
                'has_digits': False,
                'has_special': False
            },
            'detected_patterns': [],
            'pattern_types': [],
            'pattern_penalty': 0,
            'suggestions': ['Enter a password to analyze'],
            'analyzed': False
        }

    def _calculate_strength_score(
        self,
        entropy: float,
        length: int,
        pool_info: Dict[str, bool],
        pattern_penalty: int
    ) -> int:
        """
        Calculate the overall strength score (0-100).

        Args:
            entropy: Calculated entropy in bits
            length: Password length
            pool_info: Character type availability
            pattern_penalty: Penalty from detected patterns

        Returns:
            Strength score from 0-100
        """
        # Entropy component (0-40 points)
        entropy_score = self.entropy_calc.get_entropy_score_component(entropy)

        # Length component (0-20 points)
        # Optimal length is 16+ characters
        if length < 8:
            length_score = 0
        elif length < 10:
            length_score = 8
        elif length < 12:
            length_score = 12
        elif length < 14:
            length_score = 16
        elif length < 16:
            length_score = 18
        else:
            length_score = 20

        # Variety component (0-20 points)
        # Based on number of character types used
        variety_score = self._calculate_variety_score(pool_info)

        # Calculate base score
        base_score = entropy_score + length_score + variety_score

        # Apply pattern penalty
        final_score = max(0, base_score - pattern_penalty)

        # Cap at 100
        return min(100, final_score)

    def _calculate_variety_score(self, pool_info: Dict[str, bool]) -> int:
        """
        Calculate variety score based on character type diversity.

        Args:
            pool_info: Character type availability

        Returns:
            Variety score from 0-20
        """
        types_used = sum([
            pool_info['has_lowercase'],
            pool_info['has_uppercase'],
            pool_info['has_digits'],
            pool_info['has_special']
        ])

        # Score based on variety
        variety_scores = {
            1: 5,
            2: 10,
            3: 15,
            4: 20
        }

        return variety_scores.get(types_used, 0)

    def _get_strength_label(self, score: int) -> str:
        """
        Get the strength label for a given score.

        Args:
            score: Strength score (0-100)

        Returns:
            Strength label string
        """
        for (min_score, max_score), label in self.STRENGTH_LABELS.items():
            if min_score <= score <= max_score:
                return label

        return "Unknown"

    def get_quick_score(self, password: str) -> Tuple[int, str]:
        """
        Get a quick strength score without detailed analysis.

        Args:
            password: The password to score

        Returns:
            Tuple of (score, label)
        """
        if not password:
            return (0, "N/A")

        result = self.analyze(password)
        return (result['strength_score'], result['strength_label'])
