#!/usr/bin/env python3
"""
Suggestion Generation Module

This module generates actionable improvement suggestions based on
password analysis results.
"""

from typing import List, Dict
from entropy import EntropyCalculator
from patterns import PatternDetector


class SuggestionGenerator:
    """
    Generates actionable suggestions for password improvement.
    """

    def __init__(self):
        """Initialize the suggestion generator."""
        self.entropy_calc = EntropyCalculator()
        self.pattern_detector = PatternDetector()

    def generate_suggestions(
        self,
        password: str,
        pool_info: Dict[str, bool],
        pool_breakdown: Dict[str, int],
        patterns: List,
        entropy: float,
        score: int
    ) -> List[str]:
        """
        Generate improvement suggestions based on analysis.

        Args:
            password: The password to improve
            pool_info: Dictionary of character type availability
            pool_breakdown: Dictionary of character type counts
            patterns: List of detected patterns
            entropy: Calculated entropy in bits
            score: Current strength score

        Returns:
            List of suggestion strings
        """
        suggestions = []

        # Length-based suggestions
        length = len(password)
        suggestions.extend(self._get_length_suggestions(length, entropy))

        # Character type suggestions
        suggestions.extend(self._get_character_type_suggestions(pool_info, pool_breakdown))

        # Pattern-based suggestions
        suggestions.extend(self._get_pattern_suggestions(patterns))

        # General security suggestions for weak passwords
        if score < 60:
            suggestions.extend(self._get_security_suggestions(score))

        # Remove duplicates while preserving order
        seen = set()
        unique_suggestions = []
        for s in suggestions:
            if s.lower() not in seen:
                seen.add(s.lower())
                unique_suggestions.append(s)

        # Return top 5 most important suggestions
        return unique_suggestions[:5]

    def _get_length_suggestions(self, length: int, entropy: float) -> List[str]:
        """
        Generate suggestions based on password length.

        Args:
            length: Password length
            entropy: Calculated entropy

        Returns:
            List of length-related suggestions
        """
        suggestions = []

        if length < 8:
            suggestions.append("Add at least 8 characters - short passwords are easily cracked")
            suggestions.append("Use a longer passphrase for better security")
        elif length < 12:
            suggestions.append("Consider using 12+ characters for better security")
        elif length < 16 and entropy < 60:
            suggestions.append("For high-security accounts, aim for 16+ characters")

        # Suggest adding words for low-entropy passwords
        if entropy < 40 and length < 20:
            suggestions.append("Consider using a passphrase with multiple random words")

        return suggestions

    def _get_character_type_suggestions(
        self,
        pool_info: Dict[str, bool],
        pool_breakdown: Dict[str, int]
    ) -> List[str]:
        """
        Generate suggestions for missing character types.

        Args:
            pool_info: Dictionary of character type availability
            pool_breakdown: Dictionary of character type counts

        Returns:
            List of character type suggestions
        """
        suggestions = []

        if not pool_info['has_lowercase']:
            suggestions.append("Add lowercase letters (a-z)")
        elif pool_breakdown['lowercase'] < 3:
            suggestions.append("Consider adding more lowercase letters")

        if not pool_info['has_uppercase']:
            suggestions.append("Add uppercase letters (A-Z)")
        elif pool_breakdown['uppercase'] < 2:
            suggestions.append("Consider adding more uppercase letters")

        if not pool_info['has_digits']:
            suggestions.append("Include numbers (0-9)")
        elif pool_breakdown['digits'] < 2:
            suggestions.append("Consider adding more numbers")

        if not pool_info['has_special']:
            suggestions.append("Add special characters (!@#$%^&*)")
        elif pool_breakdown['special'] < 2:
            suggestions.append("Consider adding more special characters")

        return suggestions

    def _get_pattern_suggestions(self, patterns: List) -> List[str]:
        """
        Generate suggestions based on detected patterns.

        Args:
            patterns: List of detected patterns

        Returns:
            List of pattern-related suggestions
        """
        suggestions = []

        if not patterns:
            return suggestions

        pattern_types = set(p[0] for p in patterns)

        if 'keyboard' in pattern_types:
            suggestions.append("Avoid keyboard patterns like 'qwerty' or '123456'")
            suggestions.append("Use a more random combination of characters")

        if 'sequential' in pattern_types:
            suggestions.append("Avoid sequential patterns like 'abc' or '123'")
            suggestions.append("Mix characters from different parts of the alphabet")

        if 'repeated' in pattern_types:
            suggestions.append("Avoid repeated characters like 'aaa' or '111'")

        if 'dictionary' in pattern_types:
            suggestions.append("Avoid common dictionary words")
            suggestions.append("Consider using a passphrase or random word combination")
            suggestions.append("Replace common words with less predictable alternatives")

        if 'simple' in pattern_types:
            suggestions.append("Mix different character types for stronger passwords")

        return suggestions

    def _get_security_suggestions(self, score: int) -> List[str]:
        """
        Generate general security suggestions for weak passwords.

        Args:
            score: Current strength score

        Returns:
            List of general security suggestions
        """
        suggestions = []

        if score < 20:
            suggestions.append("This password is very weak - create a new one immediately")
            suggestions.append("Use a password manager to generate strong passwords")
        elif score < 40:
            suggestions.append("Consider using a unique password for each account")
            suggestions.append("Use a password manager to help generate and store passwords")
        elif score < 60:
            suggestions.append("For important accounts, use unique strong passwords")
            suggestions.append("Consider enabling two-factor authentication")

        return suggestions

    def prioritize_suggestions(
        self,
        suggestions: List[str],
        pool_info: Dict[str, bool],
        patterns: List,
        length: int
    ) -> List[str]:
        """
        Prioritize suggestions based on their impact on password strength.

        Args:
            suggestions: List of all suggestions
            pool_info: Character type availability
            patterns: Detected patterns
            length: Password length

        Returns:
            Sorted list of suggestions by priority
        """
        priority_scores = []

        for suggestion in suggestions:
            score = 0
            suggestion_lower = suggestion.lower()

            # High priority: missing character types
            if 'lowercase' in suggestion_lower and not pool_info['has_lowercase']:
                score += 30
            if 'uppercase' in suggestion_lower and not pool_info['has_uppercase']:
                score += 30
            if 'numbers' in suggestion_lower and not pool_info['has_digits']:
                score += 25
            if 'special' in suggestion_lower and not pool_info['has_special']:
                score += 25

            # High priority: length
            if '8 characters' in suggestion_lower or '12+ characters' in suggestion_lower:
                if length < 8:
                    score += 40
                elif length < 12:
                    score += 25
                else:
                    score += 10

            # Medium priority: patterns
            if 'avoid' in suggestion_lower:
                score += 20
            if 'keyboard' in suggestion_lower or 'sequential' in suggestion_lower:
                score += 15

            # Medium priority: dictionary words
            if 'dictionary' in suggestion_lower or 'common word' in suggestion_lower:
                score += 20

            # General security suggestions (lower priority)
            if 'password manager' in suggestion_lower:
                score += 5
            if 'two-factor' in suggestion_lower:
                score += 5

            priority_scores.append((suggestion, score))

        # Sort by priority score (descending)
        priority_scores.sort(key=lambda x: x[1], reverse=True)

        return [s[0] for s in priority_scores]
