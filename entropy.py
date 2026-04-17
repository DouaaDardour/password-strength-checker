#!/usr/bin/env python3
"""
Entropy Calculator Module

This module provides entropy calculation functionality for password strength analysis.
Entropy is calculated based on the character pool size and password length.
"""

import math
from typing import Dict


class EntropyCalculator:
    """
    Calculates the entropy (bits of security) for a given password.

    Entropy Formula: entropy = length * log2(pool_size)

    The pool size is determined by which character sets are used:
    - Lowercase letters: 26 characters (a-z)
    - Uppercase letters: 26 characters (A-Z)
    - Digits: 10 characters (0-9)
    - Special characters: 32 common special characters
    """

    # Character pool sizes
    LOWERCASE_SIZE = 26
    UPPERCASE_SIZE = 26
    DIGITS_SIZE = 10
    SPECIAL_SIZE = 32

    def __init__(self):
        """Initialize the entropy calculator."""
        pass

    def get_character_pool_size(self, password: str) -> int:
        """
        Determine the total character pool size based on character types used.

        Args:
            password: The password to analyze

        Returns:
            Total number of possible characters in the pool
        """
        pool_size = 0

        has_lowercase = any(c.islower() for c in password)
        has_uppercase = any(c.isupper() for c in password)
        has_digits = any(c.isdigit() for c in password)
        has_special = self._is_special_character(password)

        if has_lowercase:
            pool_size += self.LOWERCASE_SIZE
        if has_uppercase:
            pool_size += self.UPPERCASE_SIZE
        if has_digits:
            pool_size += self.DIGITS_SIZE
        if has_special:
            pool_size += self.SPECIAL_SIZE

        return pool_size if pool_size > 0 else 1  # Prevent log(0)

    def _is_special_character(self, password: str) -> bool:
        """
        Check if the password contains special characters.

        Args:
            password: The password to check

        Returns:
            True if special characters are found
        """
        special_chars = set('!@#$%^&*()_+-=[]{}|;:\'\",./<>?`~')
        return any(c in special_chars for c in password)

    def calculate_entropy(self, password: str) -> float:
        """
        Calculate the entropy (bits) of the password.

        Args:
            password: The password to analyze

        Returns:
            Entropy in bits (rounded to 1 decimal place)
        """
        if not password:
            return 0.0

        length = len(password)
        pool_size = self.get_character_pool_size(password)

        # entropy = length * log2(pool_size)
        entropy = length * math.log2(pool_size)

        return round(entropy, 1)

    def get_entropy_score_component(self, entropy: float) -> int:
        """
        Convert entropy value to a score component (0-40 points).

        Args:
            entropy: Entropy in bits

        Returns:
            Score from 0-40 based on entropy
        """
        if entropy <= 0:
            return 0
        elif entropy < 28:
            return int(min(entropy / 28 * 10, 10))
        elif entropy < 36:
            return int(10 + min((entropy - 28) / 8 * 10, 10))
        elif entropy < 60:
            return int(20 + min((entropy - 36) / 24 * 10, 10))
        elif entropy < 80:
            return int(30 + min((entropy - 60) / 20 * 10, 10))
        else:
            return min(40, int(40))

    def get_pool_breakdown(self, password: str) -> Dict[str, int]:
        """
        Get a breakdown of character types in the password.

        Args:
            password: The password to analyze

        Returns:
            Dictionary with counts for each character type
        """
        counts = {
            'lowercase': 0,
            'uppercase': 0,
            'digits': 0,
            'special': 0
        }

        special_chars = set('!@#$%^&*()_+-=[]{}|;:\'\",./<>?`~')

        for char in password:
            if char.islower():
                counts['lowercase'] += 1
            elif char.isupper():
                counts['uppercase'] += 1
            elif char.isdigit():
                counts['digits'] += 1
            elif char in special_chars:
                counts['special'] += 1
            else:
                # Handle Unicode and other characters
                if char.isalpha():
                    # Consider as lowercase if not uppercase
                    if char.islower():
                        counts['lowercase'] += 1
                    else:
                        counts['uppercase'] += 1
                # Other characters counted as special
                else:
                    counts['special'] += 1

        return counts

    def get_pool_info(self, password: str) -> Dict[str, bool]:
        """
        Get information about which character pools are used.

        Args:
            password: The password to analyze

        Returns:
            Dictionary with boolean flags for each character type
        """
        counts = self.get_pool_breakdown(password)

        return {
            'has_lowercase': counts['lowercase'] > 0,
            'has_uppercase': counts['uppercase'] > 0,
            'has_digits': counts['digits'] > 0,
            'has_special': counts['special'] > 0
        }
