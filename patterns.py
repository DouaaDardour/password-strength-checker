#!/usr/bin/env python3
"""
Pattern Detection Module

This module detects common weak patterns in passwords such as:
- Sequential characters (abc, 123)
- Repeated characters (aaa)
- Keyboard patterns (qwerty, asdf)
- Common words and substitutions
"""

from typing import List, Tuple


class PatternDetector:
    """
    Detects common weak patterns in passwords.
    """

    # Keyboard layout patterns (QWERTY layout)
    KEYBOARD_PATTERNS = [
        'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
        '123456', '123456789', '1234', '12345', '1234567', '12345678',
        'qazwsx', 'zaqwsx', '!@#$%', '!@#$%^',
        'abcd', 'abcdef', 'abcdefgh',
        '1111', '2222', '3333', '0000', '9999',
        'aaa', 'bbb', '111', '222'
    ]

    # Sequential character sets
    SEQUENTIAL_LOWERCASE = [chr(i) + chr(i+1) + chr(i+2) for i in range(97, 119)]
    SEQUENTIAL_UPPERCASE = [chr(i) + chr(i+1) + chr(i+2) for i in range(65, 87)]
    SEQUENTIAL_DIGITS = [str(i) + str(i+1) + str(i+2) for i in range(0, 8)]
    SEQUENTIAL_DIGITS_EXTENDED = [str(i) + str(i+1) + str(i+2) + str(i+3) for i in range(0, 7)]

    # Reverse sequences
    REVERSE_SEQUENTIAL_LOWERCASE = [chr(i+2) + chr(i+1) + chr(i) for i in range(97, 119)]
    REVERSE_SEQUENTIAL_UPPERCASE = [chr(i+2) + chr(i+1) + chr(i) for i in range(65, 87)]
    REVERSE_SEQUENTIAL_DIGITS = [str(i+2) + str(i+1) + str(i) for i in range(0, 8)]

    # Common word patterns
    COMMON_WORDS = [
        'password', 'passwd', 'pass', 'admin', 'login', 'welcome',
        'monkey', 'dragon', 'master', 'letmein', 'qwerty', 'abc',
        'iloveyou', 'sunshine', 'princess', 'football', 'baseball',
        'shadow', 'michael', 'jennifer', 'jordan', 'superman',
        'batman', 'trustno1', 'ninja', 'mustang', 'access',
        'hello', 'charlie', 'donald', 'qwerty123', 'password1'
    ]

    # Common letter-to-symbol substitutions
    SUBSTITUTIONS = {
        '@': ['a', 'A'],
        '4': ['a', 'A'],
        '3': ['e', 'E'],
        '1': ['i', 'I', 'l', 'L'],
        '!': ['i', 'I'],
        '0': ['o', 'O'],
        '$': ['s', 'S'],
        '5': ['s', 'S'],
        '7': ['t', 'T'],
        '+': ['t', 'T']
    }

    def __init__(self):
        """Initialize the pattern detector."""
        self.detected_patterns: List[str] = []

    def detect_all_patterns(self, password: str) -> List[Tuple[str, str]]:
        """
        Detect all weak patterns in the password.

        Args:
            password: The password to analyze (case-insensitive for detection)

        Returns:
            List of tuples (pattern_type, pattern_description)
        """
        detected = []
        password_lower = password.lower()

        # Check keyboard patterns
        for pattern in self.KEYBOARD_PATTERNS:
            if pattern in password_lower or pattern in password:
                detected.append(('keyboard', f'Keyboard pattern: {pattern}'))
            # Check reversed keyboard patterns
            if pattern[::-1] in password_lower or pattern[::-1] in password:
                detected.append(('keyboard', f'Reversed keyboard pattern: {pattern[::-1]}'))

        # Check sequential patterns
        for seq in self.SEQUENTIAL_LOWERCASE:
            if seq in password_lower:
                detected.append(('sequential', f'Sequential letters: {seq}'))
        for seq in self.SEQUENTIAL_UPPERCASE:
            if seq in password or seq.lower() in password_lower:
                detected.append(('sequential', f'Sequential letters: {seq}'))
        for seq in self.SEQUENTIAL_DIGITS_EXTENDED:
            if seq in password:
                detected.append(('sequential', f'Sequential numbers: {seq}'))
        for seq in self.SEQUENTIAL_DIGITS:
            if seq in password:
                detected.append(('sequential', f'Sequential numbers: {seq}'))

        # Check reverse sequential patterns
        for seq in self.REVERSE_SEQUENTIAL_LOWERCASE:
            if seq in password_lower:
                detected.append(('sequential', f'Reverse sequential letters: {seq}'))
        for seq in self.REVERSE_SEQUENTIAL_DIGITS:
            if seq in password:
                detected.append(('sequential', f'Reverse sequential numbers: {seq}'))

        # Check repeated characters (3 or more)
        if self._has_repeated_chars(password, 3):
            detected.append(('repeated', 'Repeated characters detected (3+)'))

        # Check common words
        for word in self.COMMON_WORDS:
            if word in password_lower:
                detected.append(('dictionary', f'Common word: {word}'))
            # Check with common substitutions
            if self._check_substituted_word(password, word):
                detected.append(('dictionary', f'Common word with substitutions: {word}'))

        # Check for only one character type
        if self._is_single_char_type(password):
            detected.append(('simple', 'Only one character type used'))

        return detected

    def _has_repeated_chars(self, password: str, min_repeats: int = 3) -> bool:
        """
        Check if password contains repeated characters.

        Args:
            password: The password to check
            min_repeats: Minimum number of repeated characters to detect

        Returns:
            True if repeated characters are found
        """
        if len(password) < min_repeats:
            return False

        for i in range(len(password) - min_repeats + 1):
            char = password[i]
            all_same = True
            for j in range(i + 1, i + min_repeats):
                if password[j] != char:
                    all_same = False
                    break
            if all_same:
                return True

        return False

    def _check_substituted_word(self, password: str, word: str) -> bool:
        """
        Check if password contains a word with common substitutions.

        Args:
            password: The password to check
            word: The base word to check against

        Returns:
            True if a substituted version of the word is found
        """
        password_lower = password.lower()

        # Generate all possible substituted versions
        def generate_substitutions(pos: int, current: str) -> List[str]:
            if pos >= len(word):
                return [current]

            results = [current + word[pos]]
            char = word[pos].lower()
            if char in self.SUBSTITUTIONS:
                for sub in self.SUBSTITUTIONS[char]:
                    results.append(current + sub)

            all_results = []
            for r in results:
                all_results.extend(generate_substitutions(pos + 1, r))

            return all_results

        substituted_versions = generate_substitutions(0, '')
        return any(sv in password_lower for sv in substituted_versions)

    def _is_single_char_type(self, password: str) -> bool:
        """
        Check if password uses only one character type.

        Args:
            password: The password to check

        Returns:
            True if only one character type is used
        """
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in set('!@#$%^&*()_+-=[]{}|;:\'\",./<>?`~') for c in password)

        types_used = sum([has_lower, has_upper, has_digit, has_special])

        return types_used == 1

    def get_pattern_penalty(self, patterns: List[Tuple[str, str]]) -> int:
        """
        Calculate penalty score based on detected patterns.

        Args:
            patterns: List of detected patterns

        Returns:
            Penalty score (0-20)
        """
        if not patterns:
            return 0

        penalty = 0
        pattern_types = set(p[0] for p in patterns)

        for pattern_type in pattern_types:
            if pattern_type == 'dictionary':
                penalty += 15  # Heavy penalty for dictionary words
            elif pattern_type == 'keyboard':
                penalty += 8
            elif pattern_type == 'sequential':
                penalty += 6
            elif pattern_type == 'repeated':
                penalty += 4
            elif pattern_type == 'simple':
                penalty += 10

        return min(penalty, 20)  # Cap at 20 points
