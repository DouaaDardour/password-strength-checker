#!/usr/bin/env python3
"""
Output Formatting Module

This module provides formatted output for the password checker tool.
Supports both human-readable console output and JSON format.
"""

import json
from typing import Dict, List


class OutputFormatter:
    """
    Formats password analysis results for display.
    """

    # ANSI color codes
    COLORS = {
        'reset': '\033[0m',
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'bold': '\033[1m'
    }

    # Strength colors
    STRENGTH_COLORS = {
        'Very Weak': 'red',
        'Weak': 'yellow',
        'Fair': 'yellow',
        'Strong': 'green',
        'Very Strong': 'green'
    }

    def __init__(self, use_colors: bool = True):
        """
        Initialize the output formatter.

        Args:
            use_colors: Whether to use ANSI colors in output
        """
        self.use_colors = use_colors

    def _colorize(self, text: str, color: str) -> str:
        """
        Add color to text.

        Args:
            text: Text to colorize
            color: Color name from COLORS

        Returns:
            Colorized text string
        """
        if not self.use_colors:
            return text

        color_code = self.COLORS.get(color, '')
        reset_code = self.COLORS['reset']
        return f"{color_code}{text}{reset_code}"

    def _create_bar(self, score: int, width: int = 20) -> str:
        """
        Create a visual progress bar.

        Args:
            score: Score value (0-100)
            width: Width of the bar in characters

        Returns:
            Visual progress bar string
        """
        filled = int((score / 100) * width)
        empty = width - filled

        # Choose color based on score
        if score <= 20:
            color = 'red'
        elif score <= 40:
            color = 'red'
        elif score <= 60:
            color = 'yellow'
        elif score <= 80:
            color = 'green'
        else:
            color = 'green'

        bar = self._colorize('█' * filled, color)
        bar += '░' * empty

        return bar

    def format_console(self, result: Dict) -> str:
        """
        Format analysis results for console display.

        Args:
            result: Analysis result dictionary

        Returns:
            Formatted string for console output
        """
        lines = []

        # Header
        lines.append(self._colorize('╔' + '═' * 58 + '╗', 'cyan'))
        lines.append(self._colorize('║' + 'PASSWORD STRENGTH ANALYSIS'.center(58) + '║', 'cyan'))
        lines.append(self._colorize('╠' + '═' * 58 + '╣', 'cyan'))

        # Password display (masked for security)
        masked_password = self._mask_password(result.get('password_length', 0))
        lines.append(f"║  Password: {masked_password:<44}║")
        lines.append(f"║  Length: {result['password_length']} characters{' ' * (44 - len(str(result['password_length'])) - 15)}║")
        lines.append(f"║  Entropy: {result['entropy_bits']} bits{' ' * (44 - len(str(result['entropy_bits'])) - 9)}║")

        lines.append(self._colorize('╠' + '═' * 58 + '╣', 'cyan'))

        # Strength score with bar
        score = result['strength_score']
        label = result['strength_label']
        bar = self._create_bar(score)
        score_text = f"Strength Score: {score}/100 {bar} {label}"
        lines.append(f"║  {score_text:<55}║")

        lines.append(self._colorize('╠' + '═' * 58 + '╣', 'cyan'))

        # Character analysis
        lines.append(self._colorize('║  Character Analysis:'.ljust(58) + '║', 'cyan'))

        counts = result['character_counts']
        check = self._colorize('✓', 'green')
        cross = self._colorize('✗', 'red')

        lines.append(f"║    {check if counts['lowercase'] > 0 else cross} Lowercase: {counts['lowercase']} characters{' ' * (33 - len(str(counts['lowercase'])))}║")
        lines.append(f"║    {check if counts['uppercase'] > 0 else cross} Uppercase: {counts['uppercase']} characters{' ' * (33 - len(str(counts['uppercase'])))}║")
        lines.append(f"║    {check if counts['digits'] > 0 else cross} Numbers: {counts['digits']} characters{' ' * (37 - len(str(counts['digits'])))}║")
        lines.append(f"║    {check if counts['special'] > 0 else cross} Special: {counts['special']} characters{' ' * (37 - len(str(counts['special'])))}║")

        lines.append(self._colorize('╠' + '═' * 58 + '╣', 'cyan'))

        # Detected patterns
        patterns = result.get('detected_patterns', [])
        if patterns:
            lines.append(self._colorize('║  Detected Patterns:'.ljust(58) + '║', 'yellow'))
            for pattern in patterns[:3]:  # Show max 3 patterns
                pattern_short = pattern[:50] + '...' if len(pattern) > 50 else pattern
                lines.append(f"║    ⚠ {pattern_short:<52}║")
            lines.append(self._colorize('╠' + '═' * 58 + '╣', 'cyan'))

        # Suggestions
        suggestions = result.get('suggestions', [])
        if suggestions:
            lines.append(self._colorize('║  Suggestions for Improvement:'.ljust(58) + '║', 'cyan'))
            for suggestion in suggestions:
                suggestion_short = suggestion[:50] + '...' if len(suggestion) > 50 else suggestion
                lines.append(f"║    • {suggestion_short:<52}║")

        lines.append(self._colorize('╚' + '═' * 58 + '╝', 'cyan'))

        return '\n'.join(lines)

    def _mask_password(self, length: int) -> str:
        """
        Create a masked representation of the password.

        Args:
            length: Length of the password

        Returns:
            Masked string
        """
        if length == 0:
            return "(empty)"
        return '•' * min(length, 12) + ('+' if length > 12 else '')

    def format_json(self, result: Dict, pretty: bool = True) -> str:
        """
        Format analysis results as JSON.

        Args:
            result: Analysis result dictionary
            pretty: Whether to use pretty printing

        Returns:
            JSON string
        """
        # Create a clean copy without internal fields
        output = {
            'password_length': result['password_length'],
            'entropy_bits': result['entropy_bits'],
            'strength_score': result['strength_score'],
            'strength_label': result['strength_label'],
            'character_counts': result['character_counts'],
            'detected_patterns': result.get('detected_patterns', []),
            'suggestions': result.get('suggestions', [])
        }

        if pretty:
            return json.dumps(output, indent=2, ensure_ascii=False)
        return json.dumps(output, ensure_ascii=False)

    def format_compact(self, result: Dict) -> str:
        """
        Format a compact single-line result.

        Args:
            result: Analysis result dictionary

        Returns:
            Compact string representation
        """
        score = result['strength_score']
        label = result['strength_label']
        length = result['password_length']
        entropy = result['entropy_bits']

        return f"[{score:3d}/100] {label:12s} | {length:3d} chars | {entropy:6.1f} bits entropy"

    def format_simple(self, result: Dict) -> str:
        """
        Format a simple result without special characters.

        Args:
            result: Analysis result dictionary

        Returns:
            Simple string representation
        """
        lines = []

        lines.append("PASSWORD STRENGTH ANALYSIS")
        lines.append("=" * 50)
        lines.append(f"Length: {result['password_length']} characters")
        lines.append(f"Entropy: {result['entropy_bits']} bits")
        lines.append(f"Strength Score: {result['strength_score']}/100 ({result['strength_label']})")
        lines.append("-" * 50)
        lines.append("Character Types:")

        counts = result['character_counts']
        lines.append(f"  Lowercase: {'Yes' if counts['lowercase'] > 0 else 'No'} ({counts['lowercase']})")
        lines.append(f"  Uppercase: {'Yes' if counts['uppercase'] > 0 else 'No'} ({counts['uppercase']})")
        lines.append(f"  Numbers: {'Yes' if counts['digits'] > 0 else 'No'} ({counts['digits']})")
        lines.append(f"  Special: {'Yes' if counts['special'] > 0 else 'No'} ({counts['special']})")

        patterns = result.get('detected_patterns', [])
        if patterns:
            lines.append("-" * 50)
            lines.append("Detected Patterns:")
            for pattern in patterns[:3]:
                lines.append(f"  - {pattern}")

        suggestions = result.get('suggestions', [])
        if suggestions:
            lines.append("-" * 50)
            lines.append("Suggestions:")
            for suggestion in suggestions:
                lines.append(f"  - {suggestion}")

        return '\n'.join(lines)
