# Password Strength Checker

A powerful Python command-line tool for evaluating password security using entropy-based calculations and providing actionable improvement suggestions.

## Features

- **Entropy-Based Scoring**: Calculate password strength using information theory (bits of entropy)
- **Comprehensive Analysis**: Detect character types, patterns, and common weaknesses
- **Pattern Detection**: Identify keyboard patterns, sequential characters, repeated chars, and dictionary words
- **Smart Suggestions**: Get actionable improvement recommendations prioritized by impact
- **Multiple Output Formats**: Console (with colors), JSON, and compact modes

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/password-strength-checker.git
cd password-strength-checker

# Run directly
python password_checker.py your_password
