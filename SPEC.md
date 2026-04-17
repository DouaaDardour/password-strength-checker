# Password Strength Checker Tool - Specification

## 1. Project Overview

**Project Name:** Password Strength Checker
**Project Type:** Python Command-Line Tool
**Core Functionality:** Evaluates password security using entropy-based calculations and provides actionable improvement suggestions
**Target Users:** Security-conscious users, developers testing password policies, and organizations wanting to assess password security

---

## 2. Technical Specification

### 2.1 Core Features

#### Entropy Calculation
- **Formula:** `entropy = length * log2(pool_size)`
- **Pool Size Calculation:**
  - Lowercase letters (a-z): 26 characters
  - Uppercase letters (A-Z): 26 characters
  - Digits (0-9): 10 characters
  - Special characters (!@#$%^&*()_+-=[]{}|;':\",./<>?): 32 characters
- **Character Set Detection:** Analyze password to determine which character pools are used

#### Strength Scoring
- **Score Range:** 0-100 points
- **Score Breakdown:**
  - Entropy score (0-40 points): Based on bits of entropy
  - Length bonus (0-20 points): Longer passwords get additional points
  - Variety bonus (0-20 points): Using diverse character types
  - Pattern penalty (0-20 points deduction): Penalize common patterns
  - Dictionary word penalty (heavily penalized if detected)

#### Strength Labels
- **0-20:** Very Weak
- **21-40:** Weak
- **41-60:** Fair
- **61-80:** Strong
- **81-100:** Very Strong

### 2.2 Improvement Suggestion System

The tool generates specific, actionable suggestions based on detected weaknesses:

1. **Length Suggestions**
   - If length < 8: "Add at least 8 characters"
   - If length < 12: "Consider using 12+ characters for better security"
   - If length < 16: "For high-security accounts, use 16+ characters"

2. **Character Type Suggestions**
   - Missing lowercase: "Add lowercase letters (a-z)"
   - Missing uppercase: "Add uppercase letters (A-Z)"
   - Missing digits: "Include numbers (0-9)"
   - Missing special: "Add special characters (!@#$%^&*)"

3. **Pattern Detection Warnings**
   - Sequential characters: "Avoid sequential patterns like 'abc' or '123'"
   - Repeated characters: "Avoid repeated characters like 'aaa'"
   - Keyboard patterns: "Avoid keyboard patterns like 'qwerty'"
   - Common substitutions: "Avoid common substitutions like '@' for 'a'"

4. **Dictionary Word Detection**
   - "Avoid common dictionary words"
   - "Consider using a passphrase instead of a single word"

### 2.3 User Interface

#### Command-Line Interface
```
Usage: python password_checker.py [OPTIONS] [PASSWORD]

Options:
  --detailed / --no-detailed    Show detailed analysis (default: True)
  --suggestions / --no-suggestions  Show suggestions (default: True)
  --json                         Output in JSON format
  --help                         Show this help message
```

#### Output Format (Console)
```
╔══════════════════════════════════════════════════════════╗
║              PASSWORD STRENGTH ANALYSIS                  ║
╠══════════════════════════════════════════════════════════╣
║  Password: ••••••••                                     ║
║  Length: 12 characters                                   ║
║  Entropy: 70.4 bits                                      ║
╠══════════════════════════════════════════════════════════╣
║  Strength Score: 78/100 ████████████████████░░░░░ Strong ║
╠══════════════════════════════════════════════════════════╣
║  Character Analysis:                                      ║
║    ✓ Lowercase: 6 characters                             ║
║    ✓ Uppercase: 4 characters                              ║
║    ✓ Numbers: 2 characters                                ║
║    ✓ Special: 0 characters                               ║
╠══════════════════════════════════════════════════════════╣
║  Suggestions for Improvement:                            ║
║    • Add special characters (!@#$%^&*)                   ║
║    • Consider adding more numbers                         ║
╚══════════════════════════════════════════════════════════╝
```

#### Output Format (JSON)
```json
{
  "password_length": 12,
  "entropy_bits": 70.4,
  "strength_score": 78,
  "strength_label": "Strong",
  "character_counts": {
    "lowercase": 6,
    "uppercase": 4,
    "digits": 2,
    "special": 0
  },
  "detected_patterns": [],
  "suggestions": [
    "Add special characters (!@#$%^&*)",
    "Consider adding more numbers"
  ]
}
```

### 2.4 Edge Cases Handling

1. **Empty Password:** Return score 0 with message "No password entered"
2. **Whitespace-only:** Trim and analyze, or return error for empty after trim
3. **Unicode Characters:** Support extended Unicode for international passwords
4. **Extremely Long Passwords:** Cap entropy calculation at 128 bits for scoring
5. **No Interactive Mode:** Password read from command line argument or stdin (secure)

---

## 3. Acceptance Criteria

### 3.1 Functional Requirements

- [ ] Calculate accurate entropy based on character pool
- [ ] Score passwords on 0-100 scale with appropriate labels
- [ ] Detect missing character types (lowercase, uppercase, digits, special)
- [ ] Identify common patterns (sequential, repeated, keyboard patterns)
- [ ] Provide 3-5 specific improvement suggestions
- [ ] Support both interactive and non-interactive usage
- [ ] Output in both human-readable and JSON formats

### 3.2 Quality Requirements

- [ ] Clear, informative output with visual formatting
- [ ] Actionable suggestions that directly address weaknesses
- [ ] Fast execution (< 100ms for analysis)
- [ ] No external dependencies beyond Python standard library
- [ ] Handles edge cases gracefully without crashing

### 3.3 Test Scenarios

1. **Basic Test:** "password" → Score ~25 (Very Weak), suggest uppercase, numbers, special
2. **Moderate Test:** "Pass1234" → Score ~55 (Fair), suggest longer, special
3. **Strong Test:** "MyP@ssw0rd!2024" → Score ~85 (Very Strong)
4. **Pattern Test:** "abc123456" → Detect sequential pattern warning
5. **Empty Test:** "" → Handle gracefully with appropriate message

---

## 4. Implementation Plan

### Phase 1: Core Engine
- Entropy calculator module
- Character pool analyzer
- Strength scorer

### Phase 2: Pattern Detection
- Sequential pattern detector
- Keyboard pattern detector
- Repeated character detector
- Dictionary word checker (basic)

### Phase 3: Suggestions Engine
- Rule-based suggestion generator
- Priority-based suggestion sorting

### Phase 4: User Interface
- CLI argument parser
- Formatted console output
- JSON output support

---

## 5. File Structure

```
/workspace/
├── SPEC.md                 # This specification
├── password_checker.py    # Main entry point
├── entropy.py             # Entropy calculation module
├── analyzer.py            # Password analysis module
├── patterns.py            # Pattern detection module
├── suggestions.py         # Suggestion generation module
├── output.py              # Output formatting module
└── tests.py               # Unit tests
```
