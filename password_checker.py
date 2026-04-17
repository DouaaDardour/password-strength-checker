#!/usr/bin/env python3
"""
Password Strength Checker Tool

A command-line tool for evaluating password security using entropy-based
scoring and providing actionable improvement suggestions.

Usage:
    python password_checker.py [OPTIONS] [PASSWORD]

Examples:
    python password_checker.py mypassword123
    python password_checker.py "MySecureP@ssw0rd!"
    python password_checker.py --json "password"
    echo "MyPassword" | python password_checker.py
"""

import sys
import argparse
import os
from typing import Optional

from analyzer import PasswordAnalyzer
from output import OutputFormatter


class PasswordCheckerCLI:
    """
    Command-line interface for the password checker.
    """

    def __init__(self):
        """Initialize the CLI."""
        self.analyzer = PasswordAnalyzer()

    def run(self, args: argparse.Namespace) -> int:
        """
        Run the password checker based on arguments.

        Args:
            args: Parsed command-line arguments

        Returns:
            Exit code (0 for success, 1 for error)
        """
        password = self._get_password(args)

        if not password:
            print("Error: No password provided. Use --help for usage information.", file=sys.stderr)
            return 1

        # Analyze the password
        result = self.analyzer.analyze(password)

        # Output the result
        if args.json:
            output_formatter = OutputFormatter(use_colors=False)
            print(output_formatter.format_json(result, pretty=not args.compact))
        elif args.compact:
            output_formatter = OutputFormatter(use_colors=False)
            print(output_formatter.format_compact(result))
        else:
            output_formatter = OutputFormatter(use_colors=sys.stdout.isatty())
            print(output_formatter.format_console(result))

        return 0

    def _get_password(self, args: argparse.Namespace) -> Optional[str]:
        """
        Get the password from arguments or stdin.

        Args:
            args: Parsed command-line arguments

        Returns:
            The password string or None
        """
        # Priority 1: Command-line argument
        if args.password:
            return args.password

        # Priority 2: Environment variable
        if 'PASSWORD' in os.environ:
            return os.environ['PASSWORD']

        # Priority 3: Stdin (if provided via pipe)
        if not sys.stdin.isatty():
            password = sys.stdin.read().strip()
            if password:
                return password

        return None


def create_parser() -> argparse.ArgumentParser:
    """
    Create the argument parser.

    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog='password_checker.py',
        description='Password Strength Checker - Evaluate password security with entropy-based scoring',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s mypassword123
  %(prog)s "MySecureP@ssw0rd!"
  %(prog)s --json "password"
  %(prog)s --compact "abc123"
  echo "secret" | %(prog)s

Environment Variables:
  PASSWORD     Alternative way to pass the password (not recommended)

Exit Codes:
  0   Success
  1   Error (no password provided)
        '''
    )

    parser.add_argument(
        'password',
        nargs='?',
        default=None,
        help='Password to check (if not provided, reads from stdin)'
    )

    parser.add_argument(
        '-j', '--json',
        action='store_true',
        default=False,
        help='Output results in JSON format'
    )

    parser.add_argument(
        '-c', '--compact',
        action='store_true',
        default=False,
        help='Output compact single-line result'
    )

    parser.add_argument(
        '-s', '--simple',
        action='store_true',
        default=False,
        help='Output simple format without special characters'
    )

    parser.add_argument(
        '--no-colors',
        action='store_true',
        default=False,
        help='Disable colored output'
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    return parser


def main() -> int:
    """
    Main entry point.

    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args()

    cli = PasswordCheckerCLI()
    return cli.run(args)


if __name__ == '__main__':
    sys.exit(main())
