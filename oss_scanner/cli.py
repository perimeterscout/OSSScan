"""Command-line interface for OSS Risk Scanner."""

import argparse
import json
import sys
import os
from typing import Optional
from .scanner import OSSScanner
from .report_formatter import format_report


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='OSS Risk Scanner - Analyze open-source software for security and maintenance risks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  oss-scan https://github.com/owner/repo
  oss-scan owner/repo --token YOUR_GITHUB_TOKEN
  oss-scan owner/repo --output json
  oss-scan owner/repo --output-file report.json
        """
    )

    parser.add_argument(
        'repository',
        help='GitHub repository URL or owner/repo format'
    )

    parser.add_argument(
        '--token',
        help='GitHub personal access token (or set GITHUB_TOKEN env var)',
        default=os.environ.get('GITHUB_TOKEN')
    )

    parser.add_argument(
        '--output',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )

    parser.add_argument(
        '--output-file',
        help='Save report to file'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='OSS Risk Scanner 1.0.0'
    )

    args = parser.parse_args()

    # Initialize scanner
    scanner = OSSScanner(github_token=args.token)

    # Perform scan
    try:
        report = scanner.scan_repository(args.repository)

        if 'error' in report:
            print(f"Error: {report['error']}", file=sys.stderr)
            sys.exit(1)

        # Format output
        if args.output == 'json':
            output = json.dumps(report, indent=2)
        else:
            output = format_report(report)

        # Write to file or stdout
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(output)
            print(f"Report saved to: {args.output_file}")
        else:
            print(output)

        # Exit with appropriate code based on risk level
        risk_level = report.get('risk_level', 'UNKNOWN')
        if risk_level == 'CRITICAL':
            sys.exit(2)
        elif risk_level in ['HIGH', 'MEDIUM']:
            sys.exit(1)
        else:
            sys.exit(0)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan cancelled by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
