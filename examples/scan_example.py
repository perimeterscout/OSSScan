#!/usr/bin/env python3
"""Example script demonstrating OSS Risk Scanner usage."""

import sys
sys.path.insert(0, '..')

from oss_scanner import OSSScanner
import json


def main():
    """Run example scans."""
    # Initialize scanner (optionally with GitHub token)
    scanner = OSSScanner()

    # Example repositories to scan
    repos = [
        'torvalds/linux',
        'python/cpython',
        'nodejs/node'
    ]

    print("OSS Risk Scanner - Example Usage\n")
    print("=" * 70)

    for repo in repos:
        print(f"\nScanning: {repo}")
        print("-" * 70)

        try:
            report = scanner.scan_repository(repo)

            if 'error' in report:
                print(f"Error: {report['error']}")
                continue

            # Display key information
            print(f"Risk Level: {report['risk_level']}")
            print(f"Overall Score: {report['overall_risk_score']}/100")

            print("\nRisk Breakdown:")
            factors = report['risk_factors']
            print(f"  Security:     {factors['security']['score']}/100")
            print(f"  Maintenance:  {factors['maintenance']['score']}/100")
            print(f"  Dependencies: {factors['dependencies']['score']}/100")
            print(f"  License:      {factors['license']['score']}/100")
            print(f"  Community:    {factors['community']['score']}/100")

            print(f"\nTop Recommendations:")
            for i, rec in enumerate(report['recommendations'][:3], 1):
                print(f"  {i}. {rec}")

        except Exception as e:
            print(f"Error scanning {repo}: {e}")

        print()

    print("=" * 70)


if __name__ == '__main__':
    main()
