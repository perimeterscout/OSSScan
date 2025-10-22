"""Report formatting utilities for OSS Risk Scanner."""

from typing import Dict, Any


def format_report(report: Dict[str, Any]) -> str:
    """
    Format scan report as human-readable text.

    Args:
        report: Scan report dictionary

    Returns:
        Formatted text report
    """
    lines = []

    # Header
    lines.append("=" * 70)
    lines.append("OSS RISK SCANNER REPORT")
    lines.append("=" * 70)
    lines.append("")

    # Repository info
    lines.append(f"Repository: {report['repository']}")
    lines.append(f"Scanned at: {report['scanned_at']}")
    lines.append("")

    # Overall risk score
    risk_level = report['risk_level']
    risk_score = report['overall_risk_score']

    risk_color = {
        'LOW': '✓',
        'MEDIUM': '⚠',
        'HIGH': '⚠',
        'CRITICAL': '✗'
    }

    symbol = risk_color.get(risk_level, '?')
    lines.append(f"OVERALL RISK LEVEL: {symbol} {risk_level}")
    lines.append(f"Risk Score: {risk_score}/100")
    lines.append("")
    lines.append("-" * 70)
    lines.append("")

    # Risk factors breakdown
    lines.append("RISK FACTORS BREAKDOWN:")
    lines.append("")

    factors = report['risk_factors']

    # Security
    lines.append("1. SECURITY")
    security = factors['security']
    lines.append(f"   Score: {security['score']}/100")
    vuln = security['vulnerabilities']
    lines.append(f"   Known Vulnerabilities: {vuln['count']}")
    lines.append(f"   Security Policy: {'Yes' if vuln['has_security_policy'] else 'No'}")
    if vuln['count'] > 0:
        lines.append(f"   - Critical: {vuln['critical']}")
        lines.append(f"   - High: {vuln['high']}")
        lines.append(f"   - Medium: {vuln['medium']}")
        lines.append(f"   - Low: {vuln['low']}")
    lines.append("")

    # Maintenance
    lines.append("2. MAINTENANCE")
    maintenance = factors['maintenance']
    lines.append(f"   Score: {maintenance['score']}/100")
    details = maintenance['details']
    lines.append(f"   Last Commit: {details['last_commit_days_ago']} days ago")
    lines.append(f"   Open Issues: {details['open_issues']}")
    lines.append(f"   Archived: {'Yes' if details['is_archived'] else 'No'}")
    lines.append(f"   Stars: {details['stars']}")
    lines.append(f"   Forks: {details['forks']}")
    lines.append(f"   Watchers: {details['watchers']}")
    lines.append("")

    # Dependencies
    lines.append("3. DEPENDENCIES")
    dependencies = factors['dependencies']
    lines.append(f"   Score: {dependencies['score']}/100")
    dep_details = dependencies['details']
    lines.append(f"   Dependency Files: {', '.join(dep_details.get('dependency_files', [])) or 'None'}")
    lines.append(f"   Has Lock File: {'Yes' if dep_details.get('has_lock_file') else 'No'}")
    lines.append("")

    # License
    lines.append("4. LICENSE")
    license_info = factors['license']
    lines.append(f"   Score: {license_info['score']}/100")
    lic_details = license_info['details']
    lines.append(f"   License: {lic_details.get('license') or 'None'}")
    lines.append(f"   Risk Level: {lic_details.get('risk_level', 'UNKNOWN')}")
    lines.append(f"   Reason: {lic_details.get('reason', 'N/A')}")
    lines.append("")

    # Community
    lines.append("5. COMMUNITY HEALTH")
    community = factors['community']
    lines.append(f"   Score: {community['score']}/100")
    comm_details = community['details']
    lines.append(f"   README: {'Yes' if comm_details.get('has_readme') else 'No'}")
    lines.append(f"   Contributing Guide: {'Yes' if comm_details.get('has_contributing') else 'No'}")
    lines.append(f"   Code of Conduct: {'Yes' if comm_details.get('has_code_of_conduct') else 'No'}")
    lines.append(f"   Contributors: {comm_details.get('contributor_count', 0)}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("")

    # Recommendations
    lines.append("RECOMMENDATIONS:")
    lines.append("")
    for i, rec in enumerate(report['recommendations'], 1):
        lines.append(f"{i}. {rec}")

    lines.append("")
    lines.append("=" * 70)

    return "\n".join(lines)


def get_risk_emoji(level: str) -> str:
    """Get emoji representation for risk level."""
    emojis = {
        'LOW': '🟢',
        'MEDIUM': '🟡',
        'HIGH': '🟠',
        'CRITICAL': '🔴'
    }
    return emojis.get(level, '⚪')
