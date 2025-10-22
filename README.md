# OSS Risk Scanner

A comprehensive tool for analyzing open-source software and providing security and maintenance risk ratings.

## Features

OSS Risk Scanner evaluates repositories across multiple dimensions:

- **Security Analysis**: Detects known vulnerabilities, checks for security policies
- **Maintenance Health**: Evaluates commit activity, issue management, and archive status
- **Dependency Management**: Analyzes dependency files and lock file usage
- **License Compliance**: Assesses license types and associated legal risks
- **Community Health**: Reviews documentation, contributor activity, and community files

## Installation

### From Source

```bash
git clone https://github.com/perimeterscout/OSSScan.git
cd OSSScan
pip install -r requirements.txt
pip install -e .
```

### Using pip (once published)

```bash
pip install oss-risk-scanner
```

## Usage

### Command Line Interface

Basic usage:

```bash
# Scan a repository by URL
oss-scan https://github.com/owner/repo

# Scan using owner/repo format
oss-scan owner/repo

# Use a GitHub token for higher API rate limits
oss-scan owner/repo --token YOUR_GITHUB_TOKEN

# Or set token as environment variable
export GITHUB_TOKEN=your_token_here
oss-scan owner/repo

# Output as JSON
oss-scan owner/repo --output json

# Save report to file
oss-scan owner/repo --output-file report.json
```

### Python API

```python
from oss_scanner import OSSScanner

# Initialize scanner
scanner = OSSScanner(github_token="your_token_here")

# Scan a repository
report = scanner.scan_repository("owner/repo")

# Access risk score
print(f"Risk Level: {report['risk_level']}")
print(f"Overall Score: {report['overall_risk_score']}/100")

# Access detailed factors
security = report['risk_factors']['security']
maintenance = report['risk_factors']['maintenance']
print(f"Security Score: {security['score']}")
print(f"Maintenance Score: {maintenance['score']}")

# Get recommendations
for rec in report['recommendations']:
    print(f"- {rec}")
```

## Risk Assessment Methodology

### Overall Risk Score (0-100)

The overall risk score is calculated as a weighted average of five key factors:

- **Security** (30%): Vulnerability count, security policies
- **Maintenance** (25%): Activity level, issue management, archive status
- **Dependencies** (20%): Dependency management practices
- **License** (15%): License type and compliance implications
- **Community** (10%): Documentation, contributor activity

### Risk Levels

- **LOW** (80-100): Minimal risk, well-maintained project
- **MEDIUM** (60-79): Moderate risk, some concerns to address
- **HIGH** (40-59): Significant risks, careful evaluation needed
- **CRITICAL** (0-39): Severe risks, avoid or use with extreme caution

### Security Assessment

Evaluates:
- Known vulnerabilities from GitHub Security Advisories
- Presence of SECURITY.md policy
- Severity distribution (Critical, High, Medium, Low)

### Maintenance Assessment

Considers:
- Days since last commit
- Open issue count
- Repository archive status
- Community engagement (stars, forks, watchers)

### Dependency Assessment

Analyzes:
- Presence of dependency files (package.json, requirements.txt, etc.)
- Lock file usage for reproducible builds
- Dependency management practices

### License Assessment

Risk levels by license type:
- **Low Risk**: MIT, Apache-2.0, BSD licenses (permissive)
- **Medium Risk**: GPL, LGPL, MPL (copyleft, requires compliance)
- **High Risk**: AGPL (strong copyleft with network provisions)
- **Critical**: No license (legal risks for usage)

### Community Health Assessment

Evaluates:
- README.md presence and quality
- CONTRIBUTING.md for contribution guidelines
- CODE_OF_CONDUCT.md for community standards
- Number of active contributors

## GitHub API Rate Limits

The scanner uses the GitHub API, which has rate limits:

- **Unauthenticated**: 60 requests/hour
- **Authenticated**: 5,000 requests/hour

**Recommendation**: Use a GitHub personal access token for better rate limits.

### Creating a GitHub Token

1. Go to GitHub Settings > Developer settings > Personal access tokens
2. Generate new token (classic)
3. Select scopes: `public_repo` (or `repo` for private repos)
4. Copy token and use with `--token` flag or `GITHUB_TOKEN` environment variable

## Exit Codes

- `0`: Success, LOW risk
- `1`: MEDIUM or HIGH risk detected
- `2`: CRITICAL risk detected
- `130`: Cancelled by user

## Examples

### Example 1: Scanning a popular project

```bash
$ oss-scan facebook/react

======================================================================
OSS RISK SCANNER REPORT
======================================================================

Repository: facebook/react
Scanned at: 2025-10-22T13:58:00

OVERALL RISK LEVEL: ✓ LOW
Risk Score: 85.5/100

----------------------------------------------------------------------

RISK FACTORS BREAKDOWN:

1. SECURITY
   Score: 90/100
   Known Vulnerabilities: 0
   Security Policy: Yes

2. MAINTENANCE
   Score: 95/100
   Last Commit: 2 days ago
   Open Issues: 50
   Stars: 200000
   Forks: 45000

[...]
```

### Example 2: JSON output for automation

```bash
$ oss-scan owner/repo --output json > report.json
```

### Example 3: CI/CD Integration

```bash
#!/bin/bash
# Scan dependencies and fail if CRITICAL or HIGH risk

oss-scan dependency/repo
exit_code=$?

if [ $exit_code -eq 2 ]; then
    echo "CRITICAL risk detected - blocking deployment"
    exit 1
elif [ $exit_code -eq 1 ]; then
    echo "WARNING: Risk detected - review required"
fi
```

## Limitations

- **GitHub Only**: Currently supports only GitHub repositories
- **Public Repos**: Best results with public repositories
- **API Dependent**: Requires internet connection and GitHub API availability
- **Surface Analysis**: Does not perform deep code analysis or static analysis
- **Snapshot in Time**: Risk assessment is based on current state

## Future Enhancements

- Support for GitLab, Bitbucket, and other platforms
- Deep code analysis and vulnerability scanning
- Historical trend analysis
- Custom risk scoring policies
- Package registry integration (npm, PyPI, etc.)
- SBOM (Software Bill of Materials) generation
- CI/CD platform integrations

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

MIT License - see LICENSE file for details


## Disclaimer

This tool provides risk assessments based on publicly available information. It should be used as part of a comprehensive security and risk management strategy, not as the sole decision-making factor.
