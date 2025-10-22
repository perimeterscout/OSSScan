"""Core scanning functionality for OSS Risk Scanner."""

import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import re


class OSSScanner:
    """Main scanner class for analyzing open-source software risks."""

    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize the OSS Scanner.

        Args:
            github_token: GitHub personal access token for API requests
        """
        self.github_token = github_token
        self.headers = {}
        if github_token:
            self.headers['Authorization'] = f'token {github_token}'

    def scan_repository(self, repo_url: str) -> Dict[str, Any]:
        """
        Scan a GitHub repository and generate a risk report.

        Args:
            repo_url: GitHub repository URL or owner/repo format

        Returns:
            Dictionary containing risk analysis results
        """
        # Parse repository owner and name
        owner, repo = self._parse_repo_url(repo_url)

        print(f"Scanning repository: {owner}/{repo}")

        # Gather data from multiple sources
        repo_data = self._get_repo_data(owner, repo)
        if not repo_data:
            return {"error": "Failed to fetch repository data"}

        vulnerabilities = self._check_vulnerabilities(owner, repo)
        maintenance_score = self._analyze_maintenance(repo_data, owner, repo)
        dependency_risk = self._analyze_dependencies(owner, repo)
        license_risk = self._analyze_license(repo_data)
        community_health = self._analyze_community(repo_data, owner, repo)

        # Calculate overall risk score
        risk_score = self._calculate_risk_score({
            'vulnerabilities': vulnerabilities,
            'maintenance': maintenance_score,
            'dependencies': dependency_risk,
            'license': license_risk,
            'community': community_health
        })

        # Generate report
        report = {
            'repository': f"{owner}/{repo}",
            'scanned_at': datetime.now().isoformat(),
            'overall_risk_score': risk_score['overall'],
            'risk_level': risk_score['level'],
            'risk_factors': {
                'security': {
                    'score': risk_score['security'],
                    'vulnerabilities': vulnerabilities
                },
                'maintenance': {
                    'score': maintenance_score['score'],
                    'details': maintenance_score['details']
                },
                'dependencies': {
                    'score': dependency_risk['score'],
                    'details': dependency_risk['details']
                },
                'license': {
                    'score': license_risk['score'],
                    'details': license_risk['details']
                },
                'community': {
                    'score': community_health['score'],
                    'details': community_health['details']
                }
            },
            'recommendations': self._generate_recommendations(risk_score, {
                'vulnerabilities': vulnerabilities,
                'maintenance': maintenance_score,
                'dependencies': dependency_risk,
                'license': license_risk,
                'community': community_health
            })
        }

        return report

    def _parse_repo_url(self, repo_url: str) -> tuple:
        """Parse GitHub repository URL to extract owner and repo name."""
        # Handle github.com URLs
        if 'github.com' in repo_url:
            match = re.search(r'github\.com/([^/]+)/([^/]+)', repo_url)
            if match:
                owner, repo = match.groups()
                repo = repo.replace('.git', '')
                return owner, repo

        # Handle owner/repo format
        if '/' in repo_url:
            parts = repo_url.split('/')
            return parts[0], parts[1]

        raise ValueError("Invalid repository URL format")

    def _get_repo_data(self, owner: str, repo: str) -> Optional[Dict]:
        """Fetch repository data from GitHub API."""
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}"
            response = requests.get(url, headers=self.headers, timeout=10)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                print(f"Repository not found: {owner}/{repo}")
            elif response.status_code == 403:
                print("API rate limit exceeded. Consider using a GitHub token.")
            else:
                print(f"Error fetching repository: {response.status_code}")

            return None
        except Exception as e:
            print(f"Error fetching repository data: {e}")
            return None

    def _check_vulnerabilities(self, owner: str, repo: str) -> Dict[str, Any]:
        """Check for known security vulnerabilities."""
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/vulnerability-alerts"
            response = requests.get(url, headers=self.headers, timeout=10)

            # GitHub Security Advisories API
            advisories_url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories"
            advisories_response = requests.get(advisories_url, headers=self.headers, timeout=10)

            vulnerabilities = {
                'count': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'advisories_enabled': response.status_code != 404,
                'has_security_policy': False
            }

            # Check for security policy
            security_url = f"https://api.github.com/repos/{owner}/{repo}/contents/SECURITY.md"
            security_response = requests.get(security_url, headers=self.headers, timeout=10)
            vulnerabilities['has_security_policy'] = security_response.status_code == 200

            return vulnerabilities
        except Exception as e:
            print(f"Error checking vulnerabilities: {e}")
            return {'count': 0, 'error': str(e)}

    def _analyze_maintenance(self, repo_data: Dict, owner: str, repo: str) -> Dict:
        """Analyze repository maintenance status."""
        try:
            # Get commit activity
            commits_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
            commits_response = requests.get(commits_url, headers=self.headers, timeout=10)

            last_commit_date = None
            commit_frequency = 0

            if commits_response.status_code == 200:
                commits = commits_response.json()
                if commits:
                    last_commit_date = commits[0]['commit']['committer']['date']
                    commit_frequency = len(commits)

            # Calculate days since last commit
            days_since_commit = 9999
            if last_commit_date:
                last_commit = datetime.fromisoformat(last_commit_date.replace('Z', '+00:00'))
                days_since_commit = (datetime.now(last_commit.tzinfo) - last_commit).days

            # Maintenance score (0-100, higher is better)
            score = 100

            # Deduct points for inactivity
            if days_since_commit > 365:
                score -= 40
            elif days_since_commit > 180:
                score -= 25
            elif days_since_commit > 90:
                score -= 10

            # Deduct points for low issue resolution
            if repo_data.get('open_issues_count', 0) > 50:
                score -= 15
            elif repo_data.get('open_issues_count', 0) > 20:
                score -= 10

            # Deduct points for archived repo
            if repo_data.get('archived', False):
                score -= 50

            score = max(0, score)

            return {
                'score': score,
                'details': {
                    'last_commit_days_ago': days_since_commit,
                    'open_issues': repo_data.get('open_issues_count', 0),
                    'is_archived': repo_data.get('archived', False),
                    'is_fork': repo_data.get('fork', False),
                    'watchers': repo_data.get('watchers_count', 0),
                    'stars': repo_data.get('stargazers_count', 0),
                    'forks': repo_data.get('forks_count', 0)
                }
            }
        except Exception as e:
            print(f"Error analyzing maintenance: {e}")
            return {'score': 50, 'details': {'error': str(e)}}

    def _analyze_dependencies(self, owner: str, repo: str) -> Dict:
        """Analyze dependency risks."""
        try:
            # Check for dependency files
            dependency_files = [
                'package.json', 'requirements.txt', 'Gemfile',
                'pom.xml', 'build.gradle', 'go.mod', 'Cargo.toml'
            ]

            found_deps = []
            for dep_file in dependency_files:
                url = f"https://api.github.com/repos/{owner}/{repo}/contents/{dep_file}"
                response = requests.get(url, headers=self.headers, timeout=10)
                if response.status_code == 200:
                    found_deps.append(dep_file)

            # Check for dependency management tools
            has_lock_file = False
            lock_files = ['package-lock.json', 'yarn.lock', 'Gemfile.lock', 'poetry.lock', 'go.sum']
            for lock_file in lock_files:
                url = f"https://api.github.com/repos/{owner}/{repo}/contents/{lock_file}"
                response = requests.get(url, headers=self.headers, timeout=10)
                if response.status_code == 200:
                    has_lock_file = True
                    break

            # Score (0-100, higher is better)
            score = 70  # Base score

            if not found_deps:
                score = 100  # No dependencies = no risk
            elif has_lock_file:
                score = 80  # Lock files are good
            else:
                score = 60  # No lock files = higher risk

            return {
                'score': score,
                'details': {
                    'dependency_files': found_deps,
                    'has_lock_file': has_lock_file,
                    'dependency_count': len(found_deps)
                }
            }
        except Exception as e:
            print(f"Error analyzing dependencies: {e}")
            return {'score': 50, 'details': {'error': str(e)}}

    def _analyze_license(self, repo_data: Dict) -> Dict:
        """Analyze license compliance risks."""
        license_info = repo_data.get('license')

        # License risk levels
        low_risk_licenses = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 'ISC']
        medium_risk_licenses = ['GPL-3.0', 'GPL-2.0', 'LGPL-3.0', 'LGPL-2.1', 'MPL-2.0']
        high_risk_licenses = ['AGPL-3.0']

        if not license_info:
            return {
                'score': 40,
                'details': {
                    'license': None,
                    'risk_level': 'HIGH',
                    'reason': 'No license found'
                }
            }

        license_key = license_info.get('spdx_id', '').upper()

        if license_key in low_risk_licenses:
            return {
                'score': 100,
                'details': {
                    'license': license_info.get('name'),
                    'spdx_id': license_key,
                    'risk_level': 'LOW',
                    'reason': 'Permissive license'
                }
            }
        elif license_key in medium_risk_licenses:
            return {
                'score': 70,
                'details': {
                    'license': license_info.get('name'),
                    'spdx_id': license_key,
                    'risk_level': 'MEDIUM',
                    'reason': 'Copyleft license - requires careful compliance'
                }
            }
        elif license_key in high_risk_licenses:
            return {
                'score': 40,
                'details': {
                    'license': license_info.get('name'),
                    'spdx_id': license_key,
                    'risk_level': 'HIGH',
                    'reason': 'Strong copyleft - network copyleft provisions'
                }
            }
        else:
            return {
                'score': 60,
                'details': {
                    'license': license_info.get('name'),
                    'spdx_id': license_key,
                    'risk_level': 'MEDIUM',
                    'reason': 'Unknown or custom license - requires review'
                }
            }

    def _analyze_community(self, repo_data: Dict, owner: str, repo: str) -> Dict:
        """Analyze community health indicators."""
        try:
            # Check for community files
            community_files = ['README.md', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md']
            found_files = []

            for file in community_files:
                url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file}"
                response = requests.get(url, headers=self.headers, timeout=10)
                if response.status_code == 200:
                    found_files.append(file)

            # Get contributor count
            contributors_url = f"https://api.github.com/repos/{owner}/{repo}/contributors"
            contributors_response = requests.get(contributors_url, headers=self.headers, timeout=10)
            contributor_count = 0
            if contributors_response.status_code == 200:
                contributor_count = len(contributors_response.json())

            # Score (0-100)
            score = 50  # Base score

            score += len(found_files) * 10  # +10 per community file

            if contributor_count > 10:
                score += 20
            elif contributor_count > 5:
                score += 10
            elif contributor_count == 0:
                score -= 20

            score = min(100, max(0, score))

            return {
                'score': score,
                'details': {
                    'community_files': found_files,
                    'has_readme': 'README.md' in found_files,
                    'has_contributing': 'CONTRIBUTING.md' in found_files,
                    'has_code_of_conduct': 'CODE_OF_CONDUCT.md' in found_files,
                    'contributor_count': contributor_count
                }
            }
        except Exception as e:
            print(f"Error analyzing community: {e}")
            return {'score': 50, 'details': {'error': str(e)}}

    def _calculate_risk_score(self, factors: Dict) -> Dict:
        """Calculate overall risk score from individual factors."""
        # Weights for each factor
        weights = {
            'security': 0.30,      # 30% - Most important
            'maintenance': 0.25,   # 25%
            'dependencies': 0.20,  # 20%
            'license': 0.15,       # 15%
            'community': 0.10      # 10%
        }

        # Get scores (convert to 0-100 scale where 100 is best)
        security_score = 100 - (factors['vulnerabilities']['count'] * 20)
        security_score = max(0, security_score)
        if not factors['vulnerabilities']['has_security_policy']:
            security_score -= 10
        security_score = max(0, min(100, security_score))

        maintenance_score = factors['maintenance']['score']
        dependency_score = factors['dependencies']['score']
        license_score = factors['license']['score']
        community_score = factors['community']['score']

        # Calculate weighted average
        overall = (
            security_score * weights['security'] +
            maintenance_score * weights['maintenance'] +
            dependency_score * weights['dependencies'] +
            license_score * weights['license'] +
            community_score * weights['community']
        )

        # Determine risk level (inverted - lower score = higher risk)
        if overall >= 80:
            level = 'LOW'
        elif overall >= 60:
            level = 'MEDIUM'
        elif overall >= 40:
            level = 'HIGH'
        else:
            level = 'CRITICAL'

        return {
            'overall': round(overall, 2),
            'level': level,
            'security': security_score,
            'maintenance': maintenance_score,
            'dependencies': dependency_score,
            'license': license_score,
            'community': community_score
        }

    def _generate_recommendations(self, risk_score: Dict, factors: Dict) -> List[str]:
        """Generate actionable recommendations based on risk analysis."""
        recommendations = []

        # Security recommendations
        if risk_score['security'] < 70:
            recommendations.append("Enable security advisories and Dependabot alerts")
            if not factors['vulnerabilities']['has_security_policy']:
                recommendations.append("Add a SECURITY.md file to define vulnerability reporting process")

        # Maintenance recommendations
        maintenance = factors['maintenance']
        if maintenance['details'].get('last_commit_days_ago', 0) > 180:
            recommendations.append("Repository appears inactive - verify it's still maintained")
        if maintenance['details'].get('is_archived'):
            recommendations.append("WARNING: Repository is archived and no longer maintained")
        if maintenance['details'].get('open_issues', 0) > 50:
            recommendations.append("High number of open issues - check if they're being addressed")

        # Dependency recommendations
        if risk_score['dependencies'] < 70:
            if not factors['dependencies']['details'].get('has_lock_file'):
                recommendations.append("Add dependency lock files for reproducible builds")
            recommendations.append("Regularly audit dependencies for vulnerabilities")

        # License recommendations
        if risk_score['license'] < 70:
            if not factors['license']['details'].get('license'):
                recommendations.append("CRITICAL: No license found - legal risk for usage")
            else:
                recommendations.append(f"Review license implications: {factors['license']['details']['reason']}")

        # Community recommendations
        if risk_score['community'] < 60:
            if not factors['community']['details'].get('has_readme'):
                recommendations.append("Add comprehensive README documentation")
            if not factors['community']['details'].get('has_contributing'):
                recommendations.append("Add CONTRIBUTING.md to encourage community involvement")

        if not recommendations:
            recommendations.append("Repository shows good health indicators")

        return recommendations
