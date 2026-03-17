#!/usr/bin/env python3
"""
Security Headers Validator - Audit HTTP security headers on any website
Checks for best practices and common vulnerabilities
"""

import requests
import argparse
import json
from typing import Dict, List, Tuple
from urllib.parse import urlparse

class SecurityHeadersValidator:
    def __init__(self, url: str):
        self.url = self._normalize_url(url)
        self.headers = {}
        self.findings = []
        self.score = 0
        
        # Define security headers and their importance
        self.security_headers = {
            'Strict-Transport-Security': {
                'importance': 'CRITICAL',
                'description': 'Forces HTTPS connections',
                'good_practice': 'max-age >= 31536000'
            },
            'Content-Security-Policy': {
                'importance': 'HIGH',
                'description': 'Prevents XSS attacks',
                'good_practice': 'Should not be "unsafe-inline"'
            },
            'X-Content-Type-Options': {
                'importance': 'HIGH',
                'description': 'Prevents MIME type sniffing',
                'good_practice': 'Should be "nosniff"'
            },
            'X-Frame-Options': {
                'importance': 'HIGH',
                'description': 'Prevents clickjacking',
                'good_practice': 'Should be "DENY" or "SAMEORIGIN"'
            },
            'X-XSS-Protection': {
                'importance': 'MEDIUM',
                'description': 'Legacy XSS protection (outdated)',
                'good_practice': 'Should be "1; mode=block"'
            },
            'Referrer-Policy': {
                'importance': 'MEDIUM',
                'description': 'Controls referrer information',
                'good_practice': 'Should be "strict-origin-when-cross-origin"'
            },
            'Permissions-Policy': {
                'importance': 'MEDIUM',
                'description': 'Controls browser features',
                'good_practice': 'Should restrict geolocation, microphone, etc.'
            }
        }
    
    def _normalize_url(self, url: str) -> str:
        """Add https:// if no protocol specified"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def scan(self) -> bool:
        """Fetch headers from the URL"""
        try:
            print(f"Scanning: {self.url}")
            response = requests.get(self.url, timeout=10, allow_redirects=True)
            self.headers = dict(response.headers)
            return True
        except requests.exceptions.Timeout:
            print(f"❌ Error: Request timed out")
            return False
        except requests.exceptions.ConnectionError:
            print(f"❌ Error: Could not connect to {self.url}")
            return False
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            return False
    
    def analyze(self):
        """Analyze headers and generate findings"""
        points_per_header = 100 / len(self.security_headers)
        
        for header, config in self.security_headers.items():
            if header in self.headers:
                value = self.headers[header]
                self.findings.append({
                    'header': header,
                    'status': 'PRESENT',
                    'value': value[:60] + '...' if len(value) > 60 else value,
                    'importance': config['importance'],
                    'description': config['description']
                })
                self.score += points_per_header
            else:
                self.findings.append({
                    'header': header,
                    'status': 'MISSING',
                    'value': 'Not set',
                    'importance': config['importance'],
                    'description': config['description']
                })
        
        # Check for bad practices
        self._check_bad_practices()
    
    def _check_bad_practices(self):
        """Check for common security mistakes"""
        if 'Content-Security-Policy' in self.headers:
            csp = self.headers['Content-Security-Policy']
            if 'unsafe-inline' in csp:
                self.findings.append({
                    'header': 'Content-Security-Policy',
                    'status': 'BAD PRACTICE',
                    'value': 'Contains "unsafe-inline"',
                    'importance': 'CRITICAL',
                    'description': 'Allows inline scripts - defeats CSP purpose'
                })
                self.score -= 10
        
        if 'X-Frame-Options' in self.headers:
            xfo = self.headers['X-Frame-Options']
            if xfo not in ['DENY', 'SAMEORIGIN']:
                self.findings.append({
                    'header': 'X-Frame-Options',
                    'status': 'BAD VALUE',
                    'value': xfo,
                    'importance': 'HIGH',
                    'description': 'Should be DENY or SAMEORIGIN'
                })
                self.score -= 5
    
    def generate_report(self, output_format: str = 'text', output_file: str = None):
        """Generate report in specified format"""
        if output_format == 'json':
            report = self._generate_json_report()
        else:
            report = self._generate_text_report()
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {output_file}")
        else:
            print(report)
    
    def _generate_text_report(self) -> str:
        """Generate human-readable text report"""
        lines = []
        lines.append("\n" + "=" * 70)
        lines.append("🔒 SECURITY HEADERS AUDIT REPORT")
        lines.append("=" * 70)
        lines.append(f"\nURL: {self.url}\n")
        
        # Security Score
        score_color = "🟢" if self.score >= 80 else "🟡" if self.score >= 60 else "🔴"
        lines.append(f"{score_color} Security Score: {self.score}/100\n")
        
        # Critical Missing Headers
        critical_missing = [f for f in self.findings 
                          if f['status'] == 'MISSING' and f['importance'] == 'CRITICAL']
        if critical_missing:
            lines.append("RITICAL - Missing Headers:")
            for finding in critical_missing:
                lines.append(f"   • {finding['header']}")
                lines.append(f"     {finding['description']}")
            lines.append("")
        
        # High Priority Issues
        high_issues = [f for f in self.findings 
                      if f['importance'] == 'HIGH' and f['status'] in ['MISSING', 'BAD PRACTICE', 'BAD VALUE']]
        if high_issues:
            lines.append("HIGH PRIORITY - Issues:")
            for finding in high_issues:
                lines.append(f"   • {finding['header']}")
                lines.append(f"     Status: {finding['status']}")
                if finding['value'] != 'Not set':
                    lines.append(f"     Value: {finding['value']}")
            lines.append("")
        
        # Present Headers
        present = [f for f in self.findings if f['status'] == 'PRESENT']
        if present:
            lines.append("PRESENT - Good Security Headers:")
            for finding in present:
                lines.append(f"   • {finding['header']}")
            lines.append("")
        
        lines.append("=" * 70)
        lines.append("\nRecommendations:")
        lines.append("1. Implement all CRITICAL headers")
        lines.append("2. Set Strict-Transport-Security with max-age >= 1 year")
        lines.append("3. Use strong Content-Security-Policy (no unsafe-inline)")
        lines.append("4. Enable X-Frame-Options and X-Content-Type-Options")
        lines.append("\n" + "=" * 70 + "\n")
        
        return "\n".join(lines)
    
    def _generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            'url': self.url,
            'score': self.score,
            'findings': self.findings
        }
        return json.dumps(report, indent=2)


def main():
    parser = argparse.ArgumentParser(description='Security Headers Validator - Audit HTTP security headers')
    parser.add_argument('--url', '-u', required=True, help='URL to scan')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', '-f', choices=['text', 'json'], default='text', help='Output format')
    
    args = parser.parse_args()
    
    validator = SecurityHeadersValidator(args.url)
    
    if not validator.scan():
        return 1
    
    validator.analyze()
    validator.generate_report(output_format=args.format, output_file=args.output)
    
    return 0 if validator.score >= 80 else 1


if __name__ == "__main__":
    exit(main())