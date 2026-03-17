# Security Headers Validator

Audit HTTP security headers on any website and get a security score. Identifies missing headers, bad practices, and compliance issues.

## The Problem

70% of websites have misconfigured or missing security headers. This leads to:
- Clickjacking attacks (missing X-Frame-Options)
- XSS vulnerabilities (weak Content-Security-Policy)
- MIME type sniffing (missing X-Content-Type-Options)
- Missing HTTPS enforcement (no Strict-Transport-Security)

## Features

- Checks 7+ critical security headers
- Generates security score (0-100)
- Detects common bad practices
- JSON and text output formats
- Works with any public website
- No authentication required

## Quick Start

### Option 1: Local Run

Clone the repo:

    git clone https://github.com/0WDA/security-headers-validator.git
    cd security-headers-validator

Run the validator:

    python security_headers_validator.py --url https://example.com

### Option 2: Docker

Build the image:

    docker build -t security-headers-validator .

Run against a website:

    docker run security-headers-validator --url https://example.com

## Usage Examples

### Basic scan

    python security_headers_validator.py --url google.com

### Save results as JSON

    python security_headers_validator.py --url amazon.com --format json --output report.json

### Scan multiple sites

    for site in google.com amazon.com github.com; do
        python security_headers_validator.py --url $site
    done

## Headers Checked

- **Strict-Transport-Security** - Forces HTTPS connections
- **Content-Security-Policy** - Prevents XSS attacks
- **X-Content-Type-Options** - Prevents MIME type sniffing
- **X-Frame-Options** - Prevents clickjacking
- **X-XSS-Protection** - Legacy XSS protection
- **Referrer-Policy** - Controls referrer information
- **Permissions-Policy** - Controls browser features


## Why This Tool?

- **Simple:** One command, one URL. That's it.
- **Fast:** Gets results instantly
- **Practical:** Focuses on real security issues, not false positives
- **Insightful:** Shows what's missing AND what's misconfigured
- **Shareable:** Generate reports to share with teams

## Research Ideas

Scan popular websites and find security issues:

    python security_headers_validator.py --url microsoft.com
    python security_headers_validator.py --url apple.com
    python security_headers_validator.py --url forbes.com

Post results on LinkedIn: "Audited 50 Fortune 500 websites. Only X% have proper security headers."

## Roadmap

- Browser extension version
- Continuous monitoring for website changes
- Export reports as PDF
- Compare security scores across competitors
- Integration with CI/CD pipelines

## Contributing

Pull requests welcome! Ideas:
- Add more headers to check
- DNSSEC validation
- Certificate transparency checks
- HTTP/2 security validation

## License

MIT License

---

**Author:** Alejandro González García-Loygorri  
AppSec Engineer | CRTE • eCPPTv2  
[LinkedIn](https://linkedin.com/in/alejandro-gonzalez-garcia-loygorri) | [GitHub](https://github.com/0WDA)
