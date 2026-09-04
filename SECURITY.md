# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in NetScan, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email the maintainers directly with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Security Design

NetScan includes the following security controls:

- **CORS**: Production rejects `ALLOWED_ORIGINS="*"`; specific origins required
- **DEBUG**: Production rejects `DEBUG=True` at startup
- **SSRF Protection**: DNS failure is fail-closed; private IPs, loopback, and link-local ranges blocked; redirect validation prevents SSRF via redirects
- **Authentication**: API key via `X-API-Key` header; RBAC (admin/operator/read_only)
- **Scan Concurrency**: `asyncio.Semaphore` limits concurrent nmap scans
- **Webhook Signing**: HMAC-SHA256 signed outbound payloads

## Response Timeline

- Acknowledgment within 48 hours
- Assessment within 1 week
- Fix release timeline based on severity
