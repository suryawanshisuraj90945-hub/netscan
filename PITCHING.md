# NetScan — Pitch Deck

## Project Overview

NetScan is a production-grade IP discovery and availability tracking platform designed for office network management. It reconciles active network probes (L2 ARP, L3 ICMP, L4 TCP SYN) with managed subnet pools to track which IPs are active, quarantined, reserved, or available for allocation.

## Problem Solved

Most network monitoring tools either:
- Are overly simplistic (just ping sweeps)
- Lack availability tracking and state history
- Require complex Node.js/JavaScript setups
- Cannot reconcile discovered hosts with managed IP pools

NetScan solves these problems with a Python-based, production-ready platform that tracks IP state transitions, enforces security policies, and provides a dashboard for visibility.

## Key Features

### IP Discovery & State Tracking
- **Safe availability logic**: Unresponsive hosts enter `UNCERTAIN_FIREWALLED`; only become available after meeting **both** the consecutive-miss threshold **and** the quarantine duration
- **Multi-probe engine**: ARP (privileged), ICMP, TCP SYN (unprivileged fallback)
- **State classifier**: Prevents premature IP reclamation with quarantine duration enforcement
- **IP history**: Full audit trail of state changes with event types and probe details

### Security Hardening (Phase 1 Completed)
- **CORS**: Production `ALLOWED_ORIGINS="*"` is rejected at startup; specific origins required
- **DEBUG**: `production + DEBUG=True` blocks startup with `ValueError`
- **SSRF**: Webhook URL validation with IP range blocking, redirect protection, fail-closed DNS
- **Authentication**: API-key via `X-API-Key` header; role-based access (ADMIN/OPERATOR/READ_ONLY)
- **Session security**: Header-only auth (no session cookies = no CSRF); `SECRET_KEY` required in production
- **Scan concurrency**: `asyncio.Semaphore(4)` limits concurrent nmap scans to prevent resource exhaustion

### API-First Design
- Full REST API with OpenAPI docs (`/docs`, `/redoc`)
- Programmatic subnet management, IP provisioning queries, per-IP audit history
- API key management with scoped roles (admin/operator/read_only)
- Bootstrap endpoint for first-key creation

### Scheduler & Webhooks
- **APScheduler** integration for recurring automated scans per subnet
- **HMAC-SHA256 signed** outbound webhook notifications with full IP object snapshots
- Bounded retry behavior with configurable max retries
- Webhook URL validation prevents SSRF redirects to private IPs

### HTMX Dashboard
- Server-rendered CIDR matrix grid, IP inspector drawer, scan job monitor
- **No Node.js build step** — purely server-rendered
- Subnet overview, IP inspector drawer, provisioner, scan history, settings
- Authentication enforced via session middleware

### Docker & Deployment
- **Dockerfile**: Python 3.12-slim, non-root user (`netscan`), nmap installed, healthcheck
- **docker-compose.yaml**: Production-ready with environment separation (`ENVIRONMENT=production/debug/test`)
- **Configuration**: `ENVIRONMENT` field enforces production requirements
- **Database**: SQLite for development/postgres for production; explicit `DATABASE_URL`

### Production Security
| Control | Status |
|---------|--------|
| CORS | `*` rejected in production; specific origins required |
| DEBUG | `True` rejected in production at startup |
| SSRF | DNS failure fail-closed; private IPs blocked; redirect validation |
| Authentication | API key required; RBAC enforced; bootstrap secure |
| Scan Concurrency | `Semaphore(4)` limits resource usage |
| Docker | Non-root user, healthcheck, minimal capabilities |

## Architecture

```
netscan/
  api/v1/           # REST endpoints: subnets.py, ips.py, scans.py, webhooks.py, auth_keys.py
  api/auth.py       # API key authentication dependency (X-API-Key header)
  scanner/          # Discovery engine:
    runner.py      #   async nmap wrapper, capability auto-detection, probe parsing
    classifier.py  #   state & quarantine heuristic classifier
    cidr.py        #   CIDR utilities
  services/
    scan_service.py       # scan job orchestration
    scheduler_service.py  # in-process APScheduler integration
    webhook_service.py    # outbound HMAC-SHA256 signed webhook dispatcher
  web/views.py     # HTMX dashboard routes (Jinja2)
  config.py        # Settings via pydantic-settings
  models.py        # SQLModel schemas (Subnet, IPAddress, ScanJob, IPHistory, Webhook, ApiKey)
  db.py            # Engine + get_session dependency
  main.py          # FastAPI app factory, lifespan, middleware, rate limiting
tests/             # pytest suite (conftest.py has shared fixtures)
alembic/           # DB migrations
```

## Production Deployment

### One-Command Install (Windows PowerShell)

```powershell
# This is the primary installer target
# The installer would:
# 1. Check operating system
# 2. Check required dependencies (Python, nmap)
# 3. Detect Docker if required
# 4. Clone/download the project
# 5. Create configuration with strong SECRET_KEY
# 6. Prompt securely for dashboard/admin password
# 7. Configure ALLOWED_ORIGINS
# 8. Configure production environment (ENVIRONMENT=production)
# 9. Start Docker Compose
# 10. Wait for health check
# 11. Verify API availability (port 8000)
# 12. Verify dashboard availability
# 13. Print final URL and next steps
```

### Docker Compose

```yaml
services:
  netscan:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - SECRET_KEY=your-strong-random-string-min-32-chars
      - DASHBOARD_PASSWORD=your-secure-password (not 'admin')
      - ALLOWED_ORIGINS=https://your-domain.com,http://localhost:8080
      - DATABASE_URL=sqlite:///./netscan.db
    volumes:
      - netscan-data:/app/netscan.db
    healthcheck:
      test: ["CMD", "python", "-c", "import httpx; r=httpx.get('http://localhost:8000/health'); r.raise_for_status()"]
      interval: 30s
      timeout: 5s
      retries: 3
    user: netscan
```

### Environment Variables

| Variable | Required? | Description |
|----------|-----------|-------------|
| `ENVIRONMENT` | Yes | `development`, `test`, or `production` |
| `DEBUG` | Yes (production) | Must be `false` in production |
| `SECRET_KEY` | Yes (production) | Strong random string, min 32 chars |
| `DATABASE_URL` | No | Defaults to `sqlite:///./netscan.db` |
| `ALLOWED_ORIGINS` | Yes (production) | Comma-separated; `*` rejected in production |
| `DASHBOARD_PASSWORD` | Yes (production) | Must not be default `admin` |
| `NMAP_TIMEOUT_SECONDS` | No | Default 300 |
| `WEBHOOK_TIMEOUT_SECONDS` | No | Default 10 |
| `WEBHOOK_MAX_RETRIES` | No | Default 3 |

### API Authentication

All API endpoints require `X-API-Key` header. Create your first key:

```bash
curl -X POST http://localhost:8000/api/v1/auth/keys/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"name": "my-admin-key"}'
```

 Subsequent keys require existing key:

```bash
curl -X POST http://localhost:8000/api/v1/auth/keys \
  -H "X-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"name": "automation-key", "role": "operator"}'
```

Roles: `admin` (full access), `operator` (scan/read), `read_only` (read-only queries).

### Dashboard Access

- `http://localhost:8000/` — Subnet & pool overview
- `http://localhost:8000/docs` — Swagger UI
- `http://localhost:8000/redoc` — ReDoc

### API Examples

**Find next available IPs:**

```bash
curl -H "X-API-Key: <key>" \
  "http://localhost:8000/api/v1/ips/available?subnet_id=<SUBNET_UUID>&count=3"
```

**Trigger a subnet scan:**

```bash
curl -X POST -H "X-API-Key: <key>" \
  http://localhost:8000/api/v1/subnets/<SUBNET_UUID>/scan
```

**Inspect IP history:**

```bash
curl -H "X-API-Key: <key>" \
  http://localhost:8000/api/v1/ips/192.168.1.50/history
```

## why NetScan?

- **Production-ready** — Security hardening, authentication, RBAC, session safety
- **No Node.js** — Pure Python, server-rendered HTMX dashboard, zero build step
- **IPv4-focused** — Accurate CIDR validation, state classification, quarantine heuristics
- **Self-hosted** — SQLite default, postgres capable; no external SaaS required
- **Purpose-built** — IP discovery + availability tracking + subnet management in one platform
- **Pytest-verified** — 105/105 tests passing, deterministic, no external dependencies

## Roadmap (Future)

- IPv6 support (optional enhancement)
- PostgreSQL clustering
- LDAP/Active Directory integration
- Advanced quota/rate limiting per API key
- Webhook retry backoff configuration
- Scanner concurrency tuning

## Contact & Support

- GitHub: https://github.com/suryawanshisuraj90945-hub/netscan
- Issues: GitHub Issues
- License: MIT

---

*NetScan — Production-grade IP discovery and availability tracking for the modern office network.*