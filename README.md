<p align="center">
  <h1 align="center">NetScan</h1>
  <p align="center">Production-grade IP discovery and availability tracking platform</p>
</p>

<p align="center">
  <a href="https://github.com/suryawanshisuraj90945-hub/netscan/actions/workflows/ci.yml"><img src="https://github.com/suryawanshisuraj90945-hub/netscan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/suryawanshisuraj90945-hub/netscan/releases"><img src="https://img.shields.io/github/v/release/suryawanshisuraj90945-hub/netscan" alt="Release"></a>
  <a href="https://github.com/suryawanshisuraj90945-hub/netscan/blob/main/LICENSE"><img src="https://img.shields.io/github/license/suryawanshisuraj90945-hub/netscan" alt="License"></a>
  <a href="https://github.com/suryawanshisuraj90945-hub/netscan/pkgs/container/netscan"><img src="https://img.shields.io/badge/container-GHCR-blue" alt="GHCR"></a>
</p>

---

NetScan reconciles active network probes (L2 ARP, L3 ICMP, L4 TCP SYN) with managed subnet pools to track which IPs are active, quarantined, reserved, or available for allocation.

## Features

- **Safe Availability & Quarantine** -- Unresponsive hosts enter `UNCERTAIN_FIREWALLED` and are only released after meeting both miss thresholds and quarantine duration. No naive "ping failed = free."
- **Multi-Probe Engine** -- Auto-detects Linux capabilities for ARP/TCP SYN stealth sweeps, with fallback to unprivileged TCP Connect.
- **API-First** -- Full REST API with OpenAPI docs. Programmatic subnet management, IP provisioning queries, per-IP audit history.
- **Outbound Webhooks** -- HMAC-SHA256 signed event notifications with full IP object snapshots.
- **In-Process Scheduler** -- Background scanning with zero external dependencies (no Redis/Celery).
- **HTMX Dashboard** -- Server-rendered CIDR matrix grid, IP inspector drawer, scan job monitor. No Node.js build step.
- **Production Security** -- CORS enforcement, DEBUG protection, SSRF blocking, API-key auth with RBAC, scan concurrency limits.

## Quick Start

### Docker (Recommended)

```bash
docker pull ghcr.io/suryawanshisuraj90945-hub/netscan:latest
```

```bash
docker run -d -p 8000:8000 --name netscan \
  -e ENVIRONMENT=production \
  -e DEBUG=false \
  -e SECRET_KEY=your-strong-random-string-min-32-chars \
  -e DASHBOARD_PASSWORD=your-secure-password \
  -e ALLOWED_ORIGINS=http://localhost:8000 \
  ghcr.io/suryawanshisuraj90945-hub/netscan:latest
```

### Docker Compose

```bash
git clone https://github.com/suryawanshisuraj90945-hub/netscan.git
cd netscan
docker compose up -d
```

### From Source

```bash
git clone https://github.com/suryawanshisuraj90945-hub/netscan.git
cd netscan
pip install -e ".[test]"
uvicorn netscan.main:app --host 0.0.0.0 --port 8000 --reload
```

### Requirements

- Python 3.10+
- `nmap` installed on host (`sudo apt install nmap` on Debian/Ubuntu)

## Dashboard

| Page | URL |
|------|-----|
| Dashboard | http://localhost:8000/ |
| Swagger UI | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| Health Check | http://localhost:8000/health |

## Configuration

All settings are configured via environment variables or a `.env` file.

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | `production`, `development`, or `test` |
| `DEBUG` | `false` | Debug logging. Must be `false` in production |
| `SECRET_KEY` | *(empty)* | **Required in production.** Session signing key |
| `DATABASE_URL` | `sqlite:///./netscan.db` | Database connection string |
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins. **`*` rejected in production** |
| `DEFAULT_SCAN_INTERVAL_MINUTES` | `60` | Default scan interval per subnet |
| `DEFAULT_MISS_THRESHOLD` | `3` | Consecutive misses before uncertain state |
| `DEFAULT_QUARANTINE_HOURS` | `48` | Hours before uncertain host can become available |
| `NMAP_TIMEOUT_SECONDS` | `300` | Per-scan timeout |
| `WEBHOOK_TIMEOUT_SECONDS` | `10` | Outbound webhook timeout |
| `WEBHOOK_MAX_RETRIES` | `3` | Webhook delivery retry count |

### Production Requirements

When `ENVIRONMENT=production`, startup **fails** if:

- `DEBUG=True`
- `SECRET_KEY` is empty
- `DASHBOARD_PASSWORD` is default `admin`
- `ALLOWED_ORIGINS="*"`

## API Key Setup

All API endpoints require authentication via `X-API-Key` header.

```bash
# Bootstrap first key
curl -X POST http://localhost:8000/api/v1/auth/keys/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"name": "admin-key"}'
```

Roles: `admin` (full), `operator` (scan/read), `read_only` (read-only queries).

## API Examples

```bash
# Find next available IPs
curl -H "X-API-Key: <key>" \
  "http://localhost:8000/api/v1/ips/available?subnet_id=<ID>&count=3"

# Trigger a subnet scan
curl -X POST -H "X-API-Key: <key>" \
  http://localhost:8000/api/v1/subnets/<ID>/scan

# Inspect IP history
curl -H "X-API-Key: <key>" \
  http://localhost:8000/api/v1/ips/192.168.1.50/history
```

## Development

```bash
pip install -e ".[test]"
pytest -v
```

Tests use an in-memory SQLite database -- no nmap or API keys required.

## Architecture

```
netscan/
  api/v1/          # REST endpoints: subnets, ips, scans, webhooks, auth_keys
  api/auth.py      # API key authentication (X-API-Key header)
  scanner/         # nmap runner, CIDR utils, classifier
  services/        # scan scheduler, webhook dispatcher
  web/             # HTMX dashboard, Jinja2 templates
  config.py        # Settings via pydantic-settings
  models.py        # SQLModel schemas
  main.py          # FastAPI app, lifespan, middleware
tests/             # pytest suite
alembic/           # Database migrations
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, style, and submission guide.

## License

[MIT](LICENSE)
