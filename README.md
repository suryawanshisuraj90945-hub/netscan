# NetScan

Production-grade IP discovery and availability tracking platform.

NetScan reconciles active network probes (L2 ARP, L3 ICMP, L4 TCP SYN) with managed subnet pools to track which IPs are active, quarantined, reserved, or available for allocation.

## ⚠️ Production Security Hardening

NetScan includes production security hardening. **Do not deploy without proper configuration.**

### CORS (Cross-Origin Resource Sharing)

- **Production:** `ALLOWED_ORIGINS="*"` is **rejected** at startup. Set specific origins like:
  `ALLOWED_ORIGINS="https://your-domain.com,http://localhost:8080"`
- **Development/Test:** `ALLOWED_ORIGINS="*"` is allowed when `ENVIRONMENT=development` or `ENVIRONMENT=test`
- **Configuration:** Set via `ALLOWED_ORIGINS` environment variable or `.env` file

### DEBUG mode

- **Production:** `DEBUG=True` is **rejected** at startup when `ENVIRONMENT=production`
- **Development/Test:** `DEBUG=True` is allowed when `ENVIRONMENT=development` or `ENVIRONMENT=test`
- **Configuration:** Set via `ENVIRONMENT` and `DEBUG` environment variables

### SECRET_KEY

- **Production:** `SECRET_KEY` **must be set** when `DEBUG=False`
- **Generation:** Create a strong random string (minimum 32 characters)
- **Configuration:** Set via `SECRET_KEY` environment variable or `.env` file

### DASHBOARD_PASSWORD

- **Production:** Default `admin` password is **rejected**; must be changed to a strong password
- **Configuration:** Set via `DASHBOARD_PASSWORD` environment variable or `.env` file

## Features

- **Safe Availability & Quarantine** -- Avoids naive "ping failure = free" assumptions. Unresponsive hosts enter `UNCERTAIN_FIREWALLED` and are only released after meeting both miss thresholds and quarantine duration.
- **Multi-Probe Engine** -- Auto-detects Linux capabilities for ARP/TCP SYN stealth sweeps, with fallback to unprivileged TCP Connect.
- **API-First** -- Full REST API with OpenAPI docs. Programmatic subnet management, IP provisioning queries, and per-IP audit history.
- **Outbound Webhooks** -- HMAC-SHA256 signed event notifications with full IP object snapshots.
- **In-Process Scheduler** -- Background scanning with zero external dependencies (no Redis/Celery).
- **HTMX Dashboard** -- Server-rendered CIDR matrix grid, IP inspector drawer, scan job monitor. No Node.js build step.

## Quickstart

### Requirements

- Python 3.10+
- `nmap` installed on the host (`sudo apt install nmap` on Debian/Ubuntu)

### Install & Run

```bash
pip install -e ".[test]"
uvicorn netscan.main:app --host 0.0.0.0 --port 8000 --reload
```

- Dashboard: http://localhost:8000/
- Swagger: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Docker

```bash
docker build -t netscan .
docker run -p 8000:8000 -e ENVIRONMENT=production -e SECRET_KEY=your-secret-key -e DASHBOARD_PASSWORD=your-password netscan
```

Or with docker-compose:

```yaml
services:
  netscan:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - SECRET_KEY=your-secret-key
      - DASHBOARD_PASSWORD=your-password
      - ALLOWED_ORIGINS=https://your-domain.com,http://localhost:8080
      - DATABASE_URL=sqlite:///./netscan.db
    volumes:
      - netscan-data:/app/netscan.db
```

volumes:
  netscan-data:

## Configuration

All settings are configured via environment variables or a `.env` file in the project root.

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | Set to `production` for strict security. See notes below. |
| `DEBUG` | `false` | Enable debug logging and relaxed security. Must be `false` in production. |
| `SECRET_KEY` | *(empty)* | **Required in production.** Used for session signing. Generate a strong random string. |
| `DATABASE_URL` | `sqlite:///./netscan.db` | Database connection string. Defaults to SQLite for development/postgres for production. |
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins. **`*` is rejected in production.** Set specific origins for production. |
| `DEFAULT_SCAN_INTERVAL_MINUTES` | `60` | Default scan interval per subnet |
| `DEFAULT_MISS_THRESHOLD` | `3` | Consecutive misses before uncertain state |
| `DEFAULT_QUARANTINE_HOURS` | `48` | Hours before uncertain host can become available |
| `NMAP_TIMEOUT_SECONDS` | `300` | Per-scan timeout |
| `WEBHOOK_TIMEOUT_SECONDS` | `10` | Outbound webhook timeout |
| `WEBHOOK_MAX_RETRIES` | `3` | Webhook delivery retry count |

### Production Configuration

When `ENVIRONMENT=production`:

- `DEBUG` must be `false`
- `SECRET_KEY` must be set (non-empty)
- `DASHBOARD_PASSWORD` must be set and must not be the default `admin`
- `ALLOWED_ORIGINS` must not be `"*"` — set specific origins like `https://your-domain.com,http://localhost:8080`
- Violations raise `ValueError` at startup via `Settings.validate_for_production()`

### Development Configuration

When `ENVIRONMENT=development`:

- `DEBUG` may be `true` or `false`
- `ALLOWED_ORIGINS="*"` is allowed
- `SECRET_KEY` is optional (but recommended)
- `DASHBOARD_PASSWORD` default `admin` is allowed

### Test Configuration

When `ENVIRONMENT=test`:

- `DEBUG` may be `true`
- `ALLOWED_ORIGINS="*"` is allowed
- Used for pytest suite with in-memory SQLite

## API Key Setup

All API endpoints require authentication via `X-API-Key` header. Create your first key via the bootstrap endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/auth/keys/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"name": "my-admin-key"}'
```

The response contains your `raw_key` -- store it safely, it is never shown again. Subsequent keys require an existing key:

```bash
curl -X POST http://localhost:8000/api/v1/auth/keys \
  -H "X-API-Key: <your-existing-key>" \
  -H "Content-Type: application/json" \
  -d '{"name": "automation-key", "role": "operator"}'
```

## API Examples

**Find next available IPs (for Terraform/provisioning):**

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

## Development

```bash
pip install -e ".[test]"
pytest -v
```

The test suite uses an in-memory SQLite database and does not require nmap or API keys.

## License

[MIT](LICENSE)