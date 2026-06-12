# HAProxy Guard

HAProxy Guard is an open-source web platform for managing, visualizing, securing and troubleshooting HAProxy deployments.

It combines:
- Real-time monitoring
- Configuration management
- Security analysis
- SSL certificate management
- Automatic configuration validation
- AI-powered recommendations
- One-click fixes

into a single interface.

## Features

### Dashboard
- Requests per second
- Active connections
- Backend availability
- Response times
- HTTP status distribution
- Traffic per backend
- Error rates
- Health check history

### Topology View
Internet → Frontend → ACL → Backend → Servers

### Configuration Management
- Create Frontends
- Create Backends
- Add / Remove Servers
- Configure ACLs
- Configure SSL
- Configure Timeouts
- Configure Health Checks
- Configure Load Balancing Algorithms

### Configuration Analyzer
Detect:
- Unused Backends
- Duplicate Bind Ports
- Missing Health Checks
- Invalid ACL Chains
- Unreachable Rules
- Weak SSL Configurations
- Missing Rate Limiting
- Dangerous Timeouts
- Statistics Endpoint Exposure
- Deprecated Directives

### Auto Fix Engine
Review → Approve → Apply suggested fixes safely.

### Security Center
- DDoS Protection
- Whitelist / Blacklist
- Country Restrictions
- Administrative Access Rules

### SSL Certificate Management
- Expiration monitoring
- TLS version analysis
- Cipher analysis
- Certificate deployment

### Validation Pipeline
1. Backup configuration
2. Generate changes
3. Run HAProxy validation
4. Apply changes
5. Reload HAProxy
6. Verify health

### Architecture
Frontend:
- React
- TypeScript
- Tailwind

Backend:
- FastAPI
- PostgreSQL
- SQLAlchemy
- Alembic

Deployment:
- Docker
- Docker Compose

## Quick start (Docker)

The whole platform — API + web UI — runs with one command:

```bash
docker compose up --build
```

Then open **http://localhost:8080** (the nginx-served React UI; it proxies `/api`
and the metrics WebSocket to the API container). The API is also exposed directly
on http://localhost:8000.

Optional environment variables (a `.env` file next to `docker-compose.yml` works):

| Variable | Effect |
|---|---|
| `ANTHROPIC_API_KEY` | Enables the AI Assistant's written narrative (otherwise heuristic-only) |
| `HG_ADMIN_KEY` | Bootstraps an admin principal and switches RBAC into enforcing mode |
| `HAPROXY_STATS_ADDR` | Runtime stats socket for the live Dashboard (e.g. `127.0.0.1:9999`) |
| `HG_WEB_PORT` / `HG_API_PORT` | Override the host ports (default 8080 / 8000) |

The API image bundles the `haproxy` binary, so `haproxy -c` validation (auto-fix
and cluster deploys) runs for real inside the container.

## Development

Backend (FastAPI, port 8000):
```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/uvicorn app.main:app --reload
.venv/bin/pytest            # run tests
```

Frontend (Vite dev server, port 5173, proxies /api to the backend):
```bash
cd frontend
npm install
npm run dev                 # set HG_API_URL to override the API target
```

Live dashboard (dev HAProxy + echo backends in Docker):
```bash
docker compose --profile dev up -d haproxy echo1 echo2
HAPROXY_STATS_ADDR=127.0.0.1:9999 .venv/bin/uvicorn app.main:app   # from backend/
curl localhost:18080/        # generate some traffic
```
The Dashboard tab streams `show stat` snapshots over `/api/ws/metrics`.

## License
Apache 2.0
