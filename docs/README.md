# Architecture

HAProxy Guard is a monorepo with three main components:

```
                    ┌──────────────────┐
                    │   Browser (UI)   │
                    │   React + TS     │
                    │   port 8080      │
                    └────────┬─────────┘
                             │ HTTP/WS
                    ┌────────▼─────────┐
                    │    nginx         │
                    │  Serves React    │
                    │  Proxies /api    │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              ▼              │
              │    ┌──────────────┐         │
              │    │  FastAPI     │         │
              │    │  port 8000   │         │
              │    └──────┬───────┘         │
              │           │                 │
              │    ┌──────▼───────┐         │
              │    │  PostgreSQL  │         │
              │    │  (primary)   │         │
              │    └──────────────┘         │
              │                             │
              │  ┌──────────────────────┐   │
              │  │  HAProxy (managed)   │   │
              │  │  systemd or Docker   │   │
              │  └──────────┬───────────┘   │
              │             │               │
              │  ┌──────────▼───────────┐   │
              │  │  Host Agent          │   │
              │  │  Heartbeat + Deploy  │   │
              │  └──────────────────────┘   │
              └─────────────────────────────┘
```

## Backend modules

| Module | Purpose |
|---|---|
| `parser` | Parse haproxy.cfg → typed Python models |
| `analyzer` | 40+ rule-based config checks (security, TLS, performance, …) |
| `autofix` | Dry-run + apply + rollback for fixable findings |
| `sslmgr` | X.509 parsing, cipher grading, expiry tracking |
| `security` | DDoS/rate-limit/geo-block preset generator |
| `assistant` | Heuristic + LLM (Anthropic) root-cause analysis |
| `cluster` | Multi-node registry with agent heartbeat loop |
| `alerts` | Evaluate + dispatch (webhook/Slack) |
| `authz` | RBAC (viewer/operator/admin) + audit log |
| `versions` | Git-like config versioning + unified diff |
| `metrics` | Stats socket client + WebSocket streaming |

## Deployment modes

### Standalone (Docker Compose)
```bash
docker compose up --build
# UI → http://localhost:8080
# API → http://localhost:8000
```

### With a managed HAProxy (Docker)
```bash
docker compose --profile prod up -d haproxy-prod
# Then run the host agent with MANAGE_MODE=docker
```

### With a managed HAProxy (systemd)
```bash
# Install the agent on the HAProxy host
# Set MANAGE_MODE=systemd
```

See [`scripts/README.md`](../scripts/README.md) for agent setup.

## Key design decisions

- **Round-trip safe parser**: every directive keeps its raw text; unknown
  directives are preserved, not dropped.
- **Rules as data**: analyzer rules are plain `@rule`-decorated functions;
  community contributions are a single file.
- **Open-mode by default**: no RBAC until `HG_ADMIN_KEY` is set — then
  enforcing mode kicks in and every endpoint requires a token.
- **Real validation**: the Docker image bundles `haproxy` so `haproxy -c`
  validation runs with the actual binary, not a parser approximation.
