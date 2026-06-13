# HAProxy Guard host agent

Closes the deploy loop for a real HAProxy instance — running either as a
**systemd service** or a **Docker container**. The agent heartbeats the Guard
control plane. When a new desired config is published it validates it with
`haproxy -c`, writes it to disk, reloads HAProxy, and reports the new version
back.

Self-contained (standard library only) — copy it to any host; no extra packages
needed beyond `python3` and the `haproxy` binary (or `docker`).

## Quick start — systemd mode

```bash
# 1. Enroll the node in Guard (Cluster tab → Enroll, or via API).
#    Save the node id and one-time token.

# 2. Drop the agent and its config on the host (as root):
sudo mkdir -p /opt/haproxy-guard
sudo cp haproxy_guard_agent.py /opt/haproxy-guard/
sudo cp haproxy-guard-agent.env.example /etc/haproxy-guard-agent.env
sudo "$EDITOR" /etc/haproxy-guard-agent.env        # fill in GUARD_URL / NODE_ID / NODE_TOKEN

# 3. Install and start the service:
sudo cp haproxy-guard-agent.service /etc/systemd/system/
# Edit the service file: uncomment the systemd-mode After= line, comment the Docker one.
sudo systemctl daemon-reload
sudo systemctl enable --now haproxy-guard-agent
sudo journalctl -u haproxy-guard-agent -f          # watch it
```

## Quick start — Docker mode

Use this when HAProxy itself runs as a Docker container on the same host.

```bash
# 1. Start the production HAProxy container (from the HaproxyGuard repo):
cd /path/to/HaproxyGuard
docker compose --profile prod up -d haproxy-prod

# 2. Enroll the node, copy agent files (as root):
sudo mkdir -p /opt/haproxy-guard /etc/haproxy
sudo cp haproxy_guard_agent.py /opt/haproxy-guard/
sudo cp haproxy-guard-agent.env.example /etc/haproxy-guard-agent.env
sudo "$EDITOR" /etc/haproxy-guard-agent.env

# 3. Edit the env file — set MANAGE_MODE=docker:
#     MANAGE_MODE=docker
#     CONTAINER_NAME=haproxy-prod
#     CONTAINER_CFG_PATH=/usr/local/etc/haproxy/haproxy.cfg
#     HAPROXY_CFG=/etc/haproxy/haproxy.cfg

# 4. Install and start the service:
sudo cp haproxy-guard-agent.service /etc/systemd/system/
# Edit the service: uncomment the Docker-mode After= line.
sudo systemctl daemon-reload
sudo systemctl enable --now haproxy-guard-agent
sudo journalctl -u haproxy-guard-agent -f
```

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GUARD_URL` | **yes** | – | Control plane base URL (`http://guard.local:8000`) |
| `NODE_ID` | **yes** | – | Node id from enrollment |
| `NODE_TOKEN` | **yes** | – | Bearer token from enrollment |
| `MANAGE_MODE` | no | `systemd` | `systemd` or `docker` |
| `HAPROXY_CFG` | no | `/etc/haproxy/haproxy.cfg` | Config file path on host |
| `INTERVAL` | no | `10` | Seconds between heartbeats |
| `AGENT_VERSION` | no | `2.0.0` | Reported agent version |

### systemd mode only

| Variable | Default | Description |
|---|---|---|
| `HAPROXY_BIN` | `haproxy` (from PATH) | HAProxy binary |
| `RELOAD_CMD` | `systemctl reload haproxy` | Reload command |

### Docker mode only

| Variable | Default | Description |
|---|---|---|
| `CONTAINER_NAME` | `haproxy` | Docker container name |
| `CONTAINER_CFG_PATH` | `/usr/local/etc/haproxy/haproxy.cfg` | Config path inside container |

## How a deploy flows

```
Guard UI (Cluster → Deploy)  →  control plane stores desired config (version N)
        agent heartbeat       →  control plane replies with desired_config
        agent: haproxy -c      →  ok?
        agent: write + reload  →  systemd: write file, systemctl reload
                                  Docker:  write file, docker cp, docker kill -s HUP
        next heartbeat (vN)    →  control plane marks the deployment "applied"
```

A backup is saved to `<cfg_path>.guard.bak` before each write (both modes).
If validation fails, the agent keeps the running config and the deployment stays
"pending" in the dashboard — a bad push never takes the service down.

## Docker mode internals

When `MANAGE_MODE=docker`:

1. **validate**: config is written to a temp file, `docker cp`'d into the
   container, then `docker exec … haproxy -c -f <temp>` runs inside. The temp
   file is cleaned up afterwards.
2. **apply**: config is written to the host path (`HAPROXY_CFG`), `docker cp`'d
   to the container path (`CONTAINER_CFG_PATH`), then `docker kill -s HUP`
   triggers HAProxy's graceful reload.
3. **version**: `docker exec … haproxy -v`

The production HAProxy container is defined in the repo's `docker-compose.yml`
under `haproxy-prod` (profile `prod`).

## Security notes

- The token authenticates the node to the control plane; keep the env file
  `chmod 600` and root-owned.
- The agent must run as root to write `/etc/haproxy`, run `systemctl`, and
  access the Docker socket (`docker exec`, `docker cp`, `docker kill`).
- Prefer HTTPS for `GUARD_URL` in production (terminate TLS in front of the API).
