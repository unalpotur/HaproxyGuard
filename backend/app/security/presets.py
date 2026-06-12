"""Named bundles of security controls."""
from __future__ import annotations

from .models import ControlRequest, PresetSpec

PRESETS: dict[str, PresetSpec] = {
    "basic": PresetSpec(
        id="basic", name="Basic protection",
        description="Sensible defaults for a typical web app: request rate limiting "
                    "and slowloris mitigation.",
        controls=[
            ControlRequest(id="request_rate", params={"rate": 100, "window": "10s"}),
            ControlRequest(id="slowloris"),
        ],
    ),
    "strict": PresetSpec(
        id="strict", name="Strict hardening",
        description="Aggressive rate, connection and error limits plus slowloris "
                    "protection for high-risk endpoints.",
        controls=[
            ControlRequest(id="request_rate", params={"rate": 50, "window": "10s"}),
            ControlRequest(id="connection_rate", params={"rate": 30, "window": "3s"}),
            ControlRequest(id="concurrent_connections", params={"max": 30}),
            ControlRequest(id="error_rate", params={"rate": 15, "window": "10s"}),
            ControlRequest(id="slowloris"),
        ],
    ),
    "api": PresetSpec(
        id="api", name="API gateway",
        description="Higher request budget with concurrency caps and an admin allowlist.",
        controls=[
            ControlRequest(id="request_rate", params={"rate": 200, "window": "10s"}),
            ControlRequest(id="concurrent_connections", params={"max": 100}),
            ControlRequest(id="admin_protection"),
        ],
    ),
    "ddos-mitigation": PresetSpec(
        id="ddos-mitigation", name="DDoS mitigation",
        description="Connection-rate, concurrency and slowloris defenses tuned to "
                    "absorb volumetric/slow attacks.",
        controls=[
            ControlRequest(id="connection_rate", params={"rate": 20, "window": "3s"}),
            ControlRequest(id="concurrent_connections", params={"max": 40}),
            ControlRequest(id="request_rate", params={"rate": 80, "window": "10s"}),
            ControlRequest(id="slowloris", params={"timeout": "4s"}),
        ],
    ),
    "public-web": PresetSpec(
        id="public-web", name="Public website",
        description="Balanced protection for a public site including geo blocking scaffolding.",
        controls=[
            ControlRequest(id="request_rate", params={"rate": 120, "window": "10s"}),
            ControlRequest(id="connection_rate", params={"rate": 40, "window": "3s"}),
            ControlRequest(id="slowloris"),
            ControlRequest(id="geo_block", params={"mode": "block", "countries": []}),
        ],
    ),
}


def preset(preset_id: str) -> PresetSpec:
    if preset_id not in PRESETS:
        raise KeyError(preset_id)
    return PRESETS[preset_id]
