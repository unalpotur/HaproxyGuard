"""Catalog of security controls and the HAProxy directives they emit.

Each control knows its tunable defaults and how to render itself into config
fragments. Counter-based controls (rate limiting / DDoS) share a single
stick-table built by the generator, so they only declare the counter they need
plus the deny/reject rule that consumes it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .models import ControlSpec


@dataclass
class EmitParts:
    counter: str | None = None              # stick-table store entry (e.g. http_req_rate(10s))
    tcp_rules: list[str] = field(default_factory=list)
    http_rules: list[str] = field(default_factory=list)
    extra_frontend: list[str] = field(default_factory=list)
    global_lines: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ControlDef:
    id: str
    name: str
    category: str
    description: str
    defaults: dict
    build: Callable[[dict], EmitParts]
    detect_tokens: tuple[str, ...] = ()  # substrings that mark this control present


def _merge(defaults: dict, params: dict) -> dict:
    out = dict(defaults)
    out.update({k: v for k, v in params.items() if v is not None})
    return out


# -- counter-based controls -------------------------------------------------

def _request_rate(p: dict) -> EmitParts:
    return EmitParts(
        counter=f"http_req_rate({p['window']})",
        http_rules=[
            f"http-request deny deny_status 429 "
            f"if {{ sc_http_req_rate(0) gt {p['rate']} }}"],
    )


def _connection_rate(p: dict) -> EmitParts:
    return EmitParts(
        counter=f"conn_rate({p['window']})",
        tcp_rules=[
            f"tcp-request connection reject "
            f"if {{ sc_conn_rate(0) gt {p['rate']} }}"],
    )


def _concurrent_conn(p: dict) -> EmitParts:
    return EmitParts(
        counter="conn_cur",
        tcp_rules=[
            f"tcp-request connection reject "
            f"if {{ sc_conn_cur(0) gt {p['max']} }}"],
    )


def _error_rate(p: dict) -> EmitParts:
    return EmitParts(
        counter=f"http_err_rate({p['window']})",
        http_rules=[
            f"http-request deny deny_status 429 "
            f"if {{ sc_http_err_rate(0) gt {p['rate']} }}"],
        notes=["error-rate limiting blocks IPs generating many 4xx (scanners/bruteforce)."],
    )


# -- non-counter controls ---------------------------------------------------

def _slowloris(p: dict) -> EmitParts:
    return EmitParts(
        extra_frontend=[
            f"timeout http-request {p['timeout']}",
            "option http-buffer-request",
        ],
        notes=["Slowloris mitigation: caps the time a client has to send headers."],
    )


def _geo_block(p: dict) -> EmitParts:
    countries = " ".join(p["countries"]) if p["countries"] else "XX"
    map_path = p["map_path"]
    if p["mode"] == "allow":
        acl = f"acl geo_allowed src,map_ip({map_path}) -m str {countries}"
        deny = "http-request deny deny_status 403 if !geo_allowed"
    else:
        acl = f"acl geo_blocked src,map_ip({map_path}) -m str {countries}"
        deny = "http-request deny deny_status 403 if geo_blocked"
    return EmitParts(
        extra_frontend=[acl, deny],
        notes=[
            f"Create the map file {map_path} (IP/CIDR -> country code), "
            "e.g. generated from MaxMind GeoLite2.",
            "Adjust the country list and mode (block/allow) to your policy.",
        ],
    )


def _admin_protection(p: dict) -> EmitParts:
    nets = p["networks"]
    return EmitParts(
        extra_frontend=[
            f"acl admin_allowed src {nets}",
            "http-request deny if !admin_allowed",
        ],
        notes=[
            "Add these lines to the frontend/listen that exposes stats or admin; "
            "they restrict access to the listed networks.",
        ],
    )


CONTROLS: dict[str, ControlDef] = {
    "request_rate": ControlDef(
        "request_rate", "HTTP request rate limit", "rate-limit",
        "Deny clients exceeding a per-IP HTTP request rate (429).",
        {"rate": 100, "window": "10s"}, _request_rate,
        detect_tokens=("http_req_rate",)),
    "connection_rate": ControlDef(
        "connection_rate", "New-connection rate limit", "ddos",
        "Reject IPs opening new connections too quickly.",
        {"rate": 50, "window": "3s"}, _connection_rate,
        detect_tokens=("conn_rate",)),
    "concurrent_connections": ControlDef(
        "concurrent_connections", "Concurrent connection cap", "ddos",
        "Reject IPs holding more than N simultaneous connections.",
        {"max": 50}, _concurrent_conn,
        detect_tokens=("conn_cur",)),
    "error_rate": ControlDef(
        "error_rate", "Error rate limit", "rate-limit",
        "Block IPs generating many 4xx responses (scanners/bruteforce).",
        {"rate": 20, "window": "10s"}, _error_rate,
        detect_tokens=("http_err_rate",)),
    "slowloris": ControlDef(
        "slowloris", "Slowloris protection", "ddos",
        "Cap header-send time and buffer requests to defeat slow-header attacks.",
        {"timeout": "5s"}, _slowloris,
        detect_tokens=("timeout http-request",)),
    "geo_block": ControlDef(
        "geo_block", "Geo blocking", "geo",
        "Allow or block traffic by source-IP country via a map file.",
        {"countries": ["CN", "RU"], "map_path": "/etc/haproxy/geoip.map", "mode": "block"},
        _geo_block, detect_tokens=("map_ip(",)),
    "admin_protection": ControlDef(
        "admin_protection", "Admin/stats IP allowlist", "admin",
        "Restrict the stats/admin interface to trusted networks.",
        {"networks": "127.0.0.1 10.0.0.0/8 192.168.0.0/16"}, _admin_protection,
        detect_tokens=("admin_allowed",)),
}


def resolve_params(control_id: str, params: dict) -> dict:
    return _merge(CONTROLS[control_id].defaults, params or {})


def catalog() -> list[ControlSpec]:
    return [
        ControlSpec(id=c.id, name=c.name, category=c.category,
                    description=c.description, params=c.defaults)
        for c in CONTROLS.values()
    ]
