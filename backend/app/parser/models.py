"""Structured representation of an HAProxy configuration."""
from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class Bind(BaseModel):
    address: str
    port: Optional[int] = None
    ssl: bool = False
    certificate: Optional[str] = None
    options: dict[str, str | bool] = Field(default_factory=dict)
    raw: str = ""


class Server(BaseModel):
    name: str
    address: str
    port: Optional[int] = None
    check: bool = False
    backup: bool = False
    weight: Optional[int] = None
    maxconn: Optional[int] = None
    ssl: bool = False
    options: dict[str, str | bool] = Field(default_factory=dict)
    raw: str = ""


class Acl(BaseModel):
    name: str
    criterion: str
    values: list[str] = Field(default_factory=list)
    raw: str = ""


class SwitchingRule(BaseModel):
    """use_backend <backend> if|unless <condition>"""
    backend: str
    operator: Optional[str] = None  # "if" | "unless" | None (unconditional)
    condition: Optional[str] = None
    raw: str = ""


class Directive(BaseModel):
    keyword: str
    args: list[str] = Field(default_factory=list)
    line_number: int = 0
    raw: str = ""


class Section(BaseModel):
    kind: str  # global, defaults, frontend, backend, listen, ...
    name: Optional[str] = None
    line_number: int = 0
    directives: list[Directive] = Field(default_factory=list)

    def get(self, keyword: str) -> Optional[Directive]:
        for d in self.directives:
            if d.keyword == keyword:
                return d
        return None

    def get_all(self, keyword: str) -> list[Directive]:
        return [d for d in self.directives if d.keyword == keyword]


class Frontend(BaseModel):
    name: str
    line_number: int = 0
    binds: list[Bind] = Field(default_factory=list)
    acls: list[Acl] = Field(default_factory=list)
    switching_rules: list[SwitchingRule] = Field(default_factory=list)
    default_backend: Optional[str] = None
    mode: Optional[str] = None
    options: list[str] = Field(default_factory=list)
    timeouts: dict[str, str] = Field(default_factory=dict)
    directives: list[Directive] = Field(default_factory=list)


class Backend(BaseModel):
    name: str
    line_number: int = 0
    balance: Optional[str] = None
    mode: Optional[str] = None
    servers: list[Server] = Field(default_factory=list)
    acls: list[Acl] = Field(default_factory=list)
    has_health_check: bool = False
    options: list[str] = Field(default_factory=list)
    timeouts: dict[str, str] = Field(default_factory=dict)
    directives: list[Directive] = Field(default_factory=list)


class Listen(Backend):
    binds: list[Bind] = Field(default_factory=list)
    switching_rules: list[SwitchingRule] = Field(default_factory=list)
    default_backend: Optional[str] = None


class HaproxyConfig(BaseModel):
    global_section: Optional[Section] = None
    defaults: list[Section] = Field(default_factory=list)
    frontends: list[Frontend] = Field(default_factory=list)
    backends: list[Backend] = Field(default_factory=list)
    listens: list[Listen] = Field(default_factory=list)
    other_sections: list[Section] = Field(default_factory=list)
    parse_errors: list[str] = Field(default_factory=list)

    def backend_names(self) -> set[str]:
        return {b.name for b in self.backends} | {l.name for l in self.listens}
