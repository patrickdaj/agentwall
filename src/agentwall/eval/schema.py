from __future__ import annotations

from typing import Literal, Union

from pydantic import BaseModel, Field


class Provenance(BaseModel):
    source: str                                   # URL or citation
    kind: Literal["incident", "research", "advisory"]
    date: str                                     # ISO date the attack/PoC was documented
    note: str = ""


class FileWrite(BaseModel):
    action: Literal["file_write"] = "file_write"
    path: str
    content: bytes = b""
    untrusted_source: str | None = None           # ground-truth taint origin (see plan constraints)


class FileRead(BaseModel):
    action: Literal["file_read"] = "file_read"
    path: str
    content: bytes = b""
    untrusted_source: str | None = None


class Egress(BaseModel):
    action: Literal["egress"] = "egress"
    host: str
    method: str = "POST"
    body: bytes = b""


Action = Union[FileWrite, FileRead, Egress]


class ExpectedOutcome(BaseModel):
    min_verdict: str                              # ALLOW | WARN | BLOCK | QUARANTINE
    expect_chain: bool = False


class Scenario(BaseModel):
    id: str
    title: str
    family: str
    provenance: Provenance
    actions: list[Action] = Field(default_factory=list)
    expected: ExpectedOutcome
    status: Literal["caught", "blind-spot", "partial"]
    sensors_required: list[str] = Field(default_factory=list)
    benign: bool = False
