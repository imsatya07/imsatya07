from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low"]


class Asset(BaseModel):
    id: str
    hostname: str
    environment: Literal["it", "ot"]
    criticality: Literal["crown_jewel", "high", "medium", "low"]
    internet_exposed: bool
    software: list["Software"]


class Software(BaseModel):
    name: str
    version: str


class CVE(BaseModel):
    id: str
    description: str
    cvss: float = Field(ge=0, le=10)
    affected_software: str
    affected_versions: list[str]
    known_exploited: bool = False


class ExposureFinding(BaseModel):
    asset_id: str
    asset_hostname: str
    cve_id: str
    severity: Severity
    priority_score: float = Field(ge=0, le=100)
    rationale: str
    recommended_action: str


class ScanReport(BaseModel):
    summary: str
    findings: list[ExposureFinding]
    triage_notes: str | None = None


Asset.model_rebuild()
