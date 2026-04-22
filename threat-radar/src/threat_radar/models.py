from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


IOCType = Literal["ipv4", "domain", "url", "sha256", "md5", "file_path", "email"]
ThreatCategory = Literal[
    "ransomware", "supply-chain", "rce", "credential-theft",
    "data-exfiltration", "dos", "ot-targeted", "other",
]


class IOC(BaseModel):
    type: IOCType
    value: str


class ExtractedIntel(BaseModel):
    """Structured threat intel extracted from an unstructured advisory."""
    title: str = Field(description="Short title summarizing the threat")
    summary: str = Field(description="One-paragraph plain-English summary")
    category: ThreatCategory
    cve_ids: list[str] = Field(default_factory=list, description="CVE IDs referenced")
    affected_products: list[str] = Field(
        default_factory=list,
        description="Product names, lowercased (e.g. 'log4j', 'openssl', 'windows')",
    )
    iocs: list[IOC] = Field(default_factory=list)
    severity: Literal["critical", "high", "medium", "low"]


class Asset(BaseModel):
    id: str
    hostname: str
    environment: Literal["it", "ot"]
    criticality: Literal["crown_jewel", "high", "medium", "low"]
    software: list[str] = Field(description="Installed product names, lowercased")


class AssetRisk(BaseModel):
    asset_id: str
    hostname: str
    environment: str
    criticality: str
    matched_products: list[str]
    matched_cves: list[str]
    risk_note: str


class ExposureAssessment(BaseModel):
    advisory_title: str
    severity: str
    at_risk_assets: list[AssetRisk]
    overall_recommendation: str
