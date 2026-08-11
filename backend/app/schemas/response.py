"""Schemas de response (DTOs de saída)."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    LEGITIMATE = "LEGITIMO"
    LOW_RISK = "BAIXO_RISCO"
    SUSPICIOUS = "SUSPEITO"
    HIGH_RISK = "ALTO_RISCO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class FindingDTO(BaseModel):
    category: str
    description: str
    weight: int
    severity: Severity


class AnalysisReportDTO(BaseModel):
    subject: str
    score: int
    verdict: Verdict
    sender_domain: Optional[str] = None
    sender_email: Optional[str] = None
    from_name: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject_line: Optional[str] = None
    domains_checked: list[str] = Field(default_factory=list)
    urls_found: list[str] = Field(default_factory=list)
    findings: list[FindingDTO]


class ProgressStepDTO(BaseModel):
    """Evento individual de progresso enviado via SSE."""
    step: str
    status: str  # "pending" | "running" | "done" | "error"
    message: Optional[str] = None
    findings: Optional[list[FindingDTO]] = None


class TrustedDomainDTO(BaseModel):
    domains: list[str]


class ErrorResponse(BaseModel):
    detail: str
    error_type: str
