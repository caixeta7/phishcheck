"""Report builder — AnalysisReport e Finding.

Extraído e adaptado de phishcheck.py. Agrega achados e calcula veredito.
"""

from __future__ import annotations

from typing import Optional

from app.schemas.response import AnalysisReportDTO, FindingDTO, Severity, Verdict


class Finding:
    def __init__(
        self,
        category: str,
        description: str,
        weight: int,
        severity: str = "info",
        rule: str | None = None,
    ):
        self.category = category
        self.description = description
        self.weight = weight
        self.severity = severity
        self.rule = rule or description

    def __repr__(self):
        return f"[{self.severity.upper()}] ({self.category}) {self.description} (+{self.weight})"

    def to_dto(self) -> FindingDTO:
        return FindingDTO(
            category=self.category,
            description=self.description,
            weight=self.weight,
            severity=Severity(self.severity),
        )


class AnalysisReport:
    """Agrega achados de uma análise e calcula o veredito final."""

    def __init__(self, subject_label: str = "Análise"):
        self.subject_label = subject_label
        self.findings: list[Finding] = []
        self.sender_domain: Optional[str] = None
        self.sender_email: Optional[str] = None
        self.from_name: Optional[str] = None
        self.reply_to: Optional[str] = None
        self.return_path: Optional[str] = None
        self.subject_line: Optional[str] = None
        self.domains_checked: list[str] = []
        self.urls_found: list[str] = []

    def add(self, category: str, description: str, weight: int, severity: str = "info", rule: str | None = None):
        """`rule` agrupa achados da mesma heurística disparada para vários itens
        (N links, N domínios): todos aparecem no relatório, mas o score conta a
        regra uma vez, pelo maior peso. Sem `rule`, cada achado conta sozinho."""
        self.findings.append(Finding(category, description, weight, severity, rule))

    @property
    def score(self) -> int:
        best: dict[str, int] = {}
        for f in self.findings:
            best[f.rule] = max(best.get(f.rule, 0), f.weight)
        return min(100, sum(best.values()))

    @property
    def verdict(self) -> Verdict:
        s = self.score
        if s >= 60:
            return Verdict.HIGH_RISK
        elif s >= 30:
            return Verdict.SUSPICIOUS
        elif s >= 10:
            return Verdict.LOW_RISK
        return Verdict.LEGITIMATE

    @property
    def verdict_label(self) -> str:
        v = self.verdict
        labels = {
            Verdict.HIGH_RISK: "ALTO RISCO (provável phishing/malicioso)",
            Verdict.SUSPICIOUS: "SUSPEITO (requer cautela)",
            Verdict.LOW_RISK: "BAIXO RISCO (alguns sinais leves)",
            Verdict.LEGITIMATE: "LEGÍTIMO (nenhum sinal relevante encontrado)",
        }
        return labels[v]

    @property
    def findings_sorted(self) -> list[Finding]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(self.findings, key=lambda f: order.get(f.severity, 5))

    def to_dto(self) -> AnalysisReportDTO:
        return AnalysisReportDTO(
            subject=self.subject_label,
            score=self.score,
            verdict=self.verdict,
            sender_domain=self.sender_domain,
            sender_email=self.sender_email,
            from_name=self.from_name,
            reply_to=self.reply_to,
            return_path=self.return_path,
            subject_line=self.subject_line,
            domains_checked=self.domains_checked,
            urls_found=self.urls_found,
            findings=[f.to_dto() for f in self.findings_sorted],
        )
