"""Schemas de request (DTOs de entrada)."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AnalysisType(str, Enum):
    EMAIL_TEXT = "email_text"
    EMAIL_FILE = "email_file"
    URL = "url"
    DOMAIN = "domain"


class AnalyzeRequest(BaseModel):
    analysis_type: AnalysisType
    content: str = Field(
        "",
        description="Texto bruto do e-mail, URL ou domínio (para email_text, url, domain)",
    )
    online: bool = Field(
        default=True,
        description="Se True, executa verificações online (DNS, WHOIS, Threat Intel)",
    )


class TrustedDomainRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255, description="Domínio a adicionar/remover")
