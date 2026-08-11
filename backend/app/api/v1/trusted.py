"""CRUD de domínios confiáveis."""

from fastapi import APIRouter

from app.schemas.request import TrustedDomainRequest
from app.schemas.response import TrustedDomainDTO
from app.services.trusted_service import (
    get_trusted_domains,
    add_trusted_domain,
    remove_trusted_domain,
)

router = APIRouter(prefix="/api/v1/trusted-domains", tags=["trusted-domains"])


@router.get("", response_model=TrustedDomainDTO)
async def list_trusted():
    return TrustedDomainDTO(domains=get_trusted_domains())


@router.post("", response_model=TrustedDomainDTO)
async def add_trusted(req: TrustedDomainRequest):
    return TrustedDomainDTO(domains=add_trusted_domain(req.domain))


@router.delete("", response_model=TrustedDomainDTO)
async def remove_trusted(req: TrustedDomainRequest):
    return TrustedDomainDTO(domains=remove_trusted_domain(req.domain))
