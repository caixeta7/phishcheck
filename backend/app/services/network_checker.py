"""Verificações de rede — DNS, WHOIS, SPF/DMARC.

Adaptado para assíncrono, preservando a lógica de phishcheck.py.
"""

from __future__ import annotations

import asyncio
import datetime
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import whois as whois_lib

from app.core.config import get_settings
from app.services.email_analyzer import is_ip_address
from app.services.report_builder import AnalysisReport
from app.services.trusted_service import is_trusted

_executor = ThreadPoolExecutor(max_workers=8)


def _check_dns_records_sync(domain: str, report: AnalysisReport):
    resolver = dns.resolver.Resolver()
    resolver.timeout = get_settings().dns_timeout
    resolver.lifetime = get_settings().dns_timeout

    has_a = has_ns = False
    try:
        has_a = len(resolver.resolve(domain, "A")) > 0
    except Exception:
        pass
    try:
        has_ns = len(resolver.resolve(domain, "NS")) > 0
    except Exception:
        pass

    if not has_a and not has_ns:
        report.add("DNS", f"'{domain}' não respondeu a DNS (A/NS) — pode não existir.", 20, "high", rule="dns.no_records")
    else:
        report.add("DNS", f"'{domain}' possui registros DNS ativos.", 0, "info")


def _check_spf_dmarc_sync(domain: str, report: AnalysisReport):
    resolver = dns.resolver.Resolver()
    resolver.timeout = get_settings().dns_timeout
    resolver.lifetime = get_settings().dns_timeout

    has_mx = False
    try:
        has_mx = len(resolver.resolve(domain, "MX")) > 0
    except Exception:
        pass
    if not has_mx:
        report.add("DNS", f"'{domain}' sem registro MX — incomum para domínio que envia e-mail.", 8, "low")

    has_spf = False
    try:
        for rdata in resolver.resolve(domain, "TXT"):
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore") if hasattr(rdata, "strings") else str(rdata)
            if "v=spf1" in txt.lower():
                has_spf = True
                break
    except Exception:
        pass

    has_dmarc = False
    try:
        for rdata in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore") if hasattr(rdata, "strings") else str(rdata)
            if "v=dmarc1" in txt.lower():
                has_dmarc = True
                break
    except Exception:
        pass

    if not has_spf:
        report.add("E-mail Auth", f"'{domain}' sem SPF — facilita spoofing do remetente.", 15, "medium")
    else:
        report.add("E-mail Auth", f"'{domain}' possui SPF configurado.", 0, "info")

    if not has_dmarc:
        report.add("E-mail Auth", f"'{domain}' sem DMARC — reduz proteção contra spoofing.", 10, "low")
    else:
        report.add("E-mail Auth", f"'{domain}' possui DMARC configurado.", 0, "info")


def _check_whois_age_sync(domain: str, report: AnalysisReport):
    try:
        w = whois_lib.whois(domain)
    except Exception as e:
        report.add("WHOIS", f"Não foi possível consultar WHOIS para '{domain}' ({e.__class__.__name__}).", 0, "info")
        return

    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0] if creation_date else None
    if not creation_date:
        report.add("WHOIS", f"Não foi possível determinar data de criação de '{domain}'.", 0, "info")
        return
    if isinstance(creation_date, str):
        report.add("WHOIS", f"Data de criação em formato não padrão: {creation_date}", 0, "info")
        return

    now = datetime.datetime.now(creation_date.tzinfo) if creation_date.tzinfo else datetime.datetime.now()
    age_days = (now - creation_date).days
    if age_days < 0:
        return

    if age_days < 30:
        report.add("WHOIS", f"'{domain}' registrado há {age_days} dias — phishing recente.", 30, "critical", rule="whois.age")
    elif age_days < 180:
        report.add("WHOIS", f"'{domain}' registrado há {age_days} dias — domínio novo.", 15, "medium", rule="whois.age")
    elif age_days < 365:
        report.add("WHOIS", f"'{domain}' tem menos de 1 ano ({age_days} dias).", 5, "low", rule="whois.age")
    else:
        years = age_days // 365
        report.add("WHOIS", f"'{domain}' existe há ~{years} ano(s) — estabelecido.", 0, "info")


async def _run_sync(func, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, func, *args)


async def check_dns_records(domain: str, report: AnalysisReport):
    await _run_sync(_check_dns_records_sync, domain, report)


async def check_spf_dmarc(domain: str, report: AnalysisReport):
    await _run_sync(_check_spf_dmarc_sync, domain, report)


async def check_whois_age(domain: str, report: AnalysisReport):
    # ponytail: a thread do WHOIS continua rodando após o timeout (não dá para matar
    # thread em Python); só liberamos a resposta. Se virar gargalo, usar processo.
    try:
        await asyncio.wait_for(_run_sync(_check_whois_age_sync, domain, report), get_settings().whois_timeout)
    except asyncio.TimeoutError:
        report.add("WHOIS", f"Timeout ao consultar WHOIS de '{domain}'.", 0, "info")


async def run_online_domain_checks(domain: str, report: AnalysisReport, email_auth: bool = False):
    """Executa DNS e WHOIS em paralelo; MX/SPF/DMARC só se `email_auth`.

    MX/SPF/DMARC dizem respeito a quem *envia* e-mail — cobrar isso de domínios
    de links (CDN, sites) gera falso positivo.
    """
    # IP literal não tem DNS/WHOIS de domínio — vai para o AbuseIPDB no threat intel.
    if is_trusted(domain) or is_ip_address(domain):
        return
    checks = [check_dns_records(domain, report), check_whois_age(domain, report)]
    if email_auth:
        checks.append(check_spf_dmarc(domain, report))
    await asyncio.gather(*checks, return_exceptions=True)
