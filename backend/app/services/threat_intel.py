"""Threat Intel — VirusTotal v3, Google Safe Browsing v4, AbuseIPDB.

Todas as APIs são gratuitas com rate limits. Fallback gracioso se keys ausentes.
"""

from __future__ import annotations

import asyncio
import base64

import httpx

from app.core.config import get_settings
from app.services.report_builder import AnalysisReport


async def check_virustotal(urls: list[str], report: AnalysisReport):
    """Consulta VirusTotal v3 para URLs. Inclui veredito do motor Kaspersky."""
    settings = get_settings()
    if not settings.virustotal_api_key:
        return

    async with httpx.AsyncClient(timeout=settings.threat_intel_timeout) as client:
        tasks = [_vt_check_url(client, url, settings.virustotal_api_key, report) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)


async def _vt_check_url(client: httpx.AsyncClient, url: str, api_key: str, report: AnalysisReport):
    headers = {"x-apikey": api_key}
    try:
        # Relatório já existente — submeter e ler logo em seguida devolve análise
        # ainda na fila (stats zerados), o que seria reportado como "limpo".
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

        if resp.status_code == 404:
            await client.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
            report.add("VirusTotal", f"'{url}' desconhecida no VirusTotal — enviada para análise, sem veredito ainda.", 0, "info")
            return
        if resp.status_code == 429:
            report.add("VirusTotal", "Limite de requisições do VirusTotal atingido — URL não verificada.", 0, "info")
            return
        if resp.status_code != 200:
            report.add("VirusTotal", f"Consulta retornou status {resp.status_code}.", 0, "info")
            return

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {"results": attrs.get("last_analysis_results", {})}
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            report.add(
                "VirusTotal",
                f"VirusTotal: {malicious} motor(es) classificaram '{url}' como malicioso.",
                40, "critical", rule="vt.malicious",
            )

            engine_results = result.get("results", {})
            kaspersky = engine_results.get("Kaspersky", {})
            if kaspersky and kaspersky.get("category") == "malicious":
                report.add(
                    "Kaspersky (via VT)",
                    f"Motor Kaspersky detectou '{url}' como: {kaspersky.get('result', 'malicioso')}.",
                    10, "critical", rule="vt.kaspersky",
                )
        elif suspicious > 0:
            report.add(
                "VirusTotal",
                f"VirusTotal: {suspicious} motor(es) classificaram '{url}' como suspeito.",
                20, "high", rule="vt.suspicious",
            )
        else:
            report.add("VirusTotal", f"'{url}' limpo no VirusTotal (0 detecções).", 0, "info")

    except Exception as e:
        report.add("VirusTotal", f"Erro ao consultar: {type(e).__name__}", 0, "info")


async def check_google_safe_browsing(urls: list[str], report: AnalysisReport):
    """Consulta Google Safe Browsing v4."""
    settings = get_settings()
    if not settings.google_safe_browsing_api_key:
        return

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.google_safe_browsing_api_key}"
    body = {
        "client": {"clientId": "phishcheck-web", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=settings.threat_intel_timeout) as client:
            resp = await client.post(endpoint, json=body)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    for m in matches:
                        report.add(
                            "Safe Browsing",
                            f"Google Safe Browsing classificou '{m.get('threat', {}).get('url')}' como '{m.get('threatType')}'.",
                            40, "critical", rule="gsb.match",
                        )
                else:
                    report.add("Safe Browsing", "URLs não encontradas em listas de ameaças do Google.", 0, "info")
            else:
                report.add("Safe Browsing", f"Consulta retornou status {resp.status_code}.", 0, "info")
    except Exception as e:
        report.add("Safe Browsing", f"Falha: {type(e).__name__}", 0, "info")


async def check_abuseipdb(ips: list[str], report: AnalysisReport):
    """Consulta AbuseIPDB para IPs."""
    settings = get_settings()
    if not settings.abuseipdb_api_key:
        return

    async with httpx.AsyncClient(timeout=settings.threat_intel_timeout) as client:
        tasks = [_abuseipdb_check_ip(client, ip, settings.abuseipdb_api_key, report) for ip in ips]
        await asyncio.gather(*tasks, return_exceptions=True)


async def _abuseipdb_check_ip(client: httpx.AsyncClient, ip: str, api_key: str, report: AnalysisReport):
    try:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        if resp.status_code != 200:
            return

        data = resp.json().get("data", {})
        abuse_score = data.get("abuseConfidenceScore", 0)
        if abuse_score >= 75:
            report.add(
                "AbuseIPDB",
                f"IP {ip} com score de abuso {abuse_score}/100 — alto risco.",
                30, "critical", rule="abuseipdb.high",
            )
        elif abuse_score >= 30:
            report.add(
                "AbuseIPDB",
                f"IP {ip} com score de abuso {abuse_score}/100 — suspeito.",
                15, "medium", rule="abuseipdb.medium",
            )
    except Exception:
        pass


async def run_threat_intel_checks(
    urls: list[str],
    domains: list[str],
    ips: list[str],
    report: AnalysisReport,
):
    """Executa todas as verificações de Threat Intel em paralelo."""
    tasks = []
    if urls:
        tasks.append(check_virustotal(urls, report))
        tasks.append(check_google_safe_browsing(urls, report))
    if ips:
        tasks.append(check_abuseipdb(ips, report))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
