"""Análise de URLs — heurísticas offline, unwrap de wrappers de segurança, redirect chain e análise de página de destino.

Extraído e adaptado de phishcheck.py.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, unquote, urljoin

from app.core.constants import (
    BRAND_OFFICIAL_ROOTS,
    COMMON_BRANDS,
    PAGE_BRANDS,
    CREDENTIAL_TERMS,
    PUNYCODE_PREFIX,
    REQUESTS_HEADERS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    URL_SECURITY_REWRITES,
    _PROOFPOINT_V2,
    _PROOFPOINT_V3,
)
from app.services.email_analyzer import (
    extract_domain,
    extract_urls_from_text,
    is_ip_address,
    normalize_text,
    strip_accents,
)
from app.services.report_builder import AnalysisReport
from app.services.trusted_service import is_trusted


def unwrap_security_rewrite(url: str) -> tuple[str, str | None]:
    """Desempacota wrappers de segurança corporativos. Retorna (url_real, provider)."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower().lstrip("www.")
        if host not in URL_SECURITY_REWRITES:
            return url, None
        param = URL_SECURITY_REWRITES[host]

        if host in ("urldefense.proofpoint.com", "urldefense.com"):
            m = _PROOFPOINT_V3.search(url)
            if m:
                return unquote(m.group(1).replace("_", "%")), "Proofpoint"
            m = _PROOFPOINT_V2.search(parsed.query)
            if m:
                return unquote(m.group(1).replace("-", "%").replace("_", "/")), "Proofpoint"
            return url, "Proofpoint"

        if param:
            qs = parse_qs(parsed.query)
            val = qs.get(param, [None])[0]
            if val:
                provider = {
                    "linkprotect.cudasvc.com": "Barracuda",
                    "safelinks.protection.outlook.com": "Microsoft Safe Links",
                    "link.edgepilot.com": "Microsoft Safe Links",
                    "protect.mimecast.com": "Mimecast",
                }.get(host, host)
                return unquote(val), provider

        return url, None
    except Exception:
        return url, None


def analyze_url_heuristics(url: str, report: AnalysisReport):
    """Aplica heurísticas offline sobre uma URL."""
    if url.lower().startswith("mailto:"):
        return "", ""

    real_url, rewrite_provider = unwrap_security_rewrite(url)
    if rewrite_provider and real_url != url:
        report.add(
            "URL",
            f"Link encapsulado por wrapper de segurança ({rewrite_provider}) — destino real: {real_url}.",
            8, "info",
        )
        url = real_url

    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.split("@")[-1].split(":")[0].lower()
    full_url = url

    if not host:
        report.add("URL", f"Não foi possível interpretar a URL: {url}", 5, "low")
        return "", ""

    registrable = extract_domain(host)
    if is_trusted(registrable) or is_trusted(host):
        return registrable, host

    if is_ip_address(host):
        report.add("URL", f"Link usa endereço IP em vez de domínio ({host}).", 25, "high")

    if "@" in parsed.netloc:
        report.add("URL", "URL contém '@' no host — técnica de disfarce.", 30, "critical")

    if "@" in (parsed.path + "?" + parsed.query + "#" + parsed.fragment):
        report.add(
            "URL",
            "URL contém '@' no caminho/fragmento — tentativa de disfarçar destino real com domínio legítimo após o '@'.",
            25, "high",
        )

    if parsed.scheme == "http":
        report.add("URL", "Link usa HTTP (sem criptografia).", 10, "low")

    label_count = host.count(".")
    if label_count >= 4:
        report.add("URL", f"Domínio com muitos subdomínios ({host}).", 15, "medium")

    if PUNYCODE_PREFIX in host:
        report.add("URL", f"Domínio usa Punycode ({host}) — possível homógrafo.", 30, "critical")

    is_shortener = registrable in URL_SHORTENERS or host in URL_SHORTENERS
    if is_shortener:
        sev = "high" if rewrite_provider else "medium"
        weight = 25 if rewrite_provider else 15
        via = f" (revelado por {rewrite_provider})" if rewrite_provider else ""
        report.add(
            "URL",
            f"Encurtador de URL ({host}) oculta destino real{via}.",
            weight, sev,
        )

    tld = registrable.split(".")[-1] if "." in registrable else ""
    if tld in SUSPICIOUS_TLDS:
        report.add("URL", f"TLD associado a abuso (.{tld}).", 12, "medium")

    norm_host = normalize_text(host)
    for brand in COMMON_BRANDS:
        brand_norm = normalize_text(brand).replace(" ", "")
        if brand_norm and brand_norm in norm_host.replace("-", "").replace(".", ""):
            official_roots = BRAND_OFFICIAL_ROOTS.get(brand, set())
            is_official = (
                registrable in official_roots
                or any(registrable == r or host.endswith("." + r) for r in official_roots)
                or bool(re.match(rf"^{re.escape(brand_norm)}\.(com|com\.br|net|org|io|co)$", registrable.replace("-", "")))
            )
            if not is_official:
                report.add(
                    "URL",
                    f"Domínio menciona '{brand}' mas não é oficial — lookalike ({host}).",
                    25, "high",
                )
                break

    decoded = unquote(full_url)
    if decoded != full_url:
        report.add("URL", "URL com caracteres codificados — possível ofuscação.", 8, "low")

    suspicious_words = ["login", "verify", "secure", "update", "confirm", "account", "signin", "webscr", "validate"]
    path_query = (parsed.path + "?" + parsed.query).lower()
    hits = [w for w in suspicious_words if w in path_query]
    if len(hits) >= 2:
        report.add("URL", f"Caminho com termos de phishing ({', '.join(hits)}).", 10, "low")

    if host.count("-") >= 3:
        report.add("URL", f"Domínio com muitos hífens ({host}).", 10, "medium")

    if len(full_url) > 120:
        report.add("URL", "URL anormalmente longa.", 5, "low")

    return registrable, host


def _analyze_page_html(html: str, final_url: str, original_url: str, report: AnalysisReport):
    """Analisa o HTML da página de destino buscando sinais de phishing."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return

    soup = BeautifulSoup(html, "html.parser")
    final_domain = extract_domain(final_url)
    page_text = soup.get_text(" ", strip=True).lower()

    pwd_fields = soup.find_all("input", {"type": "password"})
    if pwd_fields:
        if is_trusted(final_domain):
            report.add("Página", f"Página ({final_domain}) solicita senha — domínio confiável.", 0, "info")
        else:
            report.add(
                "Página",
                f"Página ({final_domain}) contém {len(pwd_fields)} campo(s) de senha — coleta de credenciais.",
                35, "critical",
            )

    for form in soup.find_all("form"):
        action = form.get("action", "")
        if not action or action.startswith("#") or action.startswith("javascript"):
            continue
        action_abs = urljoin(final_url, action)
        action_domain = extract_domain(action_abs)
        if action_domain and action_domain != final_domain and not is_trusted(action_domain):
            report.add(
                "Página",
                f"Formulário em ({final_domain}) envia dados para '{action_domain}' — exfiltração.",
                40, "critical",
            )

    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    title_lower = title.lower()
    for brand in PAGE_BRANDS:
        if brand in title_lower or brand in page_text[:500]:
            official = BRAND_OFFICIAL_ROOTS.get(brand.replace(" ", ""), set())
            if official and not any(
                final_domain == r or final_domain.endswith("." + r) for r in official
            ) and not is_trusted(final_domain):
                report.add(
                    "Página",
                    f"Página menciona '{brand}' (título: '{title[:60]}') mas está em '{final_domain}' — clone.",
                    35, "critical",
                )
                break

    cred_matches = CREDENTIAL_TERMS.findall(page_text[:3000])
    unique_cred = list(dict.fromkeys(m.lower() for m in cred_matches))
    if len(unique_cred) >= 3 and not is_trusted(final_domain):
        report.add(
            "Página",
            f"Alta densidade de termos de credenciais: {', '.join(unique_cred[:5])}.",
            25, "high",
        )

    if len(page_text.strip()) < 50:
        report.add("Página", f"Página ({final_domain}) quase vazia — possível redirect JS.", 10, "medium")


def analyze_url_content(url: str, report: AnalysisReport):
    """Pipeline de análise de conteúdo: segue redirects e analisa HTML final."""
    try:
        import requests as _requests
    except ImportError:
        return

    from app.core.config import get_settings

    original_url = url
    try:
        session = _requests.Session()
        session.headers.update(REQUESTS_HEADERS)
        session.max_redirects = 10
        resp = session.get(url, timeout=get_settings().url_fetch_timeout, allow_redirects=True, verify=True, stream=False)
        chain = [r.url for r in resp.history] + [resp.url]
        html = resp.text
        final_url = chain[-1]

        final_domain = extract_domain(final_url)
        original_domain = extract_domain(url)

        cross_domain_hops = [u for u in chain[1:] if extract_domain(u) != original_domain]
        if len(chain) > 2 and cross_domain_hops:
            chain_str = " → ".join(extract_domain(u) for u in chain)
            report.add(
                "Redirecionamento",
                f"URL passa por {len(chain)-1} redirects cruzando domínios: {chain_str}.",
                15 * min(len(cross_domain_hops), 3), "high",
            )
        elif len(chain) > 1 and final_domain != original_domain:
            report.add("Redirecionamento", f"URL redireciona de '{original_domain}' para '{final_domain}'.", 8, "medium")

        if final_domain != original_domain and not is_trusted(final_domain):
            analyze_url_heuristics(final_url, report)

        _analyze_page_html(html, final_url, original_url, report)

    except _requests.exceptions.SSLError:
        report.add("Conteúdo URL", f"Certificado SSL inválido em '{extract_domain(url)}'.", 20, "high")
    except _requests.exceptions.ConnectionError:
        report.add("Conteúdo URL", f"Não foi possível conectar a '{extract_domain(url)}'.", 0, "info")
    except _requests.exceptions.Timeout:
        report.add("Conteúdo URL", f"Timeout ao acessar '{extract_domain(url)}'.", 0, "info")
    except Exception as e:
        report.add("Conteúdo URL", f"Erro: {type(e).__name__}: {e}", 0, "info")
