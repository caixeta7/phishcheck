"""Análise de remetente e conteúdo de e-mail.

Foco absoluto no remetente: From, Reply-To, Return-Path, SPF/DMARC,
brand impersonation, urgência, anexos e identity mismatch.
Extraído e adaptado de phishcheck.py.
"""

from __future__ import annotations

import re
import unicodedata
from email.message import Message
from email.utils import parseaddr
from urllib.parse import urlparse, unquote

from app.core.constants import (
    BRAND_OFFICIAL_ROOTS,
    COMMON_BRANDS,
    BRAND_SKIP_IF_GENERIC,
    BRAND_SERVICE_CONTEXT,
    DANGEROUS_ATTACHMENT_EXT,
    FREE_PROVIDERS,
    MEDIUM_RISK_ATTACHMENT_EXT,
    RAND_TOKEN_RE,
    TIMESTAMP_SUBJ_RE,
    URGENCY_TERMS_EN,
    URGENCY_TERMS_PT,
)
from app.services.report_builder import AnalysisReport
from app.services.trusted_service import is_trusted


def strip_accents(text: str) -> str:
    if not text:
        return ""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def normalize_text(text: str) -> str:
    return strip_accents(text.lower()) if text else ""


def extract_domain(value: str) -> str:
    """Extrai o domínio registrável de uma URL, e-mail ou domínio puro."""
    try:
        import tldextract
        _TLD = tldextract.TLDExtract(suffix_list_urls=())
    except ImportError:
        _TLD = None

    value = value.strip().strip("<>' \"")
    if "@" in value and "://" not in value:
        value = value.split("@")[-1].strip("<>' \"")
    elif "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path

    value = value.split(":")[0]
    value = value.strip("/").strip("<>' \"")

    if _TLD:
        ext = _TLD(value)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return value.lower()

    _TWO_LEVEL_TLDS = {
        "com", "org", "net", "edu", "gov", "mil", "adv", "adm",
        "arq", "art", "bio", "biz", "cng", "cnt", "ecn", "eng",
        "esp", "etc", "eti", "far", "fot", "fst", "g12", "ggf",
        "imb", "ind", "inf", "jor", "lel", "mat", "med", "mus",
        "not", "ntr", "odo", "ppg", "pro", "psc", "rec", "slg",
        "srv", "tmp", "trd", "tur", "tv", "vet", "zlg", "co",
    }
    parts = value.split(".")
    if len(parts) >= 3 and parts[-2] in _TWO_LEVEL_TLDS:
        return ".".join(parts[-3:]).lower()
    elif len(parts) >= 2:
        return ".".join(parts[-2:]).lower()
    return value.lower()


def get_fqdn(value: str) -> str:
    value = value.strip()
    if "@" in value and "://" not in value:
        return value.split("@")[-1].lower()
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.netloc
    else:
        host = value
    host = host.split("@")[-1]
    host = host.split(":")[0]
    return host.strip("/").lower()


def is_ip_address(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_urls_from_text(text: str) -> list[str]:
    from app.core.constants import URL_REGEX
    if not text:
        return []
    raw = URL_REGEX.findall(text)
    cleaned = []
    for u in raw:
        u = u.rstrip(".,;:!?)]}>\"'")
        if u.startswith("www."):
            u = "http://" + u
        cleaned.append(u)
    seen = set()
    result = []
    for u in cleaned:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result


def dedup_urls(urls: list[str]) -> list[str]:
    seen_keys = set()
    result = []
    for u in urls:
        p = urlparse(u if "://" in u else "http://" + u)
        key = (p.scheme, p.netloc.lower())
        if key not in seen_keys:
            seen_keys.add(key)
            result.append(u)
    return result


def analyze_email_headers(msg: Message, report: AnalysisReport) -> tuple[str, str, str]:
    """Analisa cabeçalhos. Retorna (from_domain, from_addr, subject)."""
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    received = msg.get_all("Received", []) or []
    subject = msg.get("Subject", "") or ""

    from_name, from_addr = parseaddr(from_header)
    from_domain = extract_domain(from_addr) if from_addr else ""

    report.from_name = from_name
    report.sender_email = from_addr
    report.sender_domain = from_domain
    report.subject_line = subject

    if reply_to:
        report.reply_to = reply_to
        _, reply_addr = parseaddr(reply_to)
        reply_domain = extract_domain(reply_addr) if reply_addr else ""
        if reply_domain and from_domain and reply_domain != from_domain:
            report.add(
                "Cabeçalho",
                f"O 'Reply-To' ({reply_domain}) é diferente do domínio do remetente 'From' ({from_domain}).",
                25, "high",
            )

    if return_path:
        report.return_path = return_path
        _, rp_addr = parseaddr(return_path)
        rp_domain = extract_domain(rp_addr) if rp_addr else ""
        if rp_domain and from_domain and rp_domain != from_domain:
            report.add(
                "Cabeçalho",
                f"O 'Return-Path' ({rp_domain}) é diferente do domínio 'From' ({from_domain}).",
                20, "high",
            )

    norm_name = normalize_text(from_name)
    for brand in COMMON_BRANDS:
        brand_norm = normalize_text(brand)
        if brand_norm and brand_norm in norm_name and from_domain in FREE_PROVIDERS:
            report.add(
                "Cabeçalho",
                f"Nome de exibição menciona '{brand}' mas o e-mail vem de provedor gratuito ({from_domain}).",
                25, "high",
            )
            break

    subj_norm = normalize_text(subject)
    hits_pt = [t for t in URGENCY_TERMS_PT if strip_accents(t) in subj_norm]
    hits_en = [t for t in URGENCY_TERMS_EN if t in subj_norm]
    all_hits = hits_pt + hits_en
    if all_hits:
        report.add(
            "Conteúdo",
            f"Assunto contém termos de engenharia social: {', '.join(all_hits[:5])}.",
            8 * min(len(all_hits), 3), "medium",
        )

    if len(received) >= 8:
        report.add("Cabeçalho", f"E-mail passou por {len(received)} servidores de retransmissão.", 5, "low")

    # Inspeção de autenticação e vereditos de gateway (SPF, DMARC, SCL, CAT:HPHISH)
    auth_results = msg.get("Authentication-Results", "").lower()
    received_spf = msg.get("Received-SPF", "").lower()
    forefront_report = msg.get("X-Forefront-Antispam-Report", "").lower()

    if "spf=fail" in auth_results or "received-spf: fail" in received_spf or "spf=fail" in received_spf:
        report.add(
            "Autenticação E-mail",
            "Falha na validação SPF — o servidor de envio não é autorizado pelo domínio remetente.",
            25, "high",
        )

    if "dmarc=fail" in auth_results:
        report.add(
            "Autenticação E-mail",
            "Falha na validação DMARC — o e-mail viola a política de autenticação do domínio remetente.",
            30, "critical",
        )

    if "cat:hphish" in forefront_report or "cat:phish" in forefront_report:
        report.add(
            "Gateway de E-mail",
            "Veredito do gateway de segurança: Phishing confirmado (CAT:HPHISH).",
            40, "critical",
        )
    elif "sfv:spm" in forefront_report or "sfv:shp" in forefront_report:
        report.add(
            "Gateway de E-mail",
            "Veredito do gateway de segurança: Spam / Phishing detectado.",
            25, "high",
        )

    # Detectar SCL (Spam Confidence Level) se presente nos cabeçalhos
    for key, val in msg.items():
        if "scl:" in val.lower() or "scl=" in val.lower():
            m = re.search(r"scl[:=]\s*(\d+)", val, re.IGNORECASE)
            if m:
                scl_val = int(m.group(1))
                if scl_val >= 5:
                    report.add(
                        "Gateway de E-mail",
                        f"Nível de confiança de spam elevado (SCL: {scl_val}/9) segundo o servidor de e-mail.",
                        20 + (scl_val * 2), "high" if scl_val < 7 else "critical",
                    )
                break

    rand_tokens = [
        t for t in RAND_TOKEN_RE.findall(subject)
        if not t.lower() in {"document", "review", "requested", "pending", "payment",
                             "agreement", "reference", "contact", "please", "action",
                             "required", "invoice", "your"}
        and not t.isdigit()
        and sum(1 for c in t if c.isupper()) >= 2
        and sum(1 for c in t if c.isdigit()) >= 1
    ]
    has_timestamp = bool(TIMESTAMP_SUBJ_RE.search(subject))
    if len(rand_tokens) >= 2 and has_timestamp:
        report.add(
            "Assunto",
            f"Assunto com padrão de geração automática: IDs aleatórios + timestamp.",
            25, "high",
        )
    elif len(rand_tokens) >= 2:
        report.add("Assunto", f"Assunto com múltiplos IDs gerados automaticamente.", 12, "medium")

    return from_domain, from_addr, subject


def analyze_email_body(body_text: str, report: AnalysisReport) -> list[str]:
    """Analisa corpo do e-mail. Retorna URLs encontradas."""
    norm_body = normalize_text(body_text)

    hits_pt = [t for t in URGENCY_TERMS_PT if strip_accents(t) in norm_body]
    hits_en = [t for t in URGENCY_TERMS_EN if t in norm_body]
    all_hits = list(dict.fromkeys(hits_pt + hits_en))
    if all_hits:
        report.add(
            "Conteúdo",
            f"Corpo contém termos de urgência: {', '.join(all_hits[:6])}.",
            5 * min(len(all_hits), 4), "medium",
        )

    sensitive_requests = [
        "senha", "password", "cartao de credito", "cartão de crédito", "cvv",
        "numero do cartao", "código de verificação", "codigo de verificacao",
        "cpf e senha", "dados bancarios", "dados bancários", "conta e senha",
        "token", "social security number",
    ]
    request_verbs = [
        "informe", "confirme", "insira", "digite", "forneca", "forneça",
        "preencha", "envie sua", "atualize sua", "valide", "clique aqui",
        "acesse o link", "entre com", "entre sua", "click here", "verify",
        "confirm your", "enter your", "provide your", "update your",
    ]
    req_hits = [t for t in sensitive_requests if strip_accents(t) in norm_body]
    if req_hits:
        has_request_verb = any(v in norm_body for v in request_verbs)
        weight = 20 if has_request_verb else 8
        severity = "high" if has_request_verb else "medium"
        report.add(
            "Conteúdo",
            f"E-mail {'solicita' if has_request_verb else 'menciona'} dados sensíveis: {', '.join(req_hits[:5])}.",
            weight, severity,
        )

    return extract_urls_from_text(body_text)


def analyze_email_html_links(html_content: str, report: AnalysisReport) -> list[str]:
    """Detecta discrepância entre texto visível de link <a> e href real."""
    if not html_content:
        return []

    anchor_pattern = re.compile(
        r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )
    mismatches = []
    all_hrefs = []

    from app.services.url_analyzer import unwrap_security_rewrite

    for match in anchor_pattern.finditer(html_content):
        href, visible = match.group(1), match.group(2)
        visible_clean = re.sub(r"<[^>]+>", "", visible).strip()

        real_href, rewrite_provider = unwrap_security_rewrite(href)
        all_hrefs.append(real_href)

        visible_urls = extract_urls_from_text(visible_clean) or (
            [visible_clean] if re.match(r"^[\w.-]+\.[a-z]{2,}", visible_clean, re.IGNORECASE) else []
        )
        if visible_urls:
            visible_domain = extract_domain(visible_urls[0])
            href_domain = extract_domain(real_href)
            if (visible_domain and href_domain
                    and visible_domain != href_domain
                    and not href.startswith("mailto:")):
                mismatches.append((visible_clean, real_href, rewrite_provider))

    for visible_text, real_url, provider in mismatches:
        via = f" (via {provider})" if provider else ""
        report.add(
            "Conteúdo HTML",
            f"Link exibe '{visible_text}' mas aponta para '{real_url}'{via}.",
            30, "critical",
        )

    return [h for h in all_hrefs if not h.lower().startswith("mailto:")]


def analyze_attachments(filenames: list[str], report: AnalysisReport):
    """Verifica anexos por extensão de risco."""
    for filename in filenames:
        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[-1].lower()
        if ext in DANGEROUS_ATTACHMENT_EXT:
            report.add("Anexo", f"Anexo de alto risco: '{filename}'.", 35, "critical")
        elif ext in MEDIUM_RISK_ATTACHMENT_EXT:
            report.add("Anexo", f"Anexo compactado/com macro: '{filename}'.", 12, "medium")
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|vbs|bat)$", filename.lower()):
            report.add("Anexo", f"Anexo '{filename}' usa extensão dupla para disfarçar executável.", 35, "critical")


def check_brand_sender_mismatch(body_text: str, body_html: str, from_domain: str, report: AnalysisReport):
    """Detecta impersonation: corpo menciona marca mas remetente não é o domínio oficial."""
    if not from_domain:
        return

    plain = (body_text or "") + " " + re.sub(r"<[^>]+>", " ", body_html or "")
    combined = normalize_text(plain)

    has_service_context = bool(BRAND_SERVICE_CONTEXT.search(plain))
    if not has_service_context:
        return

    for brand in COMMON_BRANDS:
        brand_norm = normalize_text(brand)
        if not brand_norm or brand_norm not in combined:
            continue

        if brand in BRAND_SKIP_IF_GENERIC:
            brand_in_context = re.search(
                rf"{re.escape(brand_norm)}.{{0,80}}(sign.?in|log.?in|account|conta|verify|confirm)",
                combined, re.IGNORECASE,
            )
            if not brand_in_context:
                continue

        official_roots = BRAND_OFFICIAL_ROOTS.get(brand, set())
        sender_is_official = (
            from_domain in official_roots
            or any(from_domain == r or from_domain.endswith("." + r) for r in official_roots)
            or bool(re.match(rf"^{re.escape(brand_norm)}\.(com|com\.br|net|org)$",
                             from_domain.replace("-", "")))
        )
        if sender_is_official:
            continue
        if is_trusted(from_domain):
            continue

        report.add(
            "Identidade",
            f"Corpo menciona '{brand}' mas remetente é '{from_domain}' — possível impersonation.",
            30, "critical",
        )
        break
