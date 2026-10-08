"""Self-check das heurísticas. Rodar: cd backend && python -m tests.test_heuristics (ou pytest)."""

import asyncio

from app.services import network_checker
from app.services.email_analyzer import analyze_email_html_links, extract_domain
from app.services.report_builder import AnalysisReport
from app.services.url_analyzer import analyze_url_heuristics, unwrap_security_rewrite


def test_extract_domain():
    assert extract_domain("https://login.itau.com.br/x") == "itau.com.br"
    assert extract_domain("Fulano <a@mail.example.co.uk>") == "example.co.uk"
    assert extract_domain("sub.example.com:8080") == "example.com"


def test_unwrap_only_strips_www_prefix():
    # lstrip("www.") transformava "web.example.com" em "eb.example.com"
    assert unwrap_security_rewrite("https://web.example.com/a") == ("https://web.example.com/a", None)
    real, provider = unwrap_security_rewrite(
        "https://www.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.tk%2Fx"
    )
    assert (real, provider) == ("https://evil.tk/x", "Microsoft Safe Links")


def _score(*urls: str) -> int:
    r = AnalysisReport()
    for u in urls:
        analyze_url_heuristics(u, r)
    return r.score


def test_repeated_rule_counts_once():
    one = _score("http://a.example.com/x")
    assert one == 10  # só "HTTP"
    assert _score(*(f"http://s{i}.example.com/x" for i in range(10))) == one


def test_encoded_url_only_flags_obfuscation():
    assert _score("https://example.com/a%20b?next=https%3A%2F%2Fexample.org") == 0
    assert _score("https://example.com/%6c%6f%67%69%6e") > 0  # "login" codificado


def test_security_wrapper_is_free():
    assert _score("https://www.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com") == 0


def test_email_auth_only_for_sender():
    calls = []
    names = ("check_spf_dmarc", "check_dns_records", "check_whois_age")
    orig = {n: getattr(network_checker, n) for n in names}

    async def spf(domain, report):
        calls.append(domain)

    async def noop(*a):
        pass

    network_checker.check_spf_dmarc = spf
    network_checker.check_dns_records = network_checker.check_whois_age = noop
    try:
        r = AnalysisReport()
        asyncio.run(network_checker.run_online_domain_checks("cdn.example", r))
        asyncio.run(network_checker.run_online_domain_checks("sender.example", r, email_auth=True))
    finally:
        for n, f in orig.items():
            setattr(network_checker, n, f)
    assert calls == ["sender.example"]


def test_html_link_mismatch_unquoted_href():
    r = AnalysisReport()
    hrefs = analyze_email_html_links("<a href=https://evil.tk/x><b>www.itau.com.br</b></a>", r)
    assert hrefs == ["https://evil.tk/x"]
    assert any(f.rule == "html.link_mismatch" for f in r.findings)


def test_ip_skips_domain_checks():
    r = AnalysisReport()
    asyncio.run(network_checker.run_online_domain_checks("203.0.113.5", r, email_auth=True))
    assert r.findings == []


if __name__ == "__main__":
    test_html_link_mismatch_unquoted_href()
    test_ip_skips_domain_checks()
    test_extract_domain()
    test_unwrap_only_strips_www_prefix()
    test_repeated_rule_counts_once()
    test_encoded_url_only_flags_obfuscation()
    test_security_wrapper_is_free()
    test_email_auth_only_for_sender()
    print("ok")
