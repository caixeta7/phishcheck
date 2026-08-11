"""Endpoints da API v1 — análise de e-mail/URL/domínio + SSE de progresso."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import base64
from typing import AsyncGenerator

from email.message import Message

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse

from app.schemas.request import AnalysisType
from app.schemas.response import AnalysisReportDTO, ProgressStepDTO, FindingDTO, Severity
from app.services.report_builder import AnalysisReport
from app.services.email_parser import (
    parse_eml_bytes,
    parse_eml_file,
    parse_email_text,
    parse_msg_file,
    get_body_text_and_html,
    get_attachments,
)
from app.services.email_analyzer import (
    analyze_email_headers,
    analyze_email_body,
    analyze_email_html_links,
    analyze_attachments,
    check_brand_sender_mismatch,
    extract_domain,
    get_fqdn,
    dedup_urls,
)
from app.services.url_analyzer import analyze_url_heuristics, analyze_url_content
from app.services.network_checker import run_online_domain_checks
from app.services.threat_intel import run_threat_intel_checks

router = APIRouter(prefix="/api/v1")


def _parse_uploaded_file(file_bytes: bytes, filename: str | None = None) -> Message:
    """Detecta se é .msg ou .eml e faz o parsing correto."""
    is_msg = False
    if filename and filename.lower().endswith(".msg"):
        is_msg = True
    elif file_bytes.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        is_msg = True

    if is_msg:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".msg") as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name
        try:
            return parse_msg_file(tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    else:
        return parse_eml_bytes(file_bytes)


def _emit_step(step: str, status: str, message: str | None = None, findings: list[FindingDTO] | None = None) -> str:
    """Formata um evento SSE."""
    data = ProgressStepDTO(step=step, status=status, message=message, findings=findings)
    return f"data: {data.model_dump_json()}\n\n"


async def _run_analysis_pipeline(
    analysis_type: AnalysisType,
    content: str = "",
    file_bytes: bytes | None = None,
    filename: str | None = None,
    online: bool = True,
) -> AnalysisReport:
    """Pipeline completo de análise. Retorna o AnalysisReport preenchido."""
    report = AnalysisReport("Análise")

    if analysis_type == AnalysisType.EMAIL_TEXT:
        msg = parse_email_text(content)
    elif analysis_type == AnalysisType.EMAIL_FILE:
        if not file_bytes:
            raise HTTPException(status_code=400, detail="Arquivo não fornecido")
        try:
            msg = _parse_uploaded_file(file_bytes, filename)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Erro ao parsear arquivo: {e}")
    elif analysis_type == AnalysisType.URL:
        return await _analyze_single_url(content, online, report)
    elif analysis_type == AnalysisType.DOMAIN:
        return await _analyze_single_domain(content, online, report)
    else:
        raise HTTPException(status_code=400, detail="Tipo de análise inválido")

    from_domain, from_addr, subject = analyze_email_headers(msg, report)
    body_text, body_html = get_body_text_and_html(msg)
    attachments = get_attachments(msg)

    urls_from_text = analyze_email_body(body_text, report)
    urls_from_html = analyze_email_html_links(body_html, report)
    analyze_attachments(attachments, report)
    check_brand_sender_mismatch(body_text, body_html, from_domain, report)

    all_urls = dedup_urls(list(dict.fromkeys(urls_from_text + urls_from_html)))
    report.urls_found = all_urls

    domains_seen = set()
    for u in all_urls:
        reg_domain, host = analyze_url_heuristics(u, report)
        if reg_domain:
            domains_seen.add(reg_domain)
    if from_domain:
        domains_seen.add(from_domain)
    report.domains_checked = sorted(domains_seen)

    if online:
        await asyncio.gather(
            *[run_online_domain_checks(d, report) for d in domains_seen],
            return_exceptions=True,
        )
        if all_urls:
            await run_threat_intel_checks(all_urls, list(domains_seen), [], report)
    else:
        report.add("Modo", "Análise OFFLINE — sem DNS/WHOIS/Threat Intel.", 0, "info")

    return report


async def _analyze_single_url(url: str, online: bool, report: AnalysisReport) -> AnalysisReport:
    report.subject_label = f"URL: {url}"
    reg_domain, host = analyze_url_heuristics(url, report)

    domains_seen = set()
    if reg_domain:
        domains_seen.add(reg_domain)
    report.domains_checked = sorted(domains_seen)
    report.urls_found = [url]

    if online and reg_domain:
        await run_online_domain_checks(reg_domain, report)
        await run_threat_intel_checks([url], list(domains_seen), [], report)
        await asyncio.to_thread(analyze_url_content, url, report)
    elif not online:
        report.add("Modo", "Análise OFFLINE.", 0, "info")

    return report


async def _analyze_single_domain(domain: str, online: bool, report: AnalysisReport) -> AnalysisReport:
    domain = get_fqdn(domain)
    registrable = extract_domain(domain)
    report.subject_label = f"Domínio: {domain}"

    fake_url = "http://" + domain
    analyze_url_heuristics(fake_url, report)

    report.domains_checked = [registrable]

    if online:
        await run_online_domain_checks(registrable, report)
        await run_threat_intel_checks([], [registrable], [], report)
    else:
        report.add("Modo", "Análise OFFLINE.", 0, "info")

    return report


@router.post("/analyze", response_model=AnalysisReportDTO)
async def analyze(
    analysis_type: AnalysisType = Form(...),
    content: str = Form(""),
    online: bool = Form(True),
    file: UploadFile | None = File(None),
):
    """Endpoint síncrono — retorna o relatório completo após análise."""
    file_bytes = None
    filename = None
    if file:
        file_bytes = await file.read()
        filename = file.filename

    report = await _run_analysis_pipeline(analysis_type, content, file_bytes, filename, online)
    return report.to_dto()


@router.post("/analyze/stream")
async def analyze_stream(
    analysis_type: AnalysisType = Form(...),
    content: str = Form(""),
    online: bool = Form(True),
    file: UploadFile | None = File(None),
):
    """Endpoint SSE — envia progresso em tempo real + relatório final."""
    async def event_generator() -> AsyncGenerator[str, None]:
        yield _emit_step("init", "running", f"Iniciando análise: {analysis_type.value}")

        file_bytes = None
        filename = None
        if file:
            file_bytes = await file.read()
            filename = file.filename

        yield _emit_step("parsing", "running", "Extraindo cabeçalhos e corpo")

        msg = None
        if analysis_type == AnalysisType.EMAIL_TEXT:
            msg = parse_email_text(content)
        elif analysis_type == AnalysisType.EMAIL_FILE:
            if not file_bytes:
                yield _emit_step("parsing", "error", "Arquivo não fornecido")
                return
            try:
                msg = _parse_uploaded_file(file_bytes, filename)
            except Exception as e:
                yield _emit_step("parsing", "error", f"Erro ao parsear arquivo: {e}")
                return
        elif analysis_type in (AnalysisType.URL, AnalysisType.DOMAIN):
            msg = None
        else:
            yield _emit_step("init", "error", "Tipo inválido")
            return

        yield _emit_step("parsing", "done", "Cabeçalhos extraídos")

        report = AnalysisReport("Análise")
        domains_seen: set[str] = set()

        if msg is not None:
            yield _emit_step("headers", "running", "Analisando remetente (From, Reply-To, Return-Path)")
            from_domain, from_addr, subject = analyze_email_headers(msg, report)
            yield _emit_step("headers", "done", f"Remetente: {from_addr or 'não identificado'}")

            body_text, body_html = get_body_text_and_html(msg)
            attachments = get_attachments(msg)

            yield _emit_step("body", "running", "Analisando corpo, links e anexos")
            urls_from_text = analyze_email_body(body_text, report)
            urls_from_html = analyze_email_html_links(body_html, report)
            analyze_attachments(attachments, report)
            check_brand_sender_mismatch(body_text, body_html, from_domain, report)
            all_urls = dedup_urls(list(dict.fromkeys(urls_from_text + urls_from_html)))
            report.urls_found = all_urls
            yield _emit_step("body", "done", f"Encontradas {len(all_urls)} URL(s), {len(attachments)} anexo(s)")

            yield _emit_step("heuristics", "running", "Aplicando heurísticas de URL")
            for u in all_urls:
                reg_domain, host = analyze_url_heuristics(u, report)
                if reg_domain:
                    domains_seen.add(reg_domain)
            if from_domain:
                domains_seen.add(from_domain)
            report.domains_checked = sorted(domains_seen)
            yield _emit_step("heuristics", "done", f"{len(domains_seen)} domínio(s) analisado(s)")

        elif analysis_type == AnalysisType.URL:
            yield _emit_step("heuristics", "running", "Analisando heurísticas de URL")
            reg_domain, host = analyze_url_heuristics(content, report)
            if reg_domain:
                domains_seen.add(reg_domain)
            report.domains_checked = sorted(domains_seen)
            report.urls_found = [content]
            yield _emit_step("heuristics", "done", "Heurísticas aplicadas")

        elif analysis_type == AnalysisType.DOMAIN:
            domain_clean = get_fqdn(content)
            registrable = extract_domain(domain_clean)
            analyze_url_heuristics("http://" + domain_clean, report)
            if registrable:
                domains_seen.add(registrable)
            report.domains_checked = sorted(domains_seen)
            yield _emit_step("heuristics", "done", "Heurísticas aplicadas")

        if online and domains_seen:
            yield _emit_step("dns", "running", "Consultando DNS, SPF/DMARC, WHOIS")
            await asyncio.gather(
                *[run_online_domain_checks(d, report) for d in domains_seen],
                return_exceptions=True,
            )
            yield _emit_step("dns", "done", "Verificações de rede concluídas")

            urls_list = report.urls_found
            if urls_list:
                yield _emit_step("threat_intel", "running", "Consultando VirusTotal + Safe Browsing")
                await run_threat_intel_checks(urls_list, list(domains_seen), [], report)
                yield _emit_step("threat_intel", "done", "Threat Intel concluído")

            if analysis_type == AnalysisType.URL:
                yield _emit_step("content", "running", "Analisando conteúdo da página de destino")
                await asyncio.to_thread(analyze_url_content, content, report)
                yield _emit_step("content", "done", "Análise de página concluída")

        elif not online:
            report.add("Modo", "Análise OFFLINE.", 0, "info")
            yield _emit_step("online", "done", "Modo offline — sem verificações de rede")

        yield _emit_step("verdict", "done", f"Score: {report.score}/100 — {report.verdict_label}")

        final_data = report.to_dto().model_dump_json()
        yield f"event: result\ndata: {final_data}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
