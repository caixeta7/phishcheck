"""Parser de e-mails — extrai cabeçalhos, corpo texto/HTML e anexos de .eml/.msg/texto colado.

Extraído e adaptado de phishcheck.py.
"""

from __future__ import annotations

import email
import os
import re
from email import policy
from email.message import Message
from typing import Optional


def parse_eml_bytes(data: bytes) -> Message:
    return email.message_from_bytes(data, policy=policy.default)


def parse_eml_file(path: str) -> Message:
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)


def parse_email_text(raw_text: str) -> Message:
    looks_like_headers = bool(
        re.search(r"^(From|To|Subject|Date):\s*.+$", raw_text, re.MULTILINE | re.IGNORECASE)
    )
    if looks_like_headers:
        return email.message_from_string(raw_text, policy=policy.default)

    msg = email.message.EmailMessage(policy=policy.default)
    msg["From"] = ""
    msg["Subject"] = ""
    msg.set_content(raw_text)
    return msg


def parse_msg_file(path: str) -> Message:
    """Converte .msg (Outlook) para email.message.Message via extract_msg."""
    try:
        import extract_msg
    except ImportError:
        raise RuntimeError(
            "Para analisar arquivos .msg é necessário instalar 'extract_msg': pip install extract_msg"
        )

    m = extract_msg.Message(path)
    header_msg = m.header

    body_text = m.body or ""
    raw_html = m.htmlBody
    body_html = ""
    if raw_html:
        body_html = raw_html.decode("utf-8", errors="ignore") if isinstance(raw_html, bytes) else str(raw_html)

    _msg_data = {
        "body_text": body_text,
        "body_html": body_html,
        "attachments": [],
    }

    try:
        for att in (m.attachments or []):
            filename = getattr(att, "name", None) or ""
            if filename:
                _msg_data["attachments"].append(filename)
    except Exception:
        pass

    header_msg._phishcheck_extra = _msg_data
    return header_msg


def get_body_text_and_html(msg: Message) -> tuple[str, str]:
    """Extrai corpo em texto puro e HTML de um email.message.Message."""
    body_text = ""
    body_html = ""

    if hasattr(msg, "_phishcheck_extra"):
        extra = msg._phishcheck_extra
        return extra.get("body_text", ""), extra.get("body_html", "")

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                continue
            try:
                payload = part.get_content()
            except Exception:
                continue
            if ctype == "text/plain" and not body_text:
                body_text = payload if isinstance(payload, str) else ""
            elif ctype == "text/html" and not body_html:
                body_html = payload if isinstance(payload, str) else ""
    else:
        ctype = msg.get_content_type()
        try:
            payload = msg.get_content()
        except Exception:
            payload = ""
        if ctype == "text/html":
            body_html = payload if isinstance(payload, str) else ""
        else:
            body_text = payload if isinstance(payload, str) else ""

    if not body_text and body_html:
        body_text = re.sub(r"<[^>]+>", " ", body_html)

    return body_text, body_html


def get_attachments(msg: Message) -> list[str]:
    """Extrai nomes de arquivos de anexos da mensagem."""
    if hasattr(msg, "_phishcheck_extra"):
        return msg._phishcheck_extra.get("attachments", [])

    filenames = []
    if not hasattr(msg, "iter_attachments"):
        return filenames
    try:
        for part in msg.iter_attachments():
            filename = part.get_filename() or ""
            if filename:
                filenames.append(filename)
    except Exception:
        pass
    return filenames
