"""Gestão da allowlist de domínios confiáveis (trusted_domains.txt)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from app.core.config import get_settings

_trusted_domains: set[str] = set()
_loaded = False


def _resolve_file() -> Path:
    return get_settings().trusted_domains_file


def load_trusted_domains() -> set[str]:
    global _trusted_domains, _loaded
    if _loaded:
        return _trusted_domains

    path = _resolve_file()
    if not path.is_file():
        _loaded = True
        return _trusted_domains

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                _trusted_domains.add(line.lower())

    _loaded = True
    return _trusted_domains


def save_trusted_domains():
    path = _resolve_file()
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Domínios confiáveis — um por linha. Linhas com # são ignoradas.\n")
        for d in sorted(_trusted_domains):
            f.write(d + "\n")


def get_trusted_domains() -> list[str]:
    return sorted(load_trusted_domains())


def add_trusted_domain(domain: str) -> list[str]:
    domain = domain.strip().lower()
    if domain:
        _trusted_domains.add(domain)
        save_trusted_domains()
    return get_trusted_domains()


def remove_trusted_domain(domain: str) -> list[str]:
    domain = domain.strip().lower()
    _trusted_domains.discard(domain)
    save_trusted_domains()
    return get_trusted_domains()


def is_trusted(domain: str) -> bool:
    if not domain:
        return False
    load_trusted_domains()
    domain = domain.lower().strip(".")
    if domain in _trusted_domains:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in _trusted_domains:
            return True
    return False
