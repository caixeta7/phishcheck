"""SSRF Guard — valida URLs antes de fetch HTTP para impedir acesso a rede interna.

Camadas de defesa:
1. validate_url() — esquema, porta, resolução DNS, denylist de IPs privados.
2. SafeRedirectSession — re-valida cada redirect antes de seguir.
3. limite de tamanho de resposta (aplicado no caller).

Depois de validate_url(), um atacante que submete http://127.0.0.1/ ou
http://169.254.169.254/ recebe UnsafeUrlError antes que qualquer TCP
seja estabelecido.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse, urljoin

import requests


class UnsafeUrlError(ValueError):
    """URL rejeitada pelo guard de SSRF."""


PRIVATE_PREFIXES = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {None, 80, 443}


def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip in net for net in PRIVATE_PREFIXES)


def _check_host(host: str, port: int | None) -> None:
    if not host:
        raise UnsafeUrlError("Host vazio")

    try:
        raw_ip = ipaddress.ip_address(host)
    except ValueError:
        raw_ip = None

    if raw_ip is not None:
        if _is_blocked(raw_ip):
            raise UnsafeUrlError(f"Host é IP bloqueado: {raw_ip}")
        return

    try:
        infos = socket.getaddrinfo(host, port or 80, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"Não foi possível resolver host: {host} ({exc})") from exc

    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if _is_blocked(ip):
            raise UnsafeUrlError(f"Host '{host}' resolve para IP bloqueado: {ip}")


def validate_url(url: str) -> str:
    """Valida URL contra SSRF. Retorna URL se OK, UnsafeUrlError se bloqueada."""
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeUrlError(f"Esquema não permitido: '{parsed.scheme}'. Apenas http e https.")

    host = parsed.hostname
    if not host:
        raise UnsafeUrlError("URL sem host válido")

    port = parsed.port
    if port not in ALLOWED_PORTS:
        raise UnsafeUrlError(f"Porta não permitida: {port}. Apenas 80 e 443.")

    _check_host(host, port)
    return url


class SafeRedirectSession(requests.Session):
    """Session que re-valida cada redirect contra validate_url().

    Sobrescreve get_redirect_target() — o método que requests chama a cada
    hop para obter a URL do redirect. Se validar, segue; se bloquear,
    retorna None e o loop de redirects para.
    """

    def get_redirect_target(self, resp):
        target = super().get_redirect_target(resp)
        if target is None:
            return None
        base = resp.url
        absolute = urljoin(base, target)
        try:
            validate_url(absolute)
        except UnsafeUrlError:
            return None
        return target
