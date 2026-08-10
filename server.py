"""PhishCheck — Servidor único (princípio intranet).

Uso:
    python server.py            — inicia na porta 8000 e abre o browser
    python server.py --port 9000 — porta customizada
    python server.py --no-browser  — não abre browser automaticamente

Requer:
    - Dependências Python: pip install -r backend/requirements.txt
    - Frontend pré-buildado: cd frontend && npm install && npm run build
      (gera frontend/dist/ que é servido como estáticos)
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import webbrowser
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
BACKEND_DIR = PROJECT_ROOT / "backend"
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"


def _check_frontend_build() -> None:
    if not (FRONTEND_DIST / "index.html").is_file():
        print("=" * 60)
        print("  ERRO: Frontend não encontrado em frontend/dist/")
        print()
        print("  Você precisa compilar o frontend uma única vez:")
        print()
        print("    cd frontend")
        print("    npm install")
        print("    npm run build")
        print()
        print("  Depois rode novamente:  python server.py")
        print("=" * 60)
        sys.exit(1)


def _check_python_deps() -> None:
    missing: list[str] = []
    critical_packages = ["fastapi", "uvicorn", "pydantic", "pydantic_settings",
                         "httpx", "multipart", "dns", "whois", "tldextract",
                         "bs4", "extract_msg"]
    for pkg in critical_packages:
        try:
            __import__(pkg)
        except ImportError:
            display = "python-multipart" if pkg == "multipart" else \
                      "python-whois" if pkg == "whois" else \
                      "dnspython" if pkg == "dns" else \
                      "beautifulsoup4" if pkg == "bs4" else pkg
            missing.append(display)
    if missing:
        print("=" * 60)
        print("  ERRO: Dependências Python ausentes:")
        for m in missing:
            print(f"    - {m}")
        print()
        print("  Instale com:")
        print(f"    pip install -r backend{os.sep}requirements.txt")
        print("=" * 60)
        sys.exit(1)


def _open_browser_delayed(url: str, delay: float = 1.5) -> None:
    def _open():
        import time
        time.sleep(delay)
        webbrowser.open(url)
    threading.Thread(target=_open, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="PhishCheck — Servidor local")
    parser.add_argument("--host", default="127.0.0.1", help="Host (padrão: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Porta (padrão: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Não abrir browser automaticamente")
    parser.add_argument("--reload", action="store_true", help="Modo desenvolvimento com reload")
    args = parser.parse_args()

    _check_frontend_build()
    _check_python_deps()

    sys.path.insert(0, str(BACKEND_DIR))

    import uvicorn

    url = f"http://{args.host}:{args.port}"
    print()
    print("=" * 60)
    print("  PhishCheck — Verificador de E-mails, Links e Domínios")
    print("=" * 60)
    print(f"  Servidor:   {url}")
    print(f"  Modo:       {'desenvolvimento (reload)' if args.reload else 'produção'}")
    if args.host not in ("127.0.0.1", "localhost"):
        print("=" * 60)
        print("  [AVISO] Servidor exposto além de localhost.")
        print("  Sem autenticação, qualquer host da rede pode:")
        print("    - Submeter URLs para análise (superfície SSRF)")
        print("    - Gerenciar a allowlist de domínios confiáveis")
        print("  Use --host 127.0.0.1 (padrão) para uso local seguro.")
    print("=" * 60)
    print()

    if not args.no_browser:
        _open_browser_delayed(url)

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        app_dir=str(BACKEND_DIR),
    )


if __name__ == "__main__":
    main()
