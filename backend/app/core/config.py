"""Configuração da aplicação via variáveis de ambiente."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Threat Intel API keys (opcionais — fallback gracioso se ausentes)
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    abuseipdb_api_key: str = ""

    # Timeouts por verificação (segundos)
    dns_timeout: int = 4
    whois_timeout: int = 8
    threat_intel_timeout: int = 10
    url_fetch_timeout: int = 10

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000", "http://127.0.0.1:8000"]

    # Trusted domains file path
    trusted_domains_file: Path = PROJECT_ROOT / "trusted_domains.txt"

    # Modo online padrão
    online_by_default: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
