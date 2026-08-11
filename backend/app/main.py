"""Entrypoint da aplicação FastAPI — serve API + frontend unificados."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core.config import get_settings, PROJECT_ROOT
from app.api.v1.analyze import router as analyze_router
from app.api.v1.trusted import router as trusted_router
from app.services.trusted_service import load_trusted_domains


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_trusted_domains()
    yield


settings = get_settings()

app = FastAPI(
    title="PhishCheck API",
    description="Verificador de e-mails, links e domínios — phishing/spam",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(trusted_router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}

_dist = PROJECT_ROOT / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/assets", StaticFiles(directory=_dist / "assets"), name="assets")

    _spa_path = _dist / "index.html"

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        f = (_dist / full_path).resolve()
        if f.is_file() and _dist.resolve() in f.parents:
            return FileResponse(f)
        return FileResponse(_spa_path)
