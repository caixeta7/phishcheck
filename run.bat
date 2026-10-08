@echo off
chcp 65001 >nul 2>&1
setlocal
title PhishCheck — Servidor Local
cd /d "%~dp0"

echo.
echo ============================================
echo   PhishCheck — Verificador de E-mails
echo ============================================
echo.

rem ---------- 1. Python 3.10+ ----------
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if errorlevel 1 (
    echo  [ERRO] Python 3.10+ nao encontrado no PATH.
    echo  Baixe em: https://www.python.org/downloads/
    echo  Na instalacao, marque "Add python.exe to PATH".
    goto :fail
)
echo  [OK] Python

rem ---------- 2. Dependencias Python ----------
rem pip so baixa o que falta; se tudo ja esta instalado, sai em ~1s sem rede.
python -m pip install -q --disable-pip-version-check -r backend\requirements.txt
if errorlevel 1 (
    echo  [ERRO] Falha ao instalar dependencias Python.
    goto :fail
)
echo  [OK] Dependencias Python

rem ---------- 3. Frontend ----------
rem Recompila se dist\ nao existe ou se algum fonte e mais novo que o build.
set "FRONT_STALE=import sys;from pathlib import Path as P;f=P('frontend');d=f/'dist'/'index.html';src=[f/'index.html',f/'package.json',f/'package-lock.json',f/'vite.config.ts',*(f/'src').rglob('*'),*(f/'public').rglob('*')];sys.exit(0 if d.is_file() and d.stat().st_mtime>=max(p.stat().st_mtime for p in src if p.is_file()) else 1)"
python -c "%FRONT_STALE%"
if not errorlevel 1 (
    echo  [OK] Frontend ja compilado
    goto :run
)

where npm >nul 2>&1
if errorlevel 1 (
    if exist "frontend\dist\index.html" (
        echo  [AVISO] Frontend desatualizado, mas Node.js nao encontrado.
        echo          Usando o build existente. Para atualizar, instale: https://nodejs.org
        goto :run
    )
    echo  [ERRO] Frontend nao compilado e Node.js nao encontrado.
    echo  Baixe em: https://nodejs.org
    goto :fail
)

rem npm install so quando o package-lock mudou desde o ultimo install.
fc /b frontend\package-lock.json frontend\node_modules\.lock-stamp >nul 2>&1
if errorlevel 1 (
    echo  Instalando dependencias do frontend...
    call npm --prefix frontend install
    if errorlevel 1 (
        echo  [ERRO] Falha no npm install.
        goto :fail
    )
    copy /y frontend\package-lock.json frontend\node_modules\.lock-stamp >nul
)

echo  Compilando frontend...
call npm --prefix frontend run build
if errorlevel 1 (
    echo  [ERRO] Falha ao compilar o frontend.
    goto :fail
)
echo  [OK] Frontend compilado

rem ---------- 4. Servidor ----------
:run
echo.
python server.py %*
if errorlevel 1 goto :fail
exit /b 0

:fail
echo.
pause
exit /b 1
