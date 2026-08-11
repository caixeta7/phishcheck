@echo off
chcp 65001 >nul 2>&1
title PhishCheck — Servidor Local
cd /d "%~dp0"

echo.
echo ============================================
echo   PhishCheck — Verificador de E-mails
echo ============================================
echo.

if not exist "frontend\dist\index.html" (
    echo  [AVISO] Frontend nao compilado encontrado.
    echo.
    echo  Para compilar o frontend (umaunica vez^):
    echo.
    echo    cd frontend
    echo    npm install
    echo    npm run build
    echo.
    echo  Tentando compilar automaticamente...
    echo.
    cd frontend
    call npm install
    if errorlevel 1 (
        echo.
        echo  [ERRO] Falha ao instalar dependencias do Node.
        echo  Verifique se o Node.js esta instalado.
        echo  Baixe em: https://nodejs.org
        echo.
        pause
        exit /b 1
    )
    call npm run build
    if errorlevel 1 (
        echo.
        echo  [ERRO] Falha ao compilar o frontend.
        echo.
        pause
        exit /b 1
    )
    cd ..
    echo  [OK] Frontend compilado com sucesso.
    echo.
)

python server.py %*

if errorlevel 1 (
    echo.
    echo  [ERRO] O servidor falhou ao iniciar.
    echo  Verifique se as dependencias Python estao instaladas:
    echo.
    echo    pip install -r backend\requirements.txt
    echo.
    pause
)
