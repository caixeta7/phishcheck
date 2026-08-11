# PhishCheck — Verificador de E-mails, Links e Domínios

Aplicação web (localhost) para analisar e-mails, links e domínios e identificar
sinais de **phishing**, **spam** ou conteúdo **legítimo**, combinando heurísticas
offline com verificações online (DNS, WHOIS, SPF/DMARC, Threat Intel).

## Arquitetura

- **Backend:** FastAPI (Python 3.12+) com assincronismo nativo, execução paralela
  de verificações e SSE para progresso em tempo real.
- **Frontend:** React + Vite + Tailwind CSS + Framer Motion, com dark mode,
  design system próprio e microinterações.
- **Threat Intel (gratuito):** VirusTotal v3 (inclui motor Kaspersky),
  Google Safe Browsing v4 e AbuseIPDB. Fallback gracioso para heurística local
  se as API keys não estiverem configuradas.

## Instalação

### Backend

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env  # preencha as API keys (opcionais)
```

### Frontend

```bash
cd frontend
npm install
```

## Como executar

Em dois terminais:

```bash
# Terminal 1 — Backend
cd backend
python -m uvicorn app.main:app --reload --port 8000

# Terminal 2 — Frontend
cd frontend
npm run dev
```

Acesse: http://localhost:5173

## O que o sistema verifica

### Heurísticas offline (sempre ativas)
- IP literal no lugar de domínio
- Uso de `@` na URL para disfarçar o destino real
- HTTP em vez de HTTPS
- Excesso de subdomínios encadeados
- Punycode / ataques de homógrafo (`xn--`)
- Encurtadores de URL (bit.ly, tinyurl, etc.)
- TLDs frequentemente associados a abuso (.xyz, .tk, .top, etc.)
- Domínios "lookalike" que mencionam marcas conhecidas
- Termos de urgência/engenharia social (PT-BR e EN)
- Solicitação direta de dados sensíveis (senha, CVV, CPF, etc.)
- Discrepância entre texto visível de link e destino real (HTML)
- `Reply-To` / `Return-Path` diferentes do remetente (spoofing)
- Nome de exibição imitando marca + provedor gratuito
- Anexos com extensões perigosas ou extensão dupla disfarçada
- Wrappers de segurança corporativos (Barracuda, Safe Links, Proofpoint, Mimecast)

### Verificações online
- **DNS:** registros A, MX, NS do domínio
- **SPF / DMARC:** proteção contra falsificação do remetente
- **WHOIS:** idade do domínio (recém-criados = alerta)
- **VirusTotal v3:** 70+ motores (inclui Kaspersky, BitDefender, etc.)
- **Google Safe Browsing:** listas oficiais de ameaças
- **AbuseIPDB:** reputação de IPs
- **Análise de página de destino:** redirect chain, forms de coleta de credenciais, clones de marcas

## API Keys (opcionais, todas gratuitas)

| Serviço | Onde obter | Rate limit |
|---------|-----------|------------|
| VirusTotal | https://www.virustotal.com/gui/my-apikey | 500 req/dia, 4 req/min |
| Google Safe Browsing | https://developers.google.com/safe-browsing/v4/get-started | 10.000 req/dia |
| AbuseIPDB | https://www.abuseipdb.com/account/api | 1.000 req/dia |

## Veredito

| Pontuação | Veredito |
|-----------|----------|
| 0–9 | 🟢 LEGÍTIMO |
| 10–29 | 🟡 BAIXO RISCO |
| 30–59 | 🟠 SUSPEITO |
| 60–100 | 🔴 ALTO RISCO |

## Estrutura

```
PhishCheck/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # Endpoints (analyze + trusted domains)
│   │   ├── core/            # Config e constantes
│   │   ├── schemas/         # DTOs Pydantic
│   │   ├── services/        # Lógica de análise (email, URL, DNS, Threat Intel)
│   │   └── main.py          # FastAPI app
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── api/             # Cliente HTTP + SSE
│   │   ├── components/      # Componentes de UI
│   │   ├── hooks/           # useAnalysis, useDarkMode
│   │   ├── types/           # TypeScript types
│   │   └── App.tsx          # Layout principal
│   └── package.json
├── trusted_domains.txt      # Allowlist de domínios confiáveis
└── README.md
```

## Limitações

- Heurísticas apontam *sinais* e *probabilidades*, não certezas absolutas.
- Não substitui antivírus ou filtros corporativos. Use como apoio à decisão.
- Verificações online podem falhar por timeout sem que isso indique algo
  sobre o domínio — o sistema registra que não conseguiu verificar.
