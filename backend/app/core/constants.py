"""Constantes de referência extraídas de phishcheck.py.

Mantém as listas e padrões usados pelas heurísticas offline:
TLDs suspeitos, marcas conhecidas, encurtadores, termos de urgência, etc.
"""

import re

# Encurtadores de URL conhecidos
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "shorturl.at", "cutt.ly", "rebrand.ly", "tiny.cc", "rb.gy", "v.gd",
    "lnkd.in", "shorte.st",
    "share.google", "forms.gle", "goo.gle",
}

# Wrappers de segurança corporativos — mapeia host -> parâmetro da querystring
URL_SECURITY_REWRITES = {
    "linkprotect.cudasvc.com": "a",
    "safelinks.protection.outlook.com": "url",
    "link.edgepilot.com": "u",
    "urldefense.proofpoint.com": None,
    "urldefense.com": None,
    "protect.mimecast.com": "r",
}

_PROOFPOINT_V2 = re.compile(r"u=([^&]+)")
_PROOFPOINT_V3 = re.compile(r"/v3/__([^;]+)")

# Termos de urgência / engenharia social (PT-BR)
URGENCY_TERMS_PT = [
    "urgente", "imediatamente", "última chance", "ultima chance", "expira hoje",
    "conta bloqueada", "conta suspensa", "ação necessária", "acao necessaria",
    "clique aqui agora", "verifique agora", "confirme seus dados", "atualize seus dados",
    "validar conta", "validação obrigatória", "validacao obrigatoria",
    "pendência financeira", "pendencia financeira", "fatura vencida",
    "premiado", "você ganhou", "voce ganhou", "parabéns você foi selecionado",
    "evite o bloqueio", "regularize agora", "suspensão da conta", "suspensao da conta",
]

URGENCY_TERMS_EN = [
    "urgent", "immediately", "verify your account", "verify your identity",
    "account suspended", "account locked", "act now", "click here now",
    "limited time", "confirm your password", "update your payment",
    "you have won", "winner", "final notice", "last chance", "unusual activity",
]

# Marcas frequentemente alvo de phishing
COMMON_BRANDS = [
    "google", "microsoft", "office365", "outlook", "apple", "amazon",
    "paypal", "netflix", "facebook", "instagram", "whatsapp", "itau",
    "itaú", "bradesco", "santander", "caixa", "bancodobrasil", "banco-brasil",
    "nubank", "mercadolivre", "mercadopago", "correios", "receita federal",
    "receitafederal", "serasa", "gov.br", "linkedin", "dropbox", "adobe",
    "spotify", "uber", "ifood",
]

# Domínios raiz oficiais por marca
BRAND_OFFICIAL_ROOTS: dict = {
    "google":        {"google.com", "google.com.br", "google"},
    "microsoft":     {"microsoft.com", "microsoftonline.com", "microsoft"},
    "office365":     {"office.com", "office365.com", "microsoftonline.com"},
    "outlook":       {"outlook.com", "outlook.com.br"},
    "apple":         {"apple.com", "icloud.com"},
    "amazon":        {"amazon.com", "amazon.com.br", "aws.com", "amazonaws.com"},
    "paypal":        {"paypal.com", "paypal.com.br"},
    "netflix":       {"netflix.com", "netflix.net"},
    "facebook":      {"facebook.com", "fb.com"},
    "instagram":     {"instagram.com"},
    "whatsapp":      {"whatsapp.com", "whatsapp.net"},
    "linkedin":      {"linkedin.com"},
    "dropbox":       {"dropbox.com", "dropboxstatic.com"},
    "adobe":         {"adobe.com", "adobelogin.com"},
    "spotify":       {"spotify.com"},
    "uber":          {"uber.com"},
    "ifood":         {"ifood.com.br"},
    "mercadolivre":  {"mercadolivre.com", "mercadolivre.com.br"},
    "mercadopago":   {"mercadopago.com", "mercadopago.com.br"},
    "nubank":        {"nubank.com.br", "nubank.com"},
    "itau":          {"itau.com.br", "itau.com"},
    "bradesco":      {"bradesco.com.br"},
    "santander":     {"santander.com.br"},
    "gov.br":        {"gov.br"},
    "serasa":        {"serasa.com.br"},
    "correios":      {"correios.com.br"},
}

# TLDs frequentemente associados a abuso
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "club", "click", "work", "live", "icu",
    "tk", "ml", "ga", "cf", "gq", "buzz", "cam", "sbs", "rest", "quest",
}

# Extensões de anexo de alto risco
DANGEROUS_ATTACHMENT_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".ps1", ".jar", ".msi", ".lnk", ".iso", ".img",
    ".hta", ".reg",
}
MEDIUM_RISK_ATTACHMENT_EXT = {".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm"}

# Punycode prefix
PUNYCODE_PREFIX = "xn--"

# Marcas para checar no título/conteúdo da página de destino
PAGE_BRANDS = [
    "itaú", "itau", "bradesco", "santander", "nubank", "caixa", "banco do brasil",
    "sicredi", "sicoob", "inter", "c6 bank", "mercado pago", "mercado livre",
    "paypal", "amazon", "microsoft", "google", "apple", "netflix", "spotify",
    "docusign", "adobe", "dropbox", "office 365", "outlook", "onedrive",
    "receita federal", "detran", "correios", "serasa", "spc",
]

# Regex para detectar IDs aleatórios e timestamps no assunto
RAND_TOKEN_RE = re.compile(r'[A-Za-z0-9]{6,14}')
TIMESTAMP_SUBJ_RE = re.compile(
    r'\d{1,2}/\d{1,2}/\d{4}.*?\d{1,2}:\d{2}'
    r'|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}'
)

# Marcas de software genéricas ( requerem contexto adicional )
BRAND_SKIP_IF_GENERIC = {"outlook", "office365", "microsoft", "google", "adobe", "dropbox"}

BRAND_SERVICE_CONTEXT = re.compile(
    r"(sign in|log in|login|acesse|clique aqui|review document|verify|confirm|"
    r"your account|sua conta|assinatura|assine|docusign|documento para assinar|"
    r"pending|payment|invoice|fatura|vencimento|boleto|atualiz)",
    re.IGNORECASE,
)

# Provedores de e-mail gratuito
FREE_PROVIDERS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "live.com", "icloud.com", "protonmail.com", "aol.com",
}

# Regex para URL
URL_REGEX = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'\)\]]+
    """
)

# Termos de credenciais no conteúdo da página
CREDENTIAL_TERMS = re.compile(
    r"(senha|password|passcode|pin\b|cpf|cnpj|cartao|card.?number|cvv|cvc"
    r"|token|codigo de seguranca|security code|login|sign.?in|entrar|acessar"
    r"|verificar|confirmar|atualizar|dados bancarios|bank.?account)",
    re.IGNORECASE,
)

REQUESTS_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}
