"""Secret detection and masking for evidence.

Everything VulnAgent emits (UI, JSON, Markdown, SARIF and the AI payload) goes through
``redact_text``: a security report must not become a new credential leak.
All quantifiers are bounded so hostile files cannot trigger ReDoS.
"""
from __future__ import annotations

import re

# (rule_id, label shown to the user, severity, regex)
SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("aws-access-key-id", "chave de acesso AWS", "High",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", "token do GitHub", "High",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("slack-token", "token do Slack", "High",
     re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,250}")),
    ("stripe-secret-key", "chave secreta Stripe", "High",
     re.compile(r"\b[rs]k_live_[0-9A-Za-z]{16,247}\b")),
    ("openai-api-key", "chave de API OpenAI", "High",
     re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,200}T3BlbkFJ[A-Za-z0-9_-]{16,200}")),
    ("anthropic-api-key", "chave de API Anthropic", "High",
     re.compile(r"\bsk-ant-[a-z]{2,10}\d{2}-[A-Za-z0-9_-]{80,200}")),
    ("private-key", "chave privada", "High",
     re.compile(r"-----BEGIN (?:[A-Z0-9]{1,20} ){0,2}PRIVATE KEY(?: BLOCK)?-----")),
    ("google-api-key", "chave de API Google", "Medium",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])")),
    ("jwt", "JSON Web Token", "Medium",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}")),
]

# Assignments such as SECRET_KEY = "...", "password": "...", apiToken: '...'.
ASSIGNED_SECRET = re.compile(
    r"(?i)(?<![\w.-])(?P<key>[\w.-]{0,40}"
    r"(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
    r"[\w.-]{0,40})[\"']?\s*(?::=|=>|[:=])\s*(?P<q>[\"'`])(?P<value>[^\"'`\s]{8,512})(?P=q)"
)

_PEM_BODY = re.compile(
    r"(-----BEGIN (?:[A-Z0-9]{1,20} ){0,2}PRIVATE KEY(?: BLOCK)?-----)(?:(?!-----END)[\s\S]){1,20000}"
)
_PLACEHOLDER_TOKENS = (
    "changeme", "change_me", "change-me", "placeholder", "example", "dummy", "your_", "your-",
    "redacted", "xxxx", "****", "${", "{{", "%(", "<", ">", "process.env", "os.environ",
)


def mask(value: str, keep: int = 4) -> str:
    """Keep a short prefix (to identify the key type) and hide the rest, including length."""
    if len(value) <= keep * 2:
        return "*" * 8
    return f"{value[:keep]}{'*' * 8}"


def is_placeholder(value: str) -> bool:
    lower = value.lower()
    if any(token in lower for token in _PLACEHOLDER_TOKENS):
        return True
    if lower.startswith(("http://", "https://")) and "@" not in lower:
        return True
    if lower.startswith(("/", "./", "../")):
        return True
    return len(set(value)) <= 2


def redact_text(text: str) -> str:
    """Mask every recognised secret in ``text``. Idempotent."""
    if not text:
        return text
    text = _PEM_BODY.sub(r"\1 [conteúdo removido]", text)
    for rule_id, _label, _severity, pattern in SECRET_PATTERNS:
        if rule_id == "private-key":
            continue
        text = pattern.sub(lambda m: mask(m.group(0)), text)

    def _mask_assignment(match: re.Match[str]) -> str:
        value = match.group("value")
        if is_placeholder(value):
            return match.group(0)
        start, end = match.span("value")
        offset = match.start()
        whole = match.group(0)
        return whole[: start - offset] + mask(value) + whole[end - offset:]

    return ASSIGNED_SECRET.sub(_mask_assignment, text)
