"""Heuristic, read-only checks for JavaScript/TypeScript extension bundles.

These checks identify review indicators, not confirmed exploitable vulnerabilities.
"""
from __future__ import annotations

import re
from itertools import islice
from pathlib import Path

from vuln_agent.findings import make_finding
from vuln_agent.fs import iter_files

JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000
MAX_MATCHES = 5
HANDLER_SCAN_LIMIT = 6000

_PATTERNS = [
    (
        re.compile(r"""\b(?:window|self|globalThis)\.postMessage\s*\([\s\S]{0,1200}?,\s*["']\*["']\s*(?:,|\))"""),
        "postMessage usa targetOrigin wildcard",
        "Medium",
        "A mensagem é enviada com targetOrigin '*'. Isso pode ser aceitável para dados públicos, mas é arriscado se o payload contiver tokens, dados de sessão ou informações internas.",
        "Use uma origem de destino exata sempre que possível; valide event.origin, event.source e o esquema do payload nos handlers receptores.",
        "vulnagent.js.postmessage-wildcard",
    ),
    (
        re.compile(r"""document\.referrer.{0,300}(?:WEB_ROOT|origin|baseUrl|baseURL)|(?:WEB_ROOT|origin|baseUrl|baseURL).{0,300}document\.referrer""", re.IGNORECASE | re.DOTALL),
        "Possível fallback de origem baseado em document.referrer",
        "Low",
        "O código parece usar document.referrer na resolução de uma origem/base URL. O trecho isolado não prova que a origem seja controlável nem que ocorra requisição indevida.",
        "Valide a origem contra uma allowlist explícita antes de enviar requisições autenticadas; não confie no referrer como autoridade de origem.",
        "vulnagent.js.referrer-origin-fallback",
    ),
]

# Inline handlers only: a handler passed by reference has its body elsewhere and cannot be judged here.
_MESSAGE_LISTENER = re.compile(
    r"""addEventListener\s*\(\s*["']message["']\s*,\s*(?:async\s+)?"""
    r"""(?:function\b[\w$\s]*\([^)]{0,200}\)|\([^)]{0,200}\)\s*=>|[\w$]+\s*=>)\s*\{"""
)
_TRIAGE = {
    "triage_status": "needs_manual_review",
    "triage_reason": "Indicador estático; valide o fluxo de dados e o contexto antes de classificar como vulnerabilidade.",
}


def _handler_source(text: str, open_brace: int) -> str:
    """Return the brace-balanced block starting at ``open_brace`` (bounded)."""
    depth = 0
    end = min(len(text), open_brace + HANDLER_SCAN_LIMIT)
    for i in range(open_brace, end):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace:i + 1]
    return text[open_brace:end]


def _unchecked_message_listeners(text: str) -> list[re.Match[str]]:
    unchecked = []
    for match in _MESSAGE_LISTENER.finditer(text):
        handler = match.group(0) + _handler_source(text, match.end() - 1)
        if "origin" not in handler:
            unchecked.append(match)
        if len(unchecked) >= MAX_MATCHES:
            break
    return unchecked


def _js_finding(title, severity, description, recommendation, rule_id, location, evidence):
    return make_finding(title, severity, description, location, evidence, recommendation,
                        "heurística JavaScript/TypeScript", "baixa; exige revisão manual",
                        rule_id=rule_id, **_TRIAGE)


def scan_javascript_patterns(root: Path) -> list[dict]:
    """Scan local JS/TS text files without executing them."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("A origem do código não é uma pasta.")

    findings: list[dict] = []
    files = iter_files(root, lambda p: p.suffix.lower() in JS_EXTENSIONS,
                       skip_dirs=SKIP_DIRS, max_files=MAX_FILES, max_bytes=MAX_FILE_BYTES)
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = path.relative_to(root).as_posix()

        def location(match):
            return f"{relative}:{text.count(chr(10), 0, match.start()) + 1}"

        def snippet(match):
            return re.sub(r"\s+", " ", match.group(0)).strip()[:400]

        for pattern, title, severity, description, recommendation, rule_id in _PATTERNS:
            for match in islice(pattern.finditer(text), MAX_MATCHES):
                findings.append(_js_finding(title, severity, description, recommendation, rule_id,
                                            location(match), snippet(match)))
        for match in _unchecked_message_listeners(text):
            findings.append(_js_finding(
                "Listener de mensagens sem verificação aparente de origem", "Medium",
                "Um handler de 'message' definido inline não referencia event.origin. Qualquer janela/iframe "
                "pode enviar mensagens a ele; se o payload chegar a DOM, storage ou requisições autenticadas, "
                "pode haver XSS ou vazamento de dados.",
                "Compare event.origin com uma allowlist exata (e valide event.source e o formato do payload) "
                "antes de processar a mensagem.",
                "vulnagent.js.message-listener-without-origin-check", location(match), snippet(match)))
    return findings
