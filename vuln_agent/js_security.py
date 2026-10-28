"""Heuristic, read-only checks for JavaScript/TypeScript extension bundles.

These checks identify review indicators, not confirmed exploitable vulnerabilities.
"""
from __future__ import annotations

import re
from pathlib import Path

JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000

_PATTERNS = [
    (
        re.compile(r"""\b(?:window|self|globalThis)\.postMessage\s*\([\s\S]{0,1200}?,\s*["']\*["']\s*(?:,|\))"""),
        "postMessage usa targetOrigin wildcard",
        "Medium",
        "A mensagem é enviada com targetOrigin '*'. Isso pode ser aceitável para dados públicos, mas é arriscado se o payload contiver tokens, dados de sessão ou informações internas.",
        "Use uma origem de destino exata sempre que possível; valide event.origin, event.source e o esquema do payload nos handlers receptores.",
    ),
    (
        re.compile(r"""document\.referrer.{0,300}(?:WEB_ROOT|origin|baseUrl|baseURL)|(?:WEB_ROOT|origin|baseUrl|baseURL).{0,300}document\.referrer""", re.IGNORECASE | re.DOTALL),
        "Possível fallback de origem baseado em document.referrer",
        "Low",
        "O código parece usar document.referrer na resolução de uma origem/base URL. O trecho isolado não prova que a origem seja controlável nem que ocorra requisição indevida.",
        "Valide a origem contra uma allowlist explícita antes de enviar requisições autenticadas; não confie no referrer como autoridade de origem.",
    ),
]


def scan_javascript_patterns(root: Path) -> list[dict]:
    """Scan local JS/TS text files without executing them."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("A origem do código não é uma pasta.")

    findings: list[dict] = []
    examined = 0
    for path in root.rglob("*"):
        if examined >= MAX_FILES:
            break
        if not path.is_file() or path.suffix.lower() not in JS_EXTENSIONS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        examined += 1
        relative = str(path.relative_to(root))

        for pattern, title, severity, description, recommendation in _PATTERNS:
            for match in list(pattern.finditer(text))[:5]:
                line = text.count("\n", 0, match.start()) + 1
                evidence = re.sub(r"\s+", " ", match.group(0)).strip()[:400]
                findings.append({
                    "title": title,
                    "severity": severity,
                    "description": description,
                    "location": f"{relative}:{line}",
                    "evidence": evidence,
                    "recommendation": recommendation,
                    "source": "heurística JavaScript/TypeScript",
                    "confidence": "baixa; exige revisão manual",
                    "triage_status": "needs_manual_review",
                    "triage_reason": "Indicador estático; valide o fluxo de dados e o contexto antes de classificar como vulnerabilidade.",
                })
    return findings
