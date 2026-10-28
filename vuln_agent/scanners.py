from __future__ import annotations
import json, os, re, shutil, subprocess
from itertools import islice
from pathlib import Path

from vuln_agent.findings import make_finding as _finding
from vuln_agent.fs import iter_files
from vuln_agent.redaction import ASSIGNED_SECRET, SECRET_PATTERNS, is_placeholder, mask
# Re-exported for backward compatibility with callers that import them from this module.
from vuln_agent.web import scan_site, validate_site_url

__all__ = ["scan_code", "parse_osv_results", "scan_site", "validate_site_url"]

MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000
MAX_MATCHES_PER_RULE = 5
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".next"}
TEXT_EXTS = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte", ".java", ".kt", ".php",
             ".rb", ".go", ".rs", ".cs", ".swift", ".c", ".cpp", ".h", ".html", ".sql", ".yaml", ".yml", ".json",
             ".toml", ".ini", ".cfg", ".properties", ".tf", ".tfvars", ".env", ".config", ".xml", ".sh", ".ps1",
             ".bat", ".pem", ".key"}
TEXT_NAMES = {".env", "Dockerfile", "requirements.txt", "Pipfile", "package-lock.json", "yarn.lock", "pom.xml",
              "Gemfile.lock", "go.sum", ".npmrc", ".pypirc", ".netrc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
PY = frozenset({".py"})
JS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte", ".html"})
OSV_SOURCE_LIMIT = 50


def _is_env_file(name: str) -> bool:
    return name == ".env" or (name.startswith(".env.") and not name.endswith(ENV_TEMPLATE_SUFFIXES))


def _accept(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTS or path.name in TEXT_NAMES or _is_env_file(path.name)


def _walk_files(root: Path):
    return iter_files(root, _accept, skip_dirs=SKIP_DIRS, max_files=MAX_FILES, max_bytes=MAX_FILE_BYTES)


def _rule(rule_id, pattern, title, severity, description, recommendation, exts=None):
    return {"id": "vulnagent." + rule_id, "regex": re.compile(pattern), "title": title, "severity": severity,
            "description": description, "recommendation": recommendation, "exts": exts}


RULES = [
    _rule("eval", r"(?<![\w.$])eval\s*\(", "Uso de eval()", "High",
          "eval pode executar conteúdo controlado por entrada externa.",
          "Evite eval; use parsing seguro ou uma lista explícita de operações."),
    _rule("sql-injection",
          r"(?i)\.execute(?:many)?\s*\(\s*(?:f\"[^\"\n]{0,500}\{|f'[^'\n]{0,500}\{" +
          r"|(?:\"[^\"\n]{0,500}\"|'[^'\n]{0,500}')\s*(?:%\s*[\w(]|\+\s*[\w(]|\.format\s*\())",
          "Possível SQL Injection", "High",
          "A consulta SQL parece ser montada por concatenação, f-string, .format() ou operador %.",
          "Use consultas parametrizadas (execute(sql, params)) e evite concatenar entrada não confiável."),
    _rule("inner-html", r"\b(?:innerHTML|outerHTML)\s*\+?=(?!=)", "Atribuição a innerHTML", "Medium",
          "Atribuir HTML não confiável a innerHTML pode permitir XSS.",
          "Prefira textContent ou sanitização robusta com biblioteca reconhecida.", JS),
    _rule("dangerously-set-inner-html", r"\bdangerouslySetInnerHTML\b", "Uso de dangerouslySetInnerHTML", "Medium",
          "O React insere HTML bruto sem escapar; com dados não confiáveis isso leva a XSS.",
          "Evite HTML bruto ou sanitize com DOMPurify antes de renderizar.", JS),
    _rule("document-write", r"\bdocument\.write(?:ln)?\s*\(", "Uso de document.write", "Low",
          "document.write com dados não confiáveis pode permitir XSS e prejudica o carregamento da página.",
          "Manipule o DOM com createElement/textContent.", JS),
    _rule("js-dynamic-code", r"\bnew\s+Function\s*\(|\b(?:setTimeout|setInterval)\s*\(\s*[\"'`]",
          "Execução dinâmica de código JavaScript", "Medium",
          "new Function() ou setTimeout/setInterval com string avaliam texto como código.",
          "Passe funções em vez de strings e evite construir código dinamicamente.", JS),
    _rule("shell-command",
          r"\b(?:subprocess\.(?:run|call|check_call|check_output|Popen)|Popen)\s*\([^)]{0,500}shell\s*=\s*True" +
          r"|\bos\.(?:system|popen)\s*\(",
          "Execução de comando via shell", "Medium",
          "Comandos executados pelo shell permitem injeção se qualquer parte vier de entrada externa.",
          "Use subprocess com lista de argumentos e shell=False; nunca interpole entrada no comando.", PY),
    _rule("unsafe-deserialization",
          r"\b(?:pickle|cPickle|dill|marshal)\.loads?\s*\(|\byaml\.unsafe_load\s*\(" +
          r"|\byaml\.load(?:_all)?\s*\((?![^)]{0,300}Safe)",
          "Desserialização insegura", "High",
          "pickle/marshal e yaml.load sem SafeLoader podem executar código ao carregar dados não confiáveis.",
          "Use formatos de dados (JSON) ou yaml.safe_load; nunca desserialize pickle de origem externa.", PY),
    _rule("jwt-verification-disabled",
          r"(?i)[\"']?verify_signature[\"']?\s*:\s*False|algorithms\s*=\s*\[\s*[\"']none[\"']\s*\]",
          "Verificação de assinatura JWT desativada", "High",
          "Tokens JWT aceitos sem verificar assinatura (ou com alg 'none') podem ser forjados.",
          "Sempre verifique a assinatura com uma lista explícita de algoritmos seguros."),
    _rule("tls-verification-disabled",
          r"(?i)\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[=:]\s*[\"']?0" +
          r"|InsecureSkipVerify\s*:\s*true|ssl\._create_unverified_context|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b",
          "Validação TLS desativada", "Medium",
          "A validação do certificado TLS parece desativada.",
          "Mantenha a validação TLS habilitada e corrija a cadeia de certificados."),
    _rule("weak-hash",
          r"\bhashlib\.(?:md5|sha1)\s*\((?![^)]{0,200}usedforsecurity\s*=\s*False)" +
          r"|createHash\(\s*[\"'](?:md5|sha1)[\"']|MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"",
          "Hash criptográfico fraco (MD5/SHA-1)", "Low",
          "MD5 e SHA-1 não devem proteger senhas, assinaturas ou integridade contra adversários.",
          "Use SHA-256+ para integridade e Argon2/bcrypt/scrypt para senhas."),
    _rule("debug-enabled", r"(?i)debug\s*=\s*True\b", "Modo debug habilitado", "Medium",
          "Modo de depuração pode expor detalhes internos se habilitado em produção.",
          "Desabilite debug em produção e configure logs sem dados sensíveis."),
    _rule("cors-wildcard", r"(?i)Access-Control-Allow-Origin[\"']?\s*[:,=]\s*[\"']\*", "CORS permissivo", "Low",
          "Foi encontrado um padrão que pode permitir origem ampla.",
          "Restrinja CORS às origens necessárias; avalie separadamente credenciais e métodos."),
]


def _line_of(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def _scan_secrets(content: str, rel: str) -> list[dict]:
    findings = []
    for rule_id, label, severity, pattern in SECRET_PATTERNS:
        for match in islice(pattern.finditer(content), MAX_MATCHES_PER_RULE):
            evidence = match.group(0) if rule_id == "private-key" else mask(match.group(0))
            findings.append(_finding(
                f"Possível segredo exposto: {label}", severity,
                f"O valor tem o formato de {label}. Se for real, considere a credencial comprometida.",
                f"{rel}:{_line_of(content, match.start())}", evidence,
                "Revogue/rotacione a credencial, remova-a do código e do histórico do Git e use um gerenciador de segredos.",
                "heurística local", "média", rule_id="vulnagent.secret." + rule_id))
    count = 0
    for match in ASSIGNED_SECRET.finditer(content):
        if count >= MAX_MATCHES_PER_RULE:
            break
        value = match.group("value")
        # Skip placeholders and values already reported above as a known token format.
        if is_placeholder(value) or any(pattern.search(value) for *_meta, pattern in SECRET_PATTERNS):
            continue
        count += 1
        findings.append(_finding(
            "Possível segredo hardcoded", "High", "Foi encontrado um valor literal associado a credenciais/segredos.",
            f"{rel}:{_line_of(content, match.start())}", match.group(0)[:250],
            "Remova o segredo do código, revogue-o se for real e use um gerenciador de segredos/variáveis de ambiente.",
            "heurística local", "baixa a média", rule_id="vulnagent.secret.hardcoded-assignment"))
    return findings


def _scan_with_rules(files, root: Path) -> list[dict]:
    findings = []
    for path in files:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        for rule in RULES:
            if rule["exts"] is not None and suffix not in rule["exts"]:
                continue
            for match in islice(rule["regex"].finditer(content), MAX_MATCHES_PER_RULE):
                findings.append(_finding(rule["title"], rule["severity"], rule["description"],
                                         f"{rel}:{_line_of(content, match.start())}", match.group(0)[:250],
                                         rule["recommendation"], "heurística local", "baixa a média",
                                         rule_id=rule["id"]))
        findings.extend(_scan_secrets(content, rel))
        # .env tracked is a warning, not proof of secret exposure.
        if _is_env_file(path.name):
            findings.append(_finding("Arquivo .env presente no escopo", "Medium",
                "Arquivo de ambiente pode conter credenciais. A presença isolada não prova exposição pública.",
                rel, f"Nome do arquivo: {path.name}", "Não versione .env; use .gitignore e secret scanning do provedor.",
                "heurística local", "média", rule_id="vulnagent.env-file"))
    return findings


def _relative(path_text: str, root: Path) -> str:
    if not path_text:
        return ""
    try:
        return Path(path_text).resolve().relative_to(root).as_posix()
    except (ValueError, OSError):
        return path_text


def _run_semgrep(root: Path, meta: dict) -> list[dict]:
    if not shutil.which("semgrep"):
        meta["scanner_status"]["semgrep"] = "não instalado"
        return []
    config = os.getenv("VULNAGENT_SEMGREP_CONFIG", "p/default").strip() or "p/default"
    findings = []
    try:
        # Only local read/analysis, no code execution. Metrics off: nothing about the code leaves the machine
        # besides fetching the rule pack (use a local rules file in VULNAGENT_SEMGREP_CONFIG to work offline).
        proc = subprocess.run(["semgrep", "scan", f"--config={config}", "--json", "--quiet", "--metrics=off",
                               "--disable-version-check", str(root)],
                              capture_output=True, text=True, timeout=300, shell=False)
        data = json.loads(proc.stdout or "{}")
        for r in data.get("results", []):
            extra = r.get("extra", {})
            sev_raw = str(extra.get("severity", "WARNING")).upper()
            severity = "High" if sev_raw in ("ERROR", "CRITICAL", "HIGH") else "Medium" if sev_raw in ("WARNING", "MEDIUM") else "Low"
            findings.append(_finding(
                extra.get("message", "Achado Semgrep"), severity,
                extra.get("metadata", {}).get("description", "Regra Semgrep sinalizou um padrão."),
                f"{_relative(r.get('path', ''), root)}:{r.get('start', {}).get('line', '?')}",
                extra.get("lines", ""), "Revise a regra e corrija conforme o contexto.",
                "Semgrep", "scanner", rule_id=r.get("check_id", "")))
        meta["scanner_status"]["semgrep"] = "concluído" if proc.returncode in (0, 1) else f"erro (código {proc.returncode})"
        if data.get("errors"):
            meta["notes"].append(f"Semgrep reportou {len(data['errors'])} erro(s) de análise.")
        if proc.returncode not in (0, 1) and proc.stderr:
            meta["notes"].append("Semgrep: " + proc.stderr[-1000:])
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as e:
        meta["scanner_status"]["semgrep"] = f"erro: {e}"
    return findings


def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "Medium"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _to_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_osv_results(data: dict, root: Path) -> list[dict]:
    """Turn OSV-Scanner JSON into one finding per vulnerable package."""
    findings = []
    for result in (data.get("results") or [])[:OSV_SOURCE_LIMIT]:
        source_path = _relative((result.get("source") or {}).get("path", ""), root)
        for pkg in result.get("packages") or []:
            vulns = pkg.get("vulnerabilities") or []
            if not vulns:
                continue
            info = pkg.get("package") or {}
            name, version, ecosystem = info.get("name", "?"), info.get("version", "?"), info.get("ecosystem", "")
            scores = [s for s in (_to_float(g.get("max_severity")) for g in pkg.get("groups") or []) if s is not None]
            ids = sorted({v["id"] for v in vulns if v.get("id")})
            cves = sorted({a for v in vulns for a in v.get("aliases") or [] if str(a).startswith("CVE-")})
            fixed = sorted({
                event["fixed"]
                for v in vulns for affected in v.get("affected") or []
                if str((affected.get("package") or {}).get("name", "")).lower() == str(name).lower()
                for rng in affected.get("ranges") or [] for event in rng.get("events") or [] if event.get("fixed")
            })
            evidence = [f"{v.get('id', '?')}: {v.get('summary') or 'sem resumo'}" for v in vulns[:10]]
            if cves:
                evidence.append("CVEs: " + ", ".join(cves[:20]))
            recommendation = (f"Atualize {name} para uma versão corrigida ({', '.join(fixed[:5])})." if fixed else
                              f"Consulte {', '.join(ids[:5])} e atualize {name} para uma versão sem vulnerabilidades conhecidas.")
            findings.append(_finding(
                f"Dependência vulnerável: {name}@{version}", _cvss_to_severity(max(scores) if scores else None),
                f"OSV-Scanner encontrou {len(vulns)} vulnerabilidade(s) conhecida(s) em {name} {version} ({ecosystem}).",
                source_path or "(dependências)", "\n".join(evidence), recommendation,
                "OSV-Scanner", "scanner", rule_id="osv.vulnerable-dependency"))
    return findings


def _run_osv(root: Path, meta: dict) -> list[dict]:
    if not shutil.which("osv-scanner"):
        meta["scanner_status"]["osv-scanner"] = "não instalado"
        return []
    try:
        proc = subprocess.run(["osv-scanner", "scan", "source", "-r", str(root), "--format", "json"],
                              capture_output=True, text=True, timeout=300, shell=False)
    except (OSError, subprocess.SubprocessError) as e:
        meta["scanner_status"]["osv-scanner"] = f"erro: {e}"
        return []
    if proc.returncode == 128:
        meta["scanner_status"]["osv-scanner"] = "concluído (nenhum manifesto de dependências encontrado)"
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        meta["scanner_status"]["osv-scanner"] = "saída não reconhecida; consulte logs"
        meta["notes"].append(proc.stderr[-1000:])
        return []
    meta["scanner_status"]["osv-scanner"] = "concluído" if proc.returncode in (0, 1) else f"código {proc.returncode}"
    return parse_osv_results(data, root)


def scan_code(root: Path):
    root = root.resolve()
    findings, meta = [], {"scanner_status": {}, "files_examined": 0, "notes": []}
    if not root.is_dir():
        raise ValueError("A origem do código não é uma pasta.")
    files = list(_walk_files(root))
    meta["files_examined"] = len(files)
    if len(files) >= MAX_FILES:
        meta["notes"].append(f"Limite de {MAX_FILES} arquivos atingido; parte do código não foi examinada.")
    findings.extend(_scan_with_rules(files, root))
    findings.extend(_run_semgrep(root, meta))
    findings.extend(_run_osv(root, meta))

    # De-duplicate identical scanner findings while retaining distinct locations.
    seen, unique = set(), []
    for f in findings:
        key = (f["title"], f["location"], f["evidence"])
        if key not in seen:
            seen.add(key); unique.append(f)
    return unique, meta
