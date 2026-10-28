from __future__ import annotations
import json, os, re, shutil, subprocess, time
from pathlib import Path
from urllib.parse import urlparse, urljoin
import requests

MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".next"}
TEXT_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".rb", ".go", ".cs", ".html", ".sql", ".yaml", ".yml", ".json", ".env", ".config", ".xml", ".sh"}

def _finding(title, severity, description, location="", evidence="", recommendation="", source="heurística", confidence="média"):
    return {"title": title, "severity": severity, "description": description, "location": location,
            "evidence": evidence, "recommendation": recommendation, "source": source, "confidence": confidence}

def _walk_files(root: Path):
    count = 0
    for path in root.rglob("*"):
        if count >= MAX_FILES:
            break
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_EXTS and path.name not in {".env", "Dockerfile", "requirements.txt", "Pipfile", "package-lock.json", "yarn.lock", "pom.xml", "Gemfile.lock", "go.sum"}:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        count += 1
        yield path

def scan_code(root: Path):
    root = root.resolve()
    findings, meta = [], {"scanner_status": {}, "files_examined": 0, "notes": []}
    if not root.is_dir():
        raise ValueError("A origem do código não é uma pasta.")
    files = list(_walk_files(root))
    meta["files_examined"] = len(files)

    patterns = [
        (re.compile(r'(?i)\beval\s*\('), "Uso de eval()", "High",
         "eval pode executar conteúdo controlado por entrada externa.", "Evite eval; use parsing seguro ou uma lista explícita de operações."),
        (re.compile(r'(?i)(password|passwd|api[_-]?key|secret|token)\s*[:=]\s*["\'][^"\']{8,}["\']'),
         "Possível segredo hardcoded", "High", "Foi encontrado um valor literal associado a credenciais/segredos.",
         "Remova o segredo do código, revogue-o se for real e use um gerenciador de segredos/variáveis de ambiente."),
        (re.compile(r'(?i)execute\s*\(\s*["\'][^"\']*(%s|\+\s*request\.|\.format\s*\()'),
         "Possível SQL Injection", "High", "A consulta SQL pode estar sendo construída por concatenação/formatação.",
         "Use consultas parametrizadas e evite concatenar entrada não confiável."),
        (re.compile(r'(?i)innerHTML\s*='), "Atribuição a innerHTML", "Medium",
         "Atribuir HTML não confiável a innerHTML pode permitir XSS.", "Prefira textContent ou sanitização robusta com biblioteca reconhecida."),
        (re.compile(r'(?i)verify\s*=\s*False'), "Validação TLS desativada", "Medium",
         "A validação do certificado TLS parece desativada.", "Mantenha a validação TLS habilitada e corrija a cadeia de certificados."),
        (re.compile(r'(?i)debug\s*=\s*True'), "Modo debug habilitado", "Medium",
         "Modo de depuração pode expor detalhes internos se habilitado em produção.", "Desabilite debug em produção e configure logs sem dados sensíveis."),
        (re.compile(r'(?i)Access-Control-Allow-Origin["\']?\s*[:,=]\s*["\']\*'), "CORS permissivo", "Low",
         "Foi encontrado um padrão que pode permitir origem ampla.", "Restrinja CORS às origens necessárias; avalie separadamente credenciais e métodos.")
    ]
    for path in files:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for regex, title, severity, desc, fix in patterns:
            for match in list(regex.finditer(content))[:5]:
                line = content.count("\n", 0, match.start()) + 1
                findings.append(_finding(title, severity, desc, f"{rel}:{line}", match.group(0)[:250], fix,
                                         "heurística local", "baixa a média"))
        # .env tracked is a warning, not proof of secret exposure.
        if path.name == ".env":
            findings.append(_finding("Arquivo .env presente no escopo", "Medium",
                "Arquivo de ambiente pode conter credenciais. A presença isolada não prova exposição pública.",
                rel, "Nome do arquivo: .env", "Não versione .env; use .gitignore e secret scanning do provedor.",
                "heurística local", "média"))

    # Semgrep JSON; only local read/analysis, no code execution.
    if shutil.which("semgrep"):
        try:
            proc = subprocess.run(["semgrep", "scan", "--config", "p/default", "--json", "--quiet", str(root)],
                                  capture_output=True, text=True, timeout=180, shell=False)
            data = json.loads(proc.stdout or "{}")
            for r in data.get("results", []):
                extra = r.get("extra", {})
                sev_raw = str(extra.get("severity", "WARNING")).upper()
                severity = "High" if sev_raw == "ERROR" else "Medium" if sev_raw == "WARNING" else "Low"
                findings.append(_finding(
                    extra.get("message", "Achado Semgrep"), severity,
                    extra.get("metadata", {}).get("description", "Regra Semgrep sinalizou um padrão."),
                    f"{r.get('path','')}:{r.get('start',{}).get('line','?')}",
                    extra.get("lines", ""), "Revise a regra e corrija conforme o contexto.",
                    "Semgrep", "scanner"))
            meta["scanner_status"]["semgrep"] = "concluído" if proc.returncode in (0, 1) else f"código {proc.returncode}"
            if proc.stderr:
                meta["notes"].append("Semgrep: " + proc.stderr[-1000:])
        except Exception as e:
            meta["scanner_status"]["semgrep"] = f"erro: {e}"
    else:
        meta["scanner_status"]["semgrep"] = "não instalado"

    if shutil.which("osv-scanner"):
        try:
            proc = subprocess.run(["osv-scanner", "scan", "source", "-r", str(root), "--format", "json"],
                                  capture_output=True, text=True, timeout=180, shell=False)
            # Different OSV-Scanner versions may differ in JSON schema; preserve parseable output summary.
            try:
                data = json.loads(proc.stdout or "{}")
                packages = data.get("results", [])
                count = sum(len(x.get("packages", [])) for x in packages)
                if count:
                    findings.append(_finding("Dependências sinalizadas pelo OSV-Scanner", "Medium",
                        f"O scanner retornou dados de dependências para revisão. Grupos de resultados: {len(packages)}; pacotes listados: {count}.",
                        str(root), json.dumps(data, ensure_ascii=False)[:5000],
                        "Atualize para versões corrigidas indicadas no relatório detalhado do OSV-Scanner.",
                        "OSV-Scanner", "scanner"))
                meta["scanner_status"]["osv-scanner"] = "concluído" if proc.returncode in (0, 1) else f"código {proc.returncode}"
            except json.JSONDecodeError:
                meta["scanner_status"]["osv-scanner"] = "saída não reconhecida; consulte logs"
                meta["notes"].append(proc.stderr[-1000:])
        except Exception as e:
            meta["scanner_status"]["osv-scanner"] = f"erro: {e}"
    else:
        meta["scanner_status"]["osv-scanner"] = "não instalado"

    # De-duplicate identical scanner findings while retaining distinct locations.
    seen, unique = set(), []
    for f in findings:
        key = (f["title"], f["location"], f["evidence"])
        if key not in seen:
            seen.add(key); unique.append(f)
    return unique, meta

def validate_site_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Informe uma URL completa começando por http:// ou https://.")
    if parsed.username or parsed.password:
        raise ValueError("Não inclua credenciais na URL.")
    if parsed.port and not (1 <= parsed.port <= 65535):
        raise ValueError("Porta inválida.")
    # MVP blocks localhost and literal private/reserved IPs to reduce accidental local scanning.
    import ipaddress, socket
    host = parsed.hostname.lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        raise ValueError("O MVP não permite localhost na análise web.")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Endereços IP privados, locais ou reservados não são permitidos.")
    except ValueError as e:
        if "não são permitidos" in str(e):
            raise
        # hostname: resolve and reject if any resolved address is non-global
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            for info in infos:
                if not ipaddress.ip_address(info[4][0]).is_global:
                    raise ValueError("O domínio resolve para endereço privado/local; análise bloqueada.")
        except socket.gaierror:
            raise ValueError("Não foi possível resolver o domínio.")
    return url

def scan_site(url: str):
    findings = []
    meta = {"scanner_status": {"web": "concluído"}, "notes": [
        "Verificação passiva de página inicial; não é um teste de penetração.",
        "Redirecionamentos são desativados para evitar sair do host fornecido."
    ]}
    timeout = float(os.getenv("HTTP_TIMEOUT", "8"))
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False,
                            headers={"User-Agent": "VulnAgent-DefensiveScanner/0.1"},
                            stream=True)
        status = resp.status_code
        headers = resp.headers
        meta["http_status"] = status
        meta["final_url"] = resp.url
        if 300 <= status < 400:
            findings.append(_finding("Redirecionamento detectado", "Info",
                "A página inicial respondeu com redirecionamento; o scanner não o seguiu.",
                url, f"HTTP {status}; Location={headers.get('Location','(ausente)')}",
                "Confirme se o destino é esperado e se não há redirecionamento aberto.",
                "verificação HTTP", "alta"))
        if urlparse(url).scheme == "http":
            findings.append(_finding("Site acessado por HTTP", "Medium",
                "A URL fornecida usa HTTP sem criptografia de transporte.",
                url, "Esquema observado: http", "Use HTTPS e redirecione HTTP para HTTPS.",
                "verificação HTTP", "alta"))
        checks = [
            ("Strict-Transport-Security", "Cabeçalho HSTS ausente", "Medium",
             "Em HTTPS, HSTS instrui navegadores a preferir conexões seguras.",
             "Configure Strict-Transport-Security após confirmar HTTPS em todos os subdomínios aplicáveis."),
            ("Content-Security-Policy", "Content Security Policy ausente", "Medium",
             "CSP pode reduzir o impacto de algumas classes de XSS e injeção de conteúdo.",
             "Defina uma CSP adequada à aplicação e teste-a em modo Report-Only antes de impor."),
            ("X-Content-Type-Options", "X-Content-Type-Options ausente", "Low",
             "A ausência de nosniff pode permitir interpretações MIME indesejadas em certos contextos.",
             "Configure X-Content-Type-Options: nosniff."),
            ("Referrer-Policy", "Referrer-Policy ausente", "Low",
             "A política de referrer controla quanto da URL de origem é enviada a outros sites.",
             "Defina uma política como strict-origin-when-cross-origin conforme a necessidade."),
            ("Permissions-Policy", "Permissions-Policy ausente", "Info",
             "Uma Permissions-Policy pode restringir recursos do navegador que a aplicação não utiliza.",
             "Defina uma política mínima conforme os recursos necessários.")
        ]
        is_https = urlparse(url).scheme == "https"
        for header, title, sev, desc, fix in checks:
            if header.lower() not in {h.lower() for h in headers.keys()} and (header != "Strict-Transport-Security" or is_https):
                findings.append(_finding(title, sev, desc, url, f"Cabeçalho ausente: {header}", fix, "verificação HTTP", "alta"))
        if "Server" in headers:
            findings.append(_finding("Cabeçalho Server divulgado", "Info",
                "O servidor informa tecnologia/identificação no cabeçalho HTTP; isso não é vulnerabilidade por si só.",
                url, "Server: " + headers.get("Server", "")[:200],
                "Considere reduzir informações de versão se a configuração permitir.",
                "verificação HTTP", "alta"))
        # Cookies may not appear if the page doesn't set any.
        cookie_headers = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
        for cookie in cookie_headers[:20]:
            low = cookie.lower()
            name = cookie.split("=",1)[0]
            missing = []
            if is_https and "secure" not in low: missing.append("Secure")
            if "httponly" not in low: missing.append("HttpOnly")
            if "samesite" not in low: missing.append("SameSite")
            if missing:
                findings.append(_finding("Atributos de cookie ausentes", "Low",
                    f"O cookie {name!r} parece não conter todos os atributos recomendados.",
                    url, f"{name}; atributos ausentes: {', '.join(missing)}",
                    "Avalie Secure, HttpOnly e SameSite conforme a finalidade do cookie.",
                    "verificação HTTP", "média"))
        resp.close()
    except requests.RequestException as e:
        raise RuntimeError(f"Falha na requisição HTTP: {e}") from e
    return findings, meta
