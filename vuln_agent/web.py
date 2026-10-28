"""Passive web checks with SSRF protection.

``validate_site_url`` rejects obviously internal targets up front, but a hostname can
resolve to a public IP during validation and to 127.0.0.1 / 169.254.169.254 a moment
later (DNS rebinding). To close that window, every outgoing connection resolves the
host itself, refuses non-public addresses and connects to the exact IP it validated.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError
from urllib3.util import connection as urllib3_connection

from vuln_agent.findings import make_finding

USER_AGENT = "VulnAgent-DefensiveScanner/0.2 (passive; authorized use only)"
# A non-resolvable origin (RFC 2606 .invalid): it only reveals whether the server reflects it.
ORIGIN_PROBE = "https://vulnagent-origin-check.invalid"
HSTS_MIN_MAX_AGE = 15_552_000  # 180 days
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


class UnsafeTargetError(ValueError):
    """The target resolves to a non-public address."""


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.version == 6:
        embedded = ip.ipv4_mapped or ip.sixtofour
        if embedded is None and ip in _NAT64:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is None and ip.teredo:
            embedded = ip.teredo[1]
        if embedded is not None and not is_public_ip(embedded):
            return False
    return ip.is_global and not ip.is_multicast


def public_addresses(host: str, port: int) -> list[str]:
    """Resolve ``host`` and return its IPs, failing if *any* of them is not public.

    Raises ``socket.gaierror`` when the name does not resolve.
    """
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = []
    for *_ignored, sockaddr in infos:
        ip = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
        if not is_public_ip(ip):
            raise UnsafeTargetError(
                f"O destino resolve para endereço privado/local ({ip}); análise bloqueada.")
        addresses.append(str(ip))
    if not addresses:
        raise UnsafeTargetError("O domínio não resolveu para nenhum endereço utilizável.")
    return addresses


class _PublicOnlyConnectionMixin:
    """Replace urllib3's resolver+connect step with a validated, pinned one."""

    def _new_conn(self):
        try:
            addresses = public_addresses(self._dns_host, self.port)
        except socket.gaierror as exc:
            raise NameResolutionError(self.host, self, exc) from exc
        error = None
        for address in addresses:
            try:
                return urllib3_connection.create_connection(
                    (address, self.port), self.timeout,
                    source_address=self.source_address, socket_options=self.socket_options)
            except TimeoutError as exc:
                error = ConnectTimeoutError(self, f"Conexão com {self.host} expirou ({exc}).")
            except OSError as exc:
                error = NewConnectionError(self, f"Falha ao conectar em {self.host}: {exc}")
        raise error


class _PublicHTTPConnection(_PublicOnlyConnectionMixin, HTTPConnection):
    pass


class _PublicHTTPSConnection(_PublicOnlyConnectionMixin, HTTPSConnection):
    pass


class _PublicHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PublicHTTPConnection


class _PublicHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PublicHTTPSConnection


class PublicOnlyAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _PublicHTTPConnectionPool, "https": _PublicHTTPSConnectionPool}


def public_only_session() -> requests.Session:
    session = requests.Session()
    # Ignore environment proxies (they would resolve the host themselves and bypass the
    # IP check) and ~/.netrc (credentials must never be sent to a scanned site).
    session.trust_env = False
    adapter = PublicOnlyAdapter(max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def validate_site_url(url: str) -> str:
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Informe uma URL completa começando por http:// ou https://.")
    if parsed.username or parsed.password:
        raise ValueError("Não inclua credenciais na URL.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Porta inválida.") from exc
    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        raise ValueError("O MVP não permite localhost na análise web.")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not is_public_ip(literal):
            raise ValueError("Endereços IP privados, locais ou reservados não são permitidos.")
        return url
    try:
        public_addresses(host, port)
    except socket.gaierror as exc:
        raise ValueError("Não foi possível resolver o domínio.") from exc
    return url


def _http_timeout() -> float:
    try:
        value = float(os.getenv("HTTP_TIMEOUT", "8"))
    except ValueError:
        value = 8.0
    return min(max(value, 1.0), 60.0)


def _parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def _csp_weaknesses(directives: dict[str, list[str]]) -> list[str]:
    scripts = directives.get("script-src", directives.get("default-src"))
    if scripts is None:
        return ["sem script-src/default-src: scripts não são restringidos"]
    issues = []
    has_nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in scripts)
    if "'unsafe-inline'" in scripts and not has_nonce_or_hash:
        issues.append("'unsafe-inline' permite scripts inline")
    if "'unsafe-eval'" in scripts:
        issues.append("'unsafe-eval' permite eval()")
    broad = sorted({t for t in scripts if t in ("*", "http:", "https:", "data:")})
    if broad:
        issues.append(f"fontes amplas para scripts ({', '.join(broad)})")
    return issues


def _hsts_max_age(value: str) -> int | None:
    for part in value.split(";"):
        name, _, raw = part.strip().partition("=")
        if name.strip().lower() == "max-age":
            try:
                return int(raw.strip().strip('"'))
            except ValueError:
                return None
    return None


def _cookie_issues(cookie: str, is_https: bool) -> tuple[str, list[str]]:
    parts = [p.strip() for p in cookie.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attributes = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attributes[key.strip().lower()] = value.strip().lower()
    missing = []
    secure_required = name.startswith(("__Secure-", "__Host-")) or attributes.get("samesite") == "none"
    if "secure" not in attributes and (is_https or secure_required):
        missing.append("Secure (obrigatório com SameSite=None)" if attributes.get("samesite") == "none" else "Secure")
    if "httponly" not in attributes:
        missing.append("HttpOnly")
    if "samesite" not in attributes:
        missing.append("SameSite")
    return name, missing


def scan_site(url: str):
    findings = []
    meta = {"scanner_status": {"web": "concluído"}, "notes": [
        "Verificação passiva de página inicial; não é um teste de penetração.",
        "Redirecionamentos são desativados para evitar sair do host fornecido.",
        f"A requisição envia o cabeçalho Origin: {ORIGIN_PROBE} para detectar reflexão de CORS.",
    ]}
    is_https = urlparse(url).scheme == "https"
    session = public_only_session()
    try:
        try:
            resp = session.get(url, timeout=_http_timeout(), allow_redirects=False, stream=True,
                               headers={"User-Agent": USER_AGENT, "Origin": ORIGIN_PROBE})
        except requests.exceptions.SSLError as exc:
            findings.append(make_finding(
                "Certificado TLS inválido ou não confiável", "High",
                "A conexão HTTPS falhou na validação do certificado (expirado, autoassinado, cadeia "
                "incompleta ou nome incorreto). Usuários ficam expostos a interceptação ou a alertas.",
                url, str(exc)[:500],
                "Instale um certificado válido emitido por uma CA confiável, com cadeia completa e o nome correto.",
                "verificação TLS", "alta", rule_id="web.tls-invalid-certificate"))
            meta["scanner_status"]["web"] = "concluído (falha na validação TLS)"
            return findings, meta
        except requests.RequestException as exc:
            raise RuntimeError(f"Falha na requisição HTTP: {exc}") from exc
        with resp:
            findings.extend(_analyse_response(url, resp, is_https, meta))
    finally:
        session.close()
    return findings, meta


def _analyse_response(url, resp, is_https, meta):
    findings = []
    status = resp.status_code
    headers = resp.headers
    meta["http_status"] = status
    meta["final_url"] = resp.url
    is_redirect = 300 <= status < 400

    def add(title, severity, description, evidence, recommendation, rule_id, confidence="alta"):
        findings.append(make_finding(title, severity, description, url, evidence, recommendation,
                                     "verificação HTTP", confidence, rule_id=rule_id))

    if is_redirect:
        location = headers.get("Location", "")
        if location:
            meta["redirect_location"] = urljoin(url, location)
        add("Redirecionamento detectado", "Info",
            "A página inicial respondeu com redirecionamento; o scanner não o seguiu.",
            f"HTTP {status}; Location={location or '(ausente)'}",
            "Confirme se o destino é esperado e se não há redirecionamento aberto. Se o destino estiver "
            "no escopo autorizado, analise-o diretamente.", "web.redirect")
        meta["notes"].append("Cabeçalhos de conteúdo (CSP, X-Frame-Options etc.) não foram avaliados "
                             "porque a resposta é um redirecionamento.")
    if not is_https:
        add("Site acessado por HTTP", "Medium", "A URL fornecida usa HTTP sem criptografia de transporte.",
            "Esquema observado: http", "Use HTTPS e redirecione HTTP para HTTPS.", "web.plain-http")

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
    for header, title, sev, desc, fix in checks:
        if header == "Strict-Transport-Security":
            if not is_https:
                continue
        elif is_redirect:
            continue
        if header not in headers:
            add(title, sev, desc, f"Cabeçalho ausente: {header}", fix, "web.missing-" + header.lower())

    hsts = headers.get("Strict-Transport-Security")
    if is_https and hsts:
        max_age = _hsts_max_age(hsts)
        if max_age is None or max_age < HSTS_MIN_MAX_AGE:
            add("HSTS com configuração fraca", "Info",
                "O max-age do HSTS está ausente ou abaixo de 180 dias, reduzindo a proteção contra downgrade.",
                f"Strict-Transport-Security: {hsts[:200]}",
                "Use max-age de pelo menos 15552000 (idealmente 31536000) e avalie includeSubDomains.",
                "web.weak-hsts")

    csp_value = headers.get("Content-Security-Policy", "")
    directives = _parse_csp(csp_value) if csp_value else {}
    if csp_value and not is_redirect:
        issues = _csp_weaknesses(directives)
        if issues:
            add("Content Security Policy permissiva", "Low",
                "A CSP existe, mas permite construções que reduzem sua proteção contra XSS: " + "; ".join(issues) + ".",
                f"Content-Security-Policy: {csp_value[:400]}",
                "Remova 'unsafe-inline'/'unsafe-eval' usando nonces ou hashes e restrinja as fontes de script.",
                "web.weak-csp")

    content_type = headers.get("Content-Type", "").lower()
    if not is_redirect and "html" in content_type and "X-Frame-Options" not in headers \
            and "frame-ancestors" not in directives:
        add("Proteção contra enquadramento não identificada", "Low",
            "A página HTML não define X-Frame-Options nem CSP frame-ancestors; ela pode ser carregada em iframes de terceiros.",
            "X-Frame-Options ausente; CSP frame-ancestors não identificada",
            "Defina CSP frame-ancestors 'self' (ou X-Frame-Options: DENY/SAMEORIGIN) se a página não deve ser enquadrada.",
            "web.missing-frame-protection")

    acao = headers.get("Access-Control-Allow-Origin", "").strip()
    credentials = headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
    cors_evidence = f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: " \
                    f"{'true' if credentials else '(ausente)'}"
    if acao == "*":
        add("CORS permite qualquer origem nesta resposta", "Info",
            "Qualquer site pode ler esta resposta. É aceitável para conteúdo público; navegadores não enviam credenciais com '*'.",
            "Access-Control-Allow-Origin: *",
            "Confirme que a resposta não contém dados sensíveis ou restrinja às origens necessárias.", "web.cors-wildcard")
    elif acao == ORIGIN_PROBE:
        add("CORS reflete origem arbitrária", "Medium" if credentials else "Low",
            "O servidor devolveu no Access-Control-Allow-Origin a origem fictícia enviada pelo scanner. "
            + ("Com credenciais habilitadas, sites de terceiros podem ler respostas autenticadas."
               if credentials else "Sem credenciais, o impacto depende de a resposta conter dados não públicos."),
            cors_evidence,
            "Valide a origem contra uma allowlist exata; nunca reflita o cabeçalho Origin recebido.",
            "web.cors-origin-reflection")
    elif acao == "null" and credentials:
        add("CORS confia na origem null com credenciais", "Medium",
            "A origem 'null' pode ser obtida por iframes sandbox e documentos locais, permitindo leitura autenticada.",
            cors_evidence, "Não inclua 'null' na allowlist de origens.", "web.cors-null-origin")

    for header in _DISCLOSURE_HEADERS:
        if header in headers:
            add(f"Cabeçalho {header} divulgado", "Info",
                "O servidor informa tecnologia/identificação no cabeçalho HTTP; isso não é vulnerabilidade por si só.",
                f"{header}: {headers.get(header, '')[:200]}",
                "Considere reduzir informações de versão se a configuração permitir.",
                "web.disclosure-" + header.lower())

    # Cookies may not appear if the page doesn't set any.
    cookie_headers = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
    for cookie in cookie_headers[:20]:
        name, missing = _cookie_issues(cookie, is_https)
        if missing:
            add("Atributos de cookie ausentes", "Low",
                f"O cookie {name!r} parece não conter todos os atributos recomendados.",
                f"{name}; atributos ausentes: {', '.join(missing)}",
                "Avalie Secure, HttpOnly e SameSite conforme a finalidade do cookie.",
                "web.cookie-attributes", confidence="média")
    return findings
