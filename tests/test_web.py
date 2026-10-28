import http.server
import ipaddress
import socket
import threading

import pytest
import requests

from vuln_agent import web
from vuln_agent.web import UnsafeTargetError, is_public_ip, scan_site, validate_site_url


class _Handler(http.server.BaseHTTPRequestHandler):
    status = 200
    headers_to_send: list = []
    hits: list = []

    def do_GET(self):
        type(self).hits.append(dict(self.headers))
        self.send_response(self.status)
        for name, value in self.headers_to_send:
            self.send_header(name, value.replace("{origin}", self.headers.get("Origin", "")))
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def local_site(monkeypatch):
    """A real HTTP server on 127.0.0.1; loopback is allowed only for these tests."""
    handler = type("Handler", (_Handler,), {"hits": [], "headers_to_send": [], "status": 200})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(web, "is_public_ip", lambda ip: True)
    yield handler, f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize("url", [
    "http://10.0.0.5/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/",
    "http://[::ffff:127.0.0.1]/", "http://[64:ff9b::a9fe:a9fe]/", "http://localhost:8080/",
    "http://app.localhost/",
])
def test_internal_targets_are_rejected(url):
    with pytest.raises(ValueError):
        validate_site_url(url)


@pytest.mark.parametrize("url", ["ftp://example.com", "https://user:pass@example.com/", "https://example.com:99999/", ""])
def test_malformed_urls_are_rejected(url):
    with pytest.raises(ValueError):
        validate_site_url(url)


def test_public_ip_classification():
    assert is_public_ip(ipaddress.ip_address("93.184.216.34"))
    for ip in ("127.0.0.1", "10.1.2.3", "100.64.0.1", "224.0.0.1", "::ffff:10.0.0.1", "64:ff9b::7f00:1", "fe80::1"):
        assert not is_public_ip(ipaddress.ip_address(ip)), ip


def test_dns_rebinding_is_blocked_at_connect_time(monkeypatch, local_site):
    handler, url = local_site
    port = int(url.rsplit(":", 1)[1].strip("/"))
    monkeypatch.undo()  # restore the real is_public_ip: only the resolver is faked here
    real_getaddrinfo = socket.getaddrinfo
    answers = iter(["93.184.216.34", "127.0.0.1", "127.0.0.1"])

    def rebinding_dns(host, *args, **kwargs):
        if host == "rebind.attacker.test":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(answers), port))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", rebinding_dns)
    target = validate_site_url(f"http://rebind.attacker.test:{port}/")  # first answer: public
    with pytest.raises(UnsafeTargetError):
        scan_site(target)  # second answer: 127.0.0.1 -> refused before connecting
    assert handler.hits == []


def test_passive_checks_against_a_real_server(local_site):
    handler, url = local_site
    handler.headers_to_send = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'"),
        ("Access-Control-Allow-Origin", "{origin}"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Server", "nginx/1.18.0"),
        ("X-Powered-By", "PHP/7.4.3"),
        ("Set-Cookie", "session=abc; Path=/; HttpOnly"),
        ("Set-Cookie", "__Secure-pref=1; SameSite=None"),
        ("Set-Cookie", "secure_httponly_samesite=1; Path=/"),
    ]
    findings, meta = scan_site(url)
    by_title = {f["title"]: f for f in findings}
    assert meta["http_status"] == 200
    assert handler.hits[0]["Origin"] == web.ORIGIN_PROBE
    assert by_title["CORS reflete origem arbitrária"]["severity"] == "Medium"
    assert "'unsafe-inline'" in by_title["Content Security Policy permissiva"]["description"]
    assert "Proteção contra enquadramento não identificada" in by_title
    assert "Site acessado por HTTP" in by_title
    assert "Cabeçalho X-Powered-By divulgado" in by_title
    assert "Content Security Policy ausente" not in by_title
    cookies = [f["evidence"] for f in findings if f["title"] == "Atributos de cookie ausentes"]
    assert "session; atributos ausentes: SameSite" in cookies
    assert any(c.startswith("__Secure-pref; atributos ausentes: Secure") for c in cookies)
    # A cookie *name* containing "secure"/"httponly" must not count as those attributes.
    assert "secure_httponly_samesite; atributos ausentes: HttpOnly, SameSite" in cookies


def test_redirect_responses_skip_content_header_checks(local_site):
    handler, url = local_site
    handler.status = 301
    handler.headers_to_send = [("Location", "https://example.com/home")]
    findings, meta = scan_site(url)
    titles = {f["title"] for f in findings}
    assert "Redirecionamento detectado" in titles
    assert "Content Security Policy ausente" not in titles
    assert meta["redirect_location"] == "https://example.com/home"


def test_environment_proxies_are_not_used(local_site, monkeypatch):
    handler, url = local_site
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    scan_site(url)
    assert len(handler.hits) == 1


def test_invalid_certificate_becomes_a_finding(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.exceptions.SSLError("certificate verify failed: self-signed certificate")

    monkeypatch.setattr(requests.Session, "get", fail)
    findings, meta = scan_site("https://self-signed.test/")
    assert findings[0]["title"] == "Certificado TLS inválido ou não confiável"
    assert findings[0]["severity"] == "High"
    assert "TLS" in meta["scanner_status"]["web"]


def test_weak_hsts_and_csp_parsing_helpers():
    assert web._hsts_max_age("max-age=300; includeSubDomains") == 300
    assert web._hsts_max_age("includeSubDomains") is None
    csp = web._parse_csp("script-src 'self' 'nonce-abc' 'unsafe-inline'; object-src 'none'")
    assert web._csp_weaknesses(csp) == []  # nonces make browsers ignore 'unsafe-inline'
    assert web._csp_weaknesses(web._parse_csp("img-src *")) == ["sem script-src/default-src: scripts não são restringidos"]
