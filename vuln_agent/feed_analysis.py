"""Passive analysis of a sportsbook odds-feed JSON (read-only).

Takes a feed payload you already captured from your own authorised session and extracts, without
any network call:
- every external host the feed references (the supply-chain surface);
- URLs hidden behind base64 (``broadcastUrl`` ``ref=``) and URL-in-path proxies (``…/p/https://…``);
- the bookmaker margin (overround) of each 1X2 market.

IMPORTANT: a public odds feed is meant to be public. Everything here is a REVIEW INDICATOR, never
a confirmed vulnerability. Most items are informational; see the report guidance before escalating
anything to a program, and confirm host ownership/scope first.
"""
from __future__ import annotations

import base64
import binascii
import json
from collections import defaultdict
from urllib.parse import parse_qs, urlparse

from vuln_agent.findings import make_finding

MAX_STRINGS = 200_000
MANUAL = {"triage_status": "needs_manual_review",
          "triage_reason": "Indicador de feed; confirme escopo, propriedade do domínio e impacto antes de reportar."}
INFO_ONLY = {"triage_status": "not_reportable_as_is",
             "triage_reason": "Observação informativa sobre a arquitetura do feed, não uma vulnerabilidade por si só."}
NEEDS_IMPACT = {"triage_status": "needs_impact_validation",
                "triage_reason": "Padrão potencialmente abusável; valide propriedade do domínio, allowlist e impacto (SSRF/redirect) antes de reportar."}

# Hosts that are plain asset CDNs: noise, not a meaningful supply-chain surface for active content.
_ASSET_HOST_HINTS = ("static", "cdn", "img", "icons", "assets")


def _walk_strings(obj, path=""):
    stack = [(path, obj)]
    seen = 0
    while stack and seen < MAX_STRINGS:
        node_path, node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                stack.append((f"{node_path}.{key}" if node_path else str(key), value))
        elif isinstance(node, list):
            for i, value in enumerate(node):
                stack.append((f"{node_path}[{i}]", value))
        elif isinstance(node, str):
            seen += 1
            yield node_path, node


def _is_url(text: str) -> bool:
    return text.startswith(("http://", "https://"))


def decode_base64_url(value: str) -> str | None:
    """If ``value`` is base64 (url-safe or standard) of an http(s) URL, return that URL."""
    candidate = value.strip()
    if not candidate or len(candidate) > 8000 or len(candidate) < 16:
        return None
    candidate += "=" * (-len(candidate) % 4)  # tolerate missing padding
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decoder(candidate)
        except (binascii.Error, ValueError):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _is_url(text):
            return text
    return None


def _hidden_urls(url: str) -> list[tuple[str, str]]:
    """Return (kind, revealed_url) pairs hidden inside ``url``: base64 query refs or URL-in-path."""
    hidden = []
    parsed = urlparse(url)
    for values in parse_qs(parsed.query).values():
        for value in values:
            if _is_url(value):
                hidden.append(("query-url", value))
            else:
                decoded = decode_base64_url(value)
                if decoded:
                    hidden.append(("base64", decoded))
    # URL-in-path proxy, e.g. https://proxy/p/https://target/...
    marker = parsed.path.find("/http")
    if marker != -1:
        tail = parsed.path[marker + 1:]
        if _is_url(tail):
            hidden.append(("path-url", tail))
    return hidden


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _is_asset_host(host: str) -> bool:
    return any(hint in host for hint in _ASSET_HOST_HINTS)


def _overround(odds: list[dict]) -> float | None:
    inverse = 0.0
    for odd in odds:
        try:
            coef = float(odd.get("coefficient"))
        except (TypeError, ValueError):
            return None
        if coef <= 1.0:
            return None
        inverse += 1.0 / coef
    return inverse - 1.0 if odds else None


def analyze_feed(data: dict):
    """Return (findings, meta) for a parsed feed payload. No network, no execution."""
    findings: list[dict] = []
    if not isinstance(data, dict):
        raise ValueError("O feed deve ser um objeto JSON.")

    urls = [(path, value) for path, value in _walk_strings(data) if _is_url(value)]
    hosts: dict[str, str] = {}          # host -> example json path
    revealed: dict[str, dict] = {}       # revealed url -> {kind, via host, source path}
    for path, url in urls:
        host = _host(url)
        if host:
            hosts.setdefault(host, path)
        for kind, hidden in _hidden_urls(url):
            revealed.setdefault(hidden, {"kind": kind, "via": host, "path": path})
            hh = _host(hidden)
            if hh:
                hosts.setdefault(hh, f"{path} ({kind})")

    active_hosts = sorted(h for h in hosts if not _is_asset_host(h))
    asset_hosts = sorted(h for h in hosts if _is_asset_host(h))

    for host in active_hosts:
        findings.append(make_finding(
            f"Domínio de terceiro referenciado pelo feed: {host}", "Info",
            "O feed aponta para este host externo (vídeo, tracker ou API). Conteúdo ativo de terceiros é "
            "superfície de supply chain: se um desses recursos for comprometido ou injetar script/redirect, "
            "afeta todas as sessões que o carregam.",
            hosts[host], host,
            "Confirme se o host é oficial/contratado; revise, na página de jogo, se ele carrega JavaScript, "
            "faz redirect ou recebe dados do usuário. Só então avalie como achado de supply chain.",
            "análise de feed", "baixa; exige revisão manual", rule_id="vulnagent.feed.third-party-host", **MANUAL))

    for hidden, info in sorted(revealed.items()):
        if info["kind"] == "base64":
            findings.append(make_finding(
                "URL ofuscada em base64 no feed (broadcast/tracker)", "Info",
                "Um parâmetro do feed guarda uma URL codificada em base64. Base64 é codificação, não "
                "criptografia: não protege nada e não é falha por si só, mas revela a infraestrutura real "
                f"de destino ({_host(hidden)}).",
                info["path"], hidden,
                "Apenas documente o destino real. Não trate a codificação como proteção nem como vulnerabilidade.",
                "análise de feed", "alta", rule_id="vulnagent.feed.base64-url", **INFO_ONLY))
        else:
            findings.append(make_finding(
                "Proxy com URL embutida na requisição (possível open redirect/SSRF)",
                "Low", "Uma URL de terceiro embute outra URL completa no caminho/parâmetro "
                f"(padrão de proxy aberto: {info['via']} → {_host(hidden)}). Se esse proxy não valida a URL "
                "de destino contra uma allowlist, pode ser abusado para open redirect ou SSRF.",
                info["path"], f"{info['kind']}: {hidden}",
                "Confirme PRIMEIRO de quem é o domínio do proxy (pode estar fora do escopo do programa). Se "
                "for do alvo, teste passivamente se ele aceita destinos arbitrários; só reporte com um PoC de "
                "redirect/SSRF e impacto concreto.",
                "análise de feed", "baixa; exige revisão manual",
                rule_id="vulnagent.feed.url-in-path-proxy", **NEEDS_IMPACT))

    # Shared embed/stream keys repeated across matches are site-wide, not per-user secrets.
    shared_keys = _shared_query_keys(list(revealed) + [u for _p, u in urls])
    for key, value in sorted(shared_keys.items()):
        findings.append(make_finding(
            f"Parâmetro constante em URLs do feed: {key}", "Info",
            f"O parâmetro '{key}' repete o mesmo valor em várias partidas. É uma chave de embed/stream "
            "compartilhada do site, NÃO um token por usuário — portanto não é vazamento de dado pessoal.",
            "feed", f"{key}={value}",
            "Não reporte como exposição de credencial de usuário. Avalie apenas se essa chave dá acesso a "
            "algo sensível e se deveria ser por sessão.",
            "análise de feed", "média", rule_id="vulnagent.feed.shared-key", **INFO_ONLY))

    meta = _summary(data, active_hosts, asset_hosts, revealed)
    return findings, meta


def _shared_query_keys(urls: list[str]) -> dict[str, str]:
    values: defaultdict[str, set] = defaultdict(set)
    for url in urls:
        for key, vals in parse_qs(urlparse(url).query).items():
            if key.lower() in ("t", "lang", "ref"):  # volatile/known params
                continue
            for v in vals:
                values[key].add(v)
    # Keep only constant, non-trivial values (a key-like token), not flags such as s=1/type=s.
    return {key: next(iter(vals)) for key, vals in values.items()
            if len(vals) == 1 and len(next(iter(vals))) >= 6}


def _summary(data, active_hosts, asset_hosts, revealed):
    matches, margins, mismatches = [], [], []
    for sport in data.get("feed", []):
        for match in sport.get("matches", []):
            label = match.get("slug") or match.get("id")
            for group in match.get("oddGroups", []):
                if "resultado do tempo regulamentar" == str(group.get("name", "")).strip().lower():
                    over = _overround(group.get("odds", []))
                    if over is not None:
                        margins.append({"match": label, "overround_pct": round(over * 100, 2)})
            slug = str(match.get("awayTeamSlug", ""))
            name = str(match.get("awayTeamName", ""))
            if slug and name and slug.replace("-", " ").split()[0] not in name.lower() \
                    and name.lower().split()[0] not in slug.replace("-", ""):
                mismatches.append({"id": match.get("id"), "name": name, "slug": slug})
            matches.append(label)
    return {
        "scanner_status": {"feed": "concluído"},
        "feed_summary": {
            "matches": len(matches),
            "active_third_party_hosts": active_hosts,
            "asset_hosts": asset_hosts,
            "revealed_urls": len(revealed),
            "market_margins": margins,
            "team_slug_mismatches": mismatches,
        },
        "notes": [
            "Análise passiva de um feed JSON; nenhuma requisição de rede foi feita.",
            "Um feed público de odds é, por natureza, público: os achados são indicadores, não vulnerabilidades.",
        ],
    }


def analyze_feed_json(text: str):
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON inválido: {exc}") from exc
    return analyze_feed(data)
