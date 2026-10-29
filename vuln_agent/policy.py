"""Policy-aware, evidence-first triage for automated findings."""
from urllib.parse import urlparse

BCNY_HOSTS = {"bcny.com", "thebrowser.company", "diabrowser.com"}
ONEWIN_HOSTS = {"1win.com"}
HEADER_TITLES = {
    "content security policy ausente",
    "x-content-type-options ausente",
    "referrer-policy ausente",
    "permissions-policy ausente",
    "cabeçalho hsts ausente",
}
WEAK_HEADER_TITLES = {"content security policy permissiva", "hsts com configuração fraca"}
SERVER_TITLES = {
    "cabeçalho server divulgado",
    "cabeçalho x-powered-by divulgado",
    "cabeçalho x-aspnet-version divulgado",
    "cabeçalho x-aspnetmvc-version divulgado",
}
FRAME_TITLES = {"proteção contra enquadramento não identificada"}
CORS_TITLES = {
    "cors permite qualquer origem nesta resposta",
    "cors permissivo",
    "cors reflete origem arbitrária",
    "cors confia na origem null com credenciais",
}
COOKIE_TITLES = {"atributos de cookie ausentes"}
# Notices about the quality of the scan itself, never vulnerabilities.
NOTICE_TITLES = {"resposta de bloqueio ou erro: cabeçalhos podem não representar o site"}
# Evidence from these sources is source code, never an HTTP header line.
CODE_SOURCES = {"semgrep", "osv-scanner", "heurística local", "heurística javascript/typescript"}


def _host_matches(host: str, domains: set[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def detect_policy_profile(target: str) -> str:
    """Choose a profile only for exact program domains and their subdomains."""
    host = (urlparse(target).hostname or "").lower().rstrip(".")
    if _host_matches(host, BCNY_HOSTS):
        return "hackerone-bcny"
    if _host_matches(host, ONEWIN_HOSTS):
        return "hackerone-1win"
    return "generic"


def triage_finding(finding: dict, profile: str = "generic") -> dict:
    """Return a copy annotated with triage; never claims exploitability."""
    result = dict(finding)
    preset_status = finding.get("triage_status")
    preset_reason = finding.get("triage_reason")
    title = str(result.get("title", "")).strip().casefold()
    # Evidence markers only count for non-code sources and at the start of the evidence (the
    # format the web scanner emits); otherwise a code snippet containing e.g. "server:" would
    # hide a real Semgrep finding as "not reportable".
    source = str(result.get("source", "")).strip().casefold()
    evidence = "" if source in CODE_SOURCES else str(result.get("evidence", "")).casefold().lstrip()
    is_header = title in HEADER_TITLES or evidence.startswith("cabeçalho ausente:")
    is_weak_header = title in WEAK_HEADER_TITLES
    is_server = title in SERVER_TITLES or evidence.startswith("server:")
    is_cors = title in CORS_TITLES or evidence.startswith("access-control-allow-origin: *")
    is_frame = title in FRAME_TITLES or evidence.startswith("x-frame-options ausente")
    is_cookie = title in COOKIE_TITLES
    status = "needs_manual_review"
    reason = "Indicador automatizado; valide o contexto e o impacto antes de reportar."

    if is_header:
        # Missing defensive headers are observations, not proof of exploitability.
        if title == "content security policy ausente" and result.get("severity") == "Medium":
            result["severity"] = "Low"
            result["severity_note"] = "Severidade reduzida: CSP ausente, isoladamente, não demonstra XSS ou impacto explorável."
        status = "needs_manual_review"
        reason = "Cabeçalho ausente é uma observação de hardening, não prova isolada de vulnerabilidade."
    if is_weak_header:
        status = "needs_manual_review"
        reason = "Configuração fraca de cabeçalho é uma observação de hardening; demonstre um vetor concreto antes de reportar."
    if is_server:
        status = "not_reportable_as_is"
        reason = "Divulgação do cabeçalho Server, isoladamente, não demonstra impacto de segurança."
    elif is_cors:
        status = "needs_impact_validation"
        reason = "CORS amplo pode ser intencional para conteúdo público; verifique dados sensíveis e comportamento com credenciais."
    elif is_frame:
        status = "needs_impact_validation"
        reason = "A ausência de proteção contra enquadramento não prova clickjacking; confirme ações sensíveis e impacto."
    elif is_cookie:
        status = "needs_manual_review"
        reason = "Atributos de cookie dependem da finalidade do cookie; a ausência isolada não demonstra comprometimento de sessão."

    if profile == "hackerone-bcny":
        if is_header or is_weak_header:
            status = "not_reportable_as_is"
            reason = "A triagem BCNY trata cabeçalhos ausentes sem impacto direto demonstrado como não reportáveis isoladamente."
        elif is_server:
            status = "not_reportable_as_is"
            reason = "A triagem BCNY trata divulgação de banner/versão isolada como não reportável."
        elif is_frame:
            status = "needs_impact_validation"
            reason = "Clickjacking exige validação de ação sensível e impacto; o cabeçalho ausente isolado é insuficiente."
        elif is_cors:
            status = "needs_impact_validation"
            reason = "É necessário demonstrar exposição de dados ou outro impacto; o cabeçalho isolado é insuficiente."

    if profile == "hackerone-1win":
        if is_header or is_weak_header:
            status = "not_reportable_as_is"
            reason = "A triagem 1win classifica ausência isolada de cabeçalhos de hardening como não reportável sem impacto demonstrado."
        elif is_server:
            status = "not_reportable_as_is"
            reason = "Identificação genérica do servidor, sem impacto demonstrado, não constitui vulnerabilidade reportável por si só."
        elif is_cookie:
            status = "not_reportable_as_is"
            reason = "A ausência isolada de flags de cookie é hardening; só reavalie se houver impacto concreto demonstrado."
        elif is_cors:
            status = "needs_impact_validation"
            reason = "CORS permissivo sem impacto demonstrado não basta; valide passivamente o contexto do recurso e não acesse dados de terceiros."
        elif is_frame:
            status = "needs_impact_validation"
            reason = "A ausência de proteção contra enquadramento não comprova clickjacking; seria necessário demonstrar impacto em ação sensível."

    if title in NOTICE_TITLES:
        status = "not_reportable_as_is"
        reason = "Aviso sobre a qualidade da análise, não uma vulnerabilidade: os cabeçalhos observados podem não ser os do site."

    # Findings from non-web scanners (code, feed) may ship their own triage; the web-header
    # rules above do not apply to them, so keep the status the scanner assigned.
    web_related = is_header or is_weak_header or is_server or is_cors or is_frame or is_cookie or title in NOTICE_TITLES
    if not web_related and preset_status:
        status = preset_status
        reason = preset_reason or reason

    result["triage_status"] = status
    result["triage_reason"] = reason
    result["policy_profile"] = profile
    return result


def triage_findings(findings: list, profile: str = "generic") -> list:
    """Annotate findings and merge identical observations while retaining locations."""
    output = []
    indexes = {}
    for original in findings:
        finding = triage_finding(original, profile)
        key = (
            str(finding.get("title", "")).casefold(),
            str(finding.get("source", "")).casefold(),
            str(finding.get("evidence", "")).casefold(),
        )
        if key in indexes:
            existing = output[indexes[key]]
            locations = existing.setdefault("locations", [existing.get("location", "")])
            location = finding.get("location", "")
            if location and location not in locations:
                locations.append(location)
            continue
        indexes[key] = len(output)
        output.append(finding)
    return output
