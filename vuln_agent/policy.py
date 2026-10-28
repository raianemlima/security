"""Policy-aware, evidence-first triage for automated findings."""
from urllib.parse import urlparse

BCNY_HOSTS = {"bcny.com", "thebrowser.company", "diabrowser.com"}
HEADER_TITLES = {
    "content security policy ausente",
    "x-content-type-options ausente",
    "referrer-policy ausente",
    "permissions-policy ausente",
    "cabeçalho hsts ausente",
}
SERVER_TITLES = {"cabeçalho server divulgado"}
FRAME_TITLES = {"proteção contra enquadramento não identificada"}
CORS_TITLES = {"cors permite qualquer origem nesta resposta", "cors permissivo"}


def detect_policy_profile(target: str) -> str:
    """Use BCNY rules only for exact program domains and their subdomains."""
    host = (urlparse(target).hostname or "").lower().rstrip(".")
    if any(host == domain or host.endswith("." + domain) for domain in BCNY_HOSTS):
        return "hackerone-bcny"
    return "generic"


def triage_finding(finding: dict, profile: str = "generic") -> dict:
    """Return a copy annotated with triage; never claims exploitability."""
    result = dict(finding)
    title = str(result.get("title", "")).strip().casefold()
    evidence = str(result.get("evidence", "")).casefold()
    status = "needs_manual_review"
    reason = "Indicador automatizado; valide o contexto e o impacto antes de reportar."

    if title in SERVER_TITLES or "server:" in evidence:
        status = "not_reportable_as_is"
        reason = "Divulgação do cabeçalho Server, isoladamente, não demonstra impacto de segurança."
    elif title in CORS_TITLES or "access-control-allow-origin: *" in evidence:
        status = "needs_impact_validation"
        reason = "CORS amplo pode ser intencional para conteúdo público; verifique dados sensíveis e comportamento com credenciais."
    elif title in FRAME_TITLES or "x-frame-options ausente" in evidence:
        status = "needs_impact_validation"
        reason = "A ausência de proteção contra enquadramento não prova clickjacking; confirme ações sensíveis e impacto."
    elif title in HEADER_TITLES or "cabeçalho ausente:" in evidence:
        status = "needs_manual_review"
        reason = "Cabeçalho ausente é uma observação de hardening, não prova isolada de vulnerabilidade."

    if profile == "hackerone-bcny":
        if title in HEADER_TITLES or "cabeçalho ausente:" in evidence:
            status = "not_reportable_as_is"
            reason = "A política BCNY exclui cabeçalhos ausentes sem impacto direto demonstrado."
        elif title in SERVER_TITLES or "server:" in evidence:
            status = "not_reportable_as_is"
            reason = "A política BCNY exclui divulgação de banner/versão isolada."
        elif title in FRAME_TITLES or "x-frame-options ausente" in evidence:
            status = "needs_impact_validation"
            reason = "A política BCNY exclui clickjacking sem ação sensível; o relatório ainda não demonstra impacto."
        elif title in CORS_TITLES or "access-control-allow-origin: *" in evidence:
            status = "needs_impact_validation"
            reason = "É necessário demonstrar exposição de dados ou outro impacto; o cabeçalho isolado é insuficiente."

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
