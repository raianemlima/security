import json
import re
import unicodedata
from datetime import datetime, timezone

from vuln_agent import __version__
from vuln_agent.policy import detect_policy_profile, triage_findings
from vuln_agent.redaction import redact_text

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")
_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
_SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
# GitHub code scanning buckets: >=9 critical, >=7 high, >=4 medium, >0 low.
_SECURITY_SEVERITY = {"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "3.0", "Info": "0.0"}


def severity_rank(severity) -> int:
    return _SEVERITY_RANK.get(severity, len(SEVERITY_ORDER))


def severity_counts(findings) -> dict:
    counts = {}
    for f in findings:
        sev = f.get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def make_report(target_type, target, findings, meta):
    profile = detect_policy_profile(target) if target_type == "site" else "generic"
    # Redact before triage so deduplication and every export only ever see masked evidence.
    redacted = [dict(f, evidence=redact_text(str(f["evidence"]))) if f.get("evidence") else dict(f)
                for f in findings]
    triaged = triage_findings(redacted, profile)
    triaged.sort(key=lambda f: severity_rank(f.get("severity")))
    triage_counts = {}
    for finding in triaged:
        status = finding.get("triage_status", "needs_manual_review")
        triage_counts[status] = triage_counts.get(status, 0) + 1
    report_meta = dict(meta or {})
    report_meta["policy_triage"] = {
        "profile": profile,
        "counts": triage_counts,
        "note": "Triagem heurística; não confirma explorabilidade nem substitui revisão humana."
    }
    return {
        "schema_version": "1.0",
        "tool": "VulnAgent",
        "tool_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_type": target_type,
        "target": target,
        "policy_profile": profile,
        "authorized_use_notice": "Use somente em alvos próprios ou expressamente autorizados.",
        "metadata": report_meta,
        "findings": triaged
    }


def _fenced(text, lang="text"):
    """Code block whose fence is longer than any backtick run inside, so content cannot escape it."""
    text = str(text)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}{lang}", text, fence]


def _inline_code(text):
    text = str(text).replace("\r", " ").replace("\n", " ")
    if not text:
        return "—"
    ticks = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def _md_text(text):
    """Neutralise link/image/HTML syntax in free text taken from scanners or scanned code."""
    return re.sub(r"([\\\[\]<>`])", r"\\\1", str(text)).replace("\r", " ").replace("\n", " ")


def findings_to_markdown(report):
    lines = [
        "# Relatório VulnAgent", "",
        f"- **Gerado em:** {report.get('generated_at')}",
        f"- **Tipo:** {report.get('target_type')}",
        f"- **Alvo:** {_inline_code(report.get('target'))}",
        f"- **Perfil de triagem:** {report.get('policy_profile', 'generic')}",
        "", "> Os achados são indicadores automatizados. A triagem não confirma explorabilidade; revise as evidências antes de reportar.", "",
        "## Resumo", ""
    ]
    findings = report.get("findings", [])
    lines.append(f"- **Total de achados:** {len(findings)}")
    for sev in SEVERITY_ORDER:
        count = sum(1 for f in findings if f.get("severity") == sev)
        lines.append(f"- **{sev}:** {count}")
    lines += ["", "### Triagem", ""]
    status_labels = {
        "not_reportable_as_is": "Não reportável como está",
        "needs_impact_validation": "Precisa validar impacto",
        "needs_manual_review": "Precisa de revisão manual",
    }
    for status in ("not_reportable_as_is", "needs_impact_validation", "needs_manual_review"):
        count = sum(1 for f in findings if f.get("triage_status") == status)
        lines.append(f"- **{status_labels[status]}:** {count}")
    lines += ["", "## Achados", ""]
    if not findings:
        lines.append("Nenhum achado retornado pelas verificações executadas. Isso não garante ausência de vulnerabilidades.")
    for i, f in enumerate(findings, 1):
        triage = status_labels.get(f.get("triage_status"), f.get("triage_status", "Revisão manual"))
        lines += [
            f"### {i}. [{_md_text(f.get('severity', 'Info'))}] {_md_text(f.get('title', 'Achado'))}", "",
            f"- **Origem:** {_md_text(f.get('source', ''))}",
            f"- **Local:** {_inline_code(f.get('location', ''))}",
            f"- **Confiança:** {_md_text(f.get('confidence', ''))}",
            f"- **Triagem:** {_md_text(triage)}",
            f"- **Justificativa:** {_md_text(f.get('triage_reason', 'Revisão manual necessária.'))}", "",
            _md_text(f.get("description", "")), "",
            "**Evidência**", *_fenced(str(f.get("evidence", ""))[:5000]), "",
            "**Recomendação**", _md_text(f.get("recommendation", "")), ""
        ]
        locations = f.get("locations", [])
        if len(locations) > 1:
            lines += ["**Locais adicionais da mesma observação**", *[f"- {_inline_code(loc)}" for loc in locations[1:]], ""]
    lines += ["## Metadados", ""]
    lines += _fenced(json.dumps(report.get("metadata", {}), indent=2, ensure_ascii=False), "json")
    lines.append("")
    return "\n".join(lines)


def _slug(text):
    ascii_text = unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", ascii_text.lower()).strip("-") or "achado"


def _split_location(location):
    if "://" not in location:
        match = re.match(r"^(?P<path>.+?):(?P<line>\d+)$", location)
        if match:
            return match.group("path"), int(match.group("line"))
    return location, None


def findings_to_sarif(report):
    """SARIF 2.1.0, ready for GitHub code scanning (upload-sarif) and other viewers."""
    rules, rule_index, results = [], {}, []
    for f in report.get("findings", []):
        title = str(f.get("title", "Achado"))
        severity = f.get("severity", "Info")
        rule_id = f.get("rule_id") or "vulnagent." + _slug(title)
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": _slug(title),
                "shortDescription": {"text": title},
                "fullDescription": {"text": str(f.get("description") or title)},
                "help": {"text": str(f.get("recommendation") or "Revise manualmente.")},
                "properties": {"tags": ["security"], "security-severity": _SECURITY_SEVERITY.get(severity, "0.0")},
            })
        locations = []
        for loc in f.get("locations") or [f.get("location", "")]:
            if not loc:
                continue
            path, line = _split_location(str(loc))
            physical = {"artifactLocation": {"uri": path.replace("\\", "/")}}
            if line:
                physical["region"] = {"startLine": line}
            locations.append({"physicalLocation": physical})
        result = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _SARIF_LEVEL.get(severity, "note"),
            "message": {"text": f"{title}: {f.get('description', '')}".strip()[:2000]},
            "properties": {key: f[key] for key in ("severity", "confidence", "source", "triage_status") if f.get(key)},
        }
        if locations:
            result["locations"] = locations
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "VulnAgent", "version": __version__,
                                "informationUri": "https://github.com/raianemlima/security", "rules": rules}},
            "results": results,
        }],
    }
