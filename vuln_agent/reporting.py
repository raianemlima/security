from datetime import datetime, timezone

from vuln_agent.policy import detect_policy_profile, triage_findings


def make_report(target_type, target, findings, meta):
    profile = detect_policy_profile(target) if target_type == "site" else "generic"
    triaged = triage_findings(findings, profile)
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
        "schema_version": "1.1",
        "tool": "VulnAgent",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_type": target_type,
        "target": target,
        "policy_profile": profile,
        "authorized_use_notice": "Use somente em alvos próprios ou expressamente autorizados.",
        "metadata": report_meta,
        "findings": triaged
    }


def findings_to_markdown(report):
    lines = [
        "# Relatório VulnAgent", "",
        f"- **Gerado em:** {report.get('generated_at')}",
        f"- **Tipo:** {report.get('target_type')}",
        f"- **Alvo:** `{report.get('target')}`",
        f"- **Perfil de triagem:** {report.get('policy_profile', 'generic')}",
        "", "> Os achados são indicadores automatizados. A triagem não confirma explorabilidade; revise as evidências antes de reportar.", "",
        "## Resumo", ""
    ]
    findings = report.get("findings", [])
    lines.append(f"- **Total de achados:** {len(findings)}")
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
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
        lines += [
            f"### {i}. [{f.get('severity','Info')}] {f.get('title','Achado')}", "",
            f"- **Origem:** {f.get('source','')}",
            f"- **Local:** `{f.get('location','')}`",
            f"- **Confiança:** {f.get('confidence','')}",
            f"- **Triagem:** {status_labels.get(f.get('triage_status'), f.get('triage_status', 'Revisão manual'))}",
            f"- **Justificativa:** {f.get('triage_reason', 'Revisão manual necessária.')}", "",
            f.get("description", ""), "",
            "**Evidência**", "```text", str(f.get("evidence", ""))[:5000], "```", "",
            "**Recomendação**", f.get("recommendation", ""), ""
        ]
        locations = f.get("locations", [])
        if len(locations) > 1:
            lines += ["**Locais adicionais da mesma observação**", *[f"- `{loc}`" for loc in locations[1:]], ""]
    lines += ["## Metadados", "", "```json"]
    import json
    lines.append(json.dumps(report.get("metadata", {}), indent=2, ensure_ascii=False))
    lines += ["```", ""]
    return "\n".join(lines)
