from datetime import datetime, timezone

def make_report(target_type, target, findings, meta):
    return {
        "schema_version": "1.0",
        "tool": "VulnAgent",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_type": target_type,
        "target": target,
        "authorized_use_notice": "Use somente em alvos próprios ou expressamente autorizados.",
        "metadata": meta,
        "findings": findings
    }

def findings_to_markdown(report):
    lines = [
        "# Relatório VulnAgent", "",
        f"- **Gerado em:** {report.get('generated_at')}",
        f"- **Tipo:** {report.get('target_type')}",
        f"- **Alvo:** `{report.get('target')}`",
        "", "> Este relatório contém indicadores automatizados; revise as evidências antes de confirmar vulnerabilidades.", "",
        "## Resumo", ""
    ]
    findings = report.get("findings", [])
    lines.append(f"- **Total de achados:** {len(findings)}")
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = sum(1 for f in findings if f.get("severity") == sev)
        lines.append(f"- **{sev}:** {count}")
    lines += ["", "## Achados", ""]
    if not findings:
        lines.append("Nenhum achado retornado pelas verificações executadas. Isso não garante ausência de vulnerabilidades.")
    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. [{f.get('severity','Info')}] {f.get('title','Achado')}", "",
            f"- **Origem:** {f.get('source','')}",
            f"- **Local:** `{f.get('location','')}`",
            f"- **Confiança:** {f.get('confidence','')}", "",
            f.get("description", ""), "",
            "**Evidência**", "```text", str(f.get("evidence", ""))[:5000], "```", "",
            "**Recomendação**", f.get("recommendation", ""), ""
        ]
    lines += ["## Metadados", "", "```json"]
    import json
    lines.append(json.dumps(report.get("metadata", {}), indent=2, ensure_ascii=False))
    lines += ["```", ""]
    return "\n".join(lines)
