"""Uniform finding construction; evidence is always redacted."""
from __future__ import annotations

from vuln_agent.redaction import redact_text


def make_finding(title, severity, description, location="", evidence="", recommendation="",
                 source="heurística", confidence="média", rule_id="", **extra):
    finding = {
        "title": title, "severity": severity, "description": description, "location": location,
        "evidence": redact_text(str(evidence)) if evidence else "",
        "recommendation": recommendation, "source": source, "confidence": confidence,
    }
    if rule_id:
        finding["rule_id"] = rule_id
    finding.update(extra)
    return finding
