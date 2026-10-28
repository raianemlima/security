"""Entry points shared by the Streamlit panel and the CLI."""
from __future__ import annotations

from pathlib import Path

from vuln_agent.js_security import scan_javascript_patterns
from vuln_agent.reporting import make_report
from vuln_agent.scanners import scan_code
from vuln_agent.solana_security import scan_solana_programs
from vuln_agent.web import scan_site, validate_site_url


def analyze_code(root: Path, target_label: str | None = None) -> dict:
    findings, meta = scan_code(Path(root))
    findings.extend(scan_javascript_patterns(Path(root)))
    meta.setdefault("scanner_status", {})["javascript-static"] = "concluído"
    findings.extend(scan_solana_programs(Path(root)))
    meta["scanner_status"]["solana-static"] = "concluído"
    return make_report("code", target_label or str(root), findings, meta)


def analyze_site(url: str, extra_headers: dict[str, str] | None = None) -> dict:
    safe_url = validate_site_url(url)
    findings, meta = scan_site(safe_url, extra_headers)
    return make_report("site", safe_url, findings, meta)
