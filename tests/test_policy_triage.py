from vuln_agent.policy import detect_policy_profile, triage_finding, triage_findings
from vuln_agent.reporting import make_report, findings_to_markdown


def test_bcny_profile_matches_exact_domain_and_subdomains():
    assert detect_policy_profile("https://www.diabrowser.com/apps") == "hackerone-bcny"
    assert detect_policy_profile("https://thebrowser.company/values") == "hackerone-bcny"
    assert detect_policy_profile("https://notdiabrowser.com/") == "generic"


def test_missing_csp_is_not_auto_medium_and_bcny_not_reportable_as_is():
    finding = {
        "title": "Content Security Policy ausente",
        "severity": "Medium",
        "evidence": "Cabeçalho ausente: Content-Security-Policy",
        "source": "verificação HTTP",
        "location": "https://www.diabrowser.com/apps",
    }
    result = triage_finding(finding, "hackerone-bcny")
    assert result["severity"] == "Low"
    assert result["triage_status"] == "not_reportable_as_is"
    assert "impacto direto" in result["triage_reason"]


def test_server_disclosure_not_reportable_as_is():
    result = triage_finding({
        "title": "Cabeçalho Server divulgado",
        "severity": "Info",
        "evidence": "Server: Vercel",
    }, "hackerone-bcny")
    assert result["triage_status"] == "not_reportable_as_is"


def test_cors_and_framing_require_impact_validation():
    cors = triage_finding({
        "title": "CORS permite qualquer origem nesta resposta",
        "severity": "Info",
        "evidence": "Access-Control-Allow-Origin: *",
    }, "hackerone-bcny")
    frame = triage_finding({
        "title": "Proteção contra enquadramento não identificada",
        "severity": "Info",
        "evidence": "X-Frame-Options ausente; CSP frame-ancestors não identificada",
    }, "hackerone-bcny")
    assert cors["triage_status"] == "needs_impact_validation"
    assert frame["triage_status"] == "needs_impact_validation"


def test_report_includes_triage_and_deduplicates_identical_observations():
    finding = {
        "title": "Cabeçalho Server divulgado",
        "severity": "Info",
        "source": "verificação HTTP",
        "location": "https://www.diabrowser.com/apps",
        "evidence": "Server: Vercel",
    }
    report = make_report("site", "https://www.diabrowser.com/apps", [finding, dict(finding)], {})
    assert report["policy_profile"] == "hackerone-bcny"
    assert len(report["findings"]) == 1
    assert report["findings"][0]["triage_status"] == "not_reportable_as_is"
    markdown = findings_to_markdown(report)
    assert "### Triagem" in markdown
    assert "Não reportável como está" in markdown


def test_code_evidence_mentioning_server_is_not_hidden_as_server_banner():
    # Regression: substring matching on "server:" used to mark real code findings as not reportable.
    result = triage_finding({
        "title": "Hardcoded credential in config", "severity": "High", "source": "Semgrep",
        "evidence": "server: {host: db, password: hunter2hunter2}",
    })
    assert result["triage_status"] == "needs_manual_review"


def test_new_web_titles_are_triaged():
    reflected = triage_finding({"title": "CORS reflete origem arbitrária", "severity": "Medium"})
    powered_by = triage_finding({"title": "Cabeçalho X-Powered-By divulgado", "severity": "Info",
                                 "evidence": "X-Powered-By: PHP/7.4"})
    weak_csp = triage_finding({"title": "Content Security Policy permissiva", "severity": "Low"}, "hackerone-bcny")
    assert reflected["triage_status"] == "needs_impact_validation"
    assert powered_by["triage_status"] == "not_reportable_as_is"
    assert weak_csp["triage_status"] == "not_reportable_as_is"
