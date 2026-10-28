from vuln_agent.reporting import make_report, findings_to_markdown

def test_report_has_schema_and_findings():
    finding = {"title": "Example", "severity": "Low", "description": "Example finding"}
    report = make_report("code", "repo", [finding], {"scanner_status": {}})
    assert report["schema_version"] == "1.0"
    assert report["findings"][0]["title"] == "Example"
    assert "Example" in findings_to_markdown(report)

def test_empty_report():
    report = make_report("site", "https://example.com", [], {})
    assert "Nenhum achado" in findings_to_markdown(report)
