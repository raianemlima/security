from vuln_agent.reporting import findings_to_markdown, findings_to_sarif, make_report

def test_report_has_schema_and_findings():
    finding = {"title": "Example", "severity": "Low", "description": "Example finding"}
    report = make_report("code", "repo", [finding], {"scanner_status": {}})
    assert report["schema_version"] == "1.0"
    assert report["findings"][0]["title"] == "Example"
    assert "Example" in findings_to_markdown(report)

def test_empty_report():
    report = make_report("site", "https://example.com", [], {})
    assert "Nenhum achado" in findings_to_markdown(report)

def test_evidence_cannot_break_out_of_its_code_block():
    payload = "x\n```\n![track](https://attacker.example/p.png)\n```"
    report = make_report("code", "repo", [{"title": "t", "severity": "Low", "evidence": payload}], {})
    markdown = findings_to_markdown(report)
    assert "````text\n" + payload + "\n````" in markdown

def test_free_text_cannot_inject_links_or_html():
    report = make_report("code", "repo", [{"title": "![x](https://attacker.example/a.png)", "severity": "Low",
                                           "description": "<img src=https://attacker.example/b.png>"}], {})
    markdown = findings_to_markdown(report)
    assert "!\\[x\\](" in markdown and "\\<img" in markdown  # rendered as literal text

def test_report_masks_secrets_from_any_source(fake_secrets):
    finding = {"title": "Semgrep", "severity": "High", "source": "Semgrep",
               "evidence": f'api_key = "{fake_secrets["password"]}"'}
    report = make_report("code", "repo", [finding], {})
    assert fake_secrets["password"] not in findings_to_markdown(report)
    assert fake_secrets["password"] not in str(findings_to_sarif(report))

def test_findings_are_sorted_by_severity():
    report = make_report("code", "repo", [{"title": "a", "severity": "Info"}, {"title": "b", "severity": "High"},
                                          {"title": "c", "severity": "Medium"}], {})
    assert [f["severity"] for f in report["findings"]] == ["High", "Medium", "Info"]

def test_sarif_export():
    findings = [
        {"title": "Uso de eval()", "severity": "High", "location": "src/app.py:12", "rule_id": "vulnagent.eval"},
        {"title": "Uso de eval()", "severity": "High", "location": "src/other.py:3", "rule_id": "vulnagent.eval"},
        {"title": "Cabeçalho HSTS ausente", "severity": "Medium", "location": "https://example.com:8443"},
    ]
    sarif = findings_to_sarif(make_report("code", "repo", findings, {}))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["vulnagent.eval", "vulnagent.cabecalho-hsts-ausente"]
    first = run["results"][0]  # identical observations are merged, keeping every location
    assert first["level"] == "error"
    assert [loc["physicalLocation"] for loc in first["locations"]] == [
        {"artifactLocation": {"uri": "src/app.py"}, "region": {"startLine": 12}},
        {"artifactLocation": {"uri": "src/other.py"}, "region": {"startLine": 3}},
    ]
    assert run["results"][1]["locations"][0]["physicalLocation"] == {"artifactLocation": {"uri": "https://example.com:8443"}}
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"
