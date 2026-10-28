from vuln_agent.policy import detect_policy_profile, triage_finding
from vuln_agent.reporting import make_report, findings_to_markdown


def test_1win_profile_is_host_scoped():
    assert detect_policy_profile("https://1win.com/pt") == "hackerone-1win"
    assert detect_policy_profile("https://www.1win.com/pt/betting") == "hackerone-1win"
    assert detect_policy_profile("https://not1win.com/") == "generic"


def test_1win_missing_headers_are_not_reportable_as_is():
    for title, evidence in [
        ("Cabeçalho HSTS ausente", "Cabeçalho ausente: Strict-Transport-Security"),
        ("Content Security Policy ausente", "Cabeçalho ausente: Content-Security-Policy"),
        ("X-Content-Type-Options ausente", "Cabeçalho ausente: X-Content-Type-Options"),
        ("Referrer-Policy ausente", "Cabeçalho ausente: Referrer-Policy"),
        ("Permissions-Policy ausente", "Cabeçalho ausente: Permissions-Policy"),
    ]:
        result = triage_finding({"title": title, "severity": "Medium", "evidence": evidence}, "hackerone-1win")
        assert result["triage_status"] == "not_reportable_as_is"


def test_1win_server_and_cookie_flags_need_no_report_without_impact():
    server = triage_finding({
        "title": "Cabeçalho Server divulgado", "severity": "Info",
        "evidence": "Server: cloudflare",
    }, "hackerone-1win")
    cookie = triage_finding({
        "title": "Atributos de cookie ausentes", "severity": "Low",
        "evidence": "device-id; atributos ausentes: SameSite",
    }, "hackerone-1win")
    assert server["triage_status"] == "not_reportable_as_is"
    assert cookie["triage_status"] == "not_reportable_as_is"


def test_1win_cors_requires_impact_validation():
    result = triage_finding({
        "title": "CORS permite qualquer origem nesta resposta",
        "severity": "Info", "evidence": "Access-Control-Allow-Origin: *",
    }, "hackerone-1win")
    assert result["triage_status"] == "needs_impact_validation"


def test_1win_report_profile_and_deduplication():
    first = {
        "title": "Cabeçalho Server divulgado", "severity": "Info",
        "source": "verificação HTTP", "location": "https://1win.com/pt",
        "evidence": "Server: cloudflare",
    }
    second = dict(first, location="https://1win.com/pt/betting")
    report = make_report("site", "https://1win.com/pt", [first, second], {})
    assert report["policy_profile"] == "hackerone-1win"
    assert len(report["findings"]) == 1
    assert report["findings"][0]["locations"] == [
        "https://1win.com/pt", "https://1win.com/pt/betting"
    ]
    assert "Perfil de triagem: hackerone-1win" in findings_to_markdown(report)
