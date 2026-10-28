from pathlib import Path

from vuln_agent.js_security import scan_javascript_patterns


def test_flags_postmessage_wildcard(tmp_path: Path):
    source = tmp_path / "content.js"
    source.write_text(
        'window.postMessage({ type: "status", value: "ok" }, "*");',
        encoding="utf-8",
    )

    findings = scan_javascript_patterns(tmp_path)

    assert any(f["title"] == "postMessage usa targetOrigin wildcard" for f in findings)
    finding = next(f for f in findings if f["title"] == "postMessage usa targetOrigin wildcard")
    assert finding["location"] == "content.js:1"
    assert finding["triage_status"] == "needs_manual_review"


def test_flags_referrer_origin_fallback_for_review(tmp_path: Path):
    source = tmp_path / "bridge.ts"
    source.write_text(
        'const origin = window.location.origin || document.referrer;\n',
        encoding="utf-8",
    )

    findings = scan_javascript_patterns(tmp_path)

    assert any("document.referrer" in f["evidence"] for f in findings)
    assert all(f["severity"] != "High" for f in findings)


def test_ignores_non_javascript_and_node_modules(tmp_path: Path):
    (tmp_path / "readme.md").write_text('window.postMessage({}, "*")', encoding="utf-8")
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "vendor.js").write_text('window.postMessage({}, "*")', encoding="utf-8")

    assert scan_javascript_patterns(tmp_path) == []


def test_flags_inline_message_listener_without_origin_check(tmp_path: Path):
    (tmp_path / "content.js").write_text(
        'window.addEventListener("message", (event) => {\n'
        '  document.body.innerHTML = event.data.html;\n'
        '});\n',
        encoding="utf-8",
    )

    findings = scan_javascript_patterns(tmp_path)

    listener = [f for f in findings if f["title"] == "Listener de mensagens sem verificação aparente de origem"]
    assert [f["location"] for f in listener] == ["content.js:1"]
    assert listener[0]["rule_id"] == "vulnagent.js.message-listener-without-origin-check"


def test_message_listener_with_origin_check_or_by_reference_is_not_flagged(tmp_path: Path):
    (tmp_path / "safe.js").write_text(
        'window.addEventListener("message", function (e) {\n'
        '  if (e.origin !== "https://app.example") { return; }\n'
        '  render(e.data);\n'
        '});\n'
        'window.addEventListener("message", onMessage);\n',
        encoding="utf-8",
    )

    assert scan_javascript_patterns(tmp_path) == []
