import json
import os
import subprocess
import time

import pytest

from vuln_agent import scanners
from vuln_agent.scanners import parse_osv_results, scan_code


@pytest.fixture(autouse=True)
def no_external_scanners(monkeypatch):
    monkeypatch.setattr(scanners.shutil, "which", lambda name: None)


def scan(tmp_path, files):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    findings, _meta = scan_code(tmp_path)
    return findings


def titles_at(findings, filename):
    return {f["title"] for f in findings if f["location"].split(":")[0] == filename}


def test_secrets_are_detected_but_never_shown_in_clear(tmp_path, fake_secrets):
    findings = scan(tmp_path, {
        "settings.py": f'API_KEY = "{fake_secrets["stripe"]}"\nSECRET_KEY = "django-insecure-{fake_secrets["password"]}"\n',
        "deploy.sh": f"export AWS_ACCESS_KEY_ID={fake_secrets['aws']}\n",
    })
    dumped = json.dumps(findings)
    for value in (fake_secrets["stripe"], fake_secrets["aws"], fake_secrets["password"]):
        assert value not in dumped
    assert "Possível segredo exposto: chave secreta Stripe" in titles_at(findings, "settings.py")
    assert "Possível segredo hardcoded" in titles_at(findings, "settings.py")  # Django SECRET_KEY
    assert "Possível segredo exposto: chave de acesso AWS" in titles_at(findings, "deploy.sh")
    # One secret, one finding: the Stripe key is not reported again as a generic assignment.
    assert sum(1 for f in findings if f["location"] == "settings.py:1") == 1


def test_placeholder_values_are_ignored(tmp_path):
    findings = scan(tmp_path, {"config.py": 'API_KEY = "${API_KEY}"\npassword = "changeme123"\n'
                                            'token_url = "https://example.com/oauth/token"\n'})
    assert not titles_at(findings, "config.py")


def test_parameterized_sql_is_not_flagged_but_string_building_is(tmp_path):
    findings = scan(tmp_path, {
        "safe.py": 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n',
        "unsafe.py": ('cursor.execute("SELECT * FROM users WHERE id = %s" % uid)\n'
                      'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n'
                      'cursor.execute("SELECT * FROM users WHERE id = " + uid)\n'),
    })
    assert not titles_at(findings, "safe.py")
    assert sum(1 for f in findings if f["title"] == "Possível SQL Injection") == 3


def test_method_calls_named_eval_are_not_flagged(tmp_path):
    findings = scan(tmp_path, {"train.py": "model.eval()\n", "calc.py": "result = eval(user_input)\n"})
    assert not titles_at(findings, "train.py")
    assert "Uso de eval()" in titles_at(findings, "calc.py")


def test_language_specific_rules(tmp_path):
    findings = scan(tmp_path, {
        "view.js": "if (el.innerHTML == old) {}\nel.innerHTML = userHtml;\n",
        "notes.py": "# el.innerHTML = x is a JS thing\n",
        "loader.py": ("import yaml, pickle, subprocess, hashlib\n"
                      "yaml.load(stream)\n"
                      "yaml.load(stream, Loader=yaml.SafeLoader)\n"
                      "pickle.loads(blob)\n"
                      "subprocess.run(cmd, shell=True)\n"
                      "hashlib.md5(data, usedforsecurity=False)\n"
                      "hashlib.md5(password)\n"),
    })
    assert sum(1 for f in findings if f["title"] == "Atribuição a innerHTML") == 1
    assert not titles_at(findings, "notes.py")
    loader = [f for f in findings if f["location"].startswith("loader.py")]
    assert {f["location"] for f in loader if f["title"] == "Desserialização insegura"} == {"loader.py:2", "loader.py:4"}
    assert any(f["title"] == "Execução de comando via shell" for f in loader)
    assert [f["location"] for f in loader if f["title"].startswith("Hash")] == ["loader.py:7"]
    assert all(f.get("rule_id", "").startswith("vulnagent.") for f in findings)


def test_env_variants_are_flagged_but_templates_are_not(tmp_path):
    findings = scan(tmp_path, {".env.production": "X=1\n", ".env.example": "X=\n"})
    env = [f for f in findings if f["title"] == "Arquivo .env presente no escopo"]
    assert [f["location"] for f in env] == [".env.production"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks indisponíveis")
def test_symlinks_outside_root_are_not_followed(tmp_path, fake_secrets):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "creds.py").write_text(f'TOKEN = "{fake_secrets["github"]}"\n', encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    try:
        os.symlink(outside / "creds.py", repo / "link.py")
        os.symlink(outside, repo / "linked_dir", target_is_directory=True)
    except OSError:
        pytest.skip("sem permissão para criar symlinks")
    findings, meta = scan_code(repo)
    assert findings == [] and meta["files_examined"] == 0


def test_project_inside_a_folder_named_build_is_scanned(tmp_path):
    root = tmp_path / "build" / "app"
    findings = scan(root, {"main.py": "eval(x)\n"})
    assert titles_at(findings, "main.py") == {"Uso de eval()"}


def test_hostile_file_does_not_hang_the_scanner(tmp_path):
    hostile = ("sk-" * 100_000) + ("a" * 300_000) + ("eyJ" * 50_000)
    start = time.perf_counter()
    scan(tmp_path, {"bundle.js": hostile})
    assert time.perf_counter() - start < 10


def test_semgrep_runs_without_metrics_and_reports_relative_redacted_results(tmp_path, monkeypatch, fake_secrets):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        output = {"results": [{
            "check_id": "python.secrets.hardcoded", "path": str(tmp_path.resolve() / "app.py"),
            "start": {"line": 1},
            "extra": {"severity": "ERROR", "message": "Hardcoded secret",
                      "lines": f'password = "{fake_secrets["password"]}"', "metadata": {}},
        }], "errors": []}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(output), "")

    monkeypatch.setattr(scanners.shutil, "which", lambda name: "/usr/bin/semgrep" if name == "semgrep" else None)
    monkeypatch.setattr(scanners.subprocess, "run", fake_run)
    findings, meta = scan_code(tmp_path)
    assert "--metrics=off" in calls[0] and "--config=p/default" in calls[0]
    semgrep = next(f for f in findings if f["source"] == "Semgrep")
    assert semgrep["location"] == "app.py:1"
    assert semgrep["rule_id"] == "python.secrets.hardcoded"
    assert fake_secrets["password"] not in semgrep["evidence"]
    assert meta["scanner_status"]["semgrep"] == "concluído"


def test_osv_results_become_one_actionable_finding_per_package(tmp_path):
    data = {"results": [{
        "source": {"path": str(tmp_path / "requirements.txt"), "type": "lockfile"},
        "packages": [
            {"package": {"name": "jinja2", "version": "2.4.1", "ecosystem": "PyPI"},
             "vulnerabilities": [{
                 "id": "GHSA-462w-v97r-4m45", "summary": "Jinja2 sandbox escape", "aliases": ["CVE-2019-10906"],
                 "affected": [{"package": {"name": "Jinja2", "ecosystem": "PyPI"},
                               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}],
             }],
             "groups": [{"ids": ["GHSA-462w-v97r-4m45"], "max_severity": "8.6"}]},
            {"package": {"name": "requests", "version": "2.32.0", "ecosystem": "PyPI"}, "vulnerabilities": []},
        ],
    }]}
    findings = parse_osv_results(data, tmp_path.resolve())
    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "Dependência vulnerável: jinja2@2.4.1"
    assert finding["severity"] == "High"
    assert finding["location"] == "requirements.txt"
    assert "CVE-2019-10906" in finding["evidence"]
    assert "2.10.1" in finding["recommendation"]
