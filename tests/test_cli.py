import json
import zipfile

import pytest

from vuln_agent import scanners
from vuln_agent.cli import main


@pytest.fixture(autouse=True)
def no_external_scanners(monkeypatch):
    monkeypatch.setattr(scanners.shutil, "which", lambda name: None)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("result = eval(user_input)\n", encoding="utf-8")
    return root


def test_fail_on_threshold(repo, capsys):
    assert main(["code", str(repo)]) == 0
    assert "Uso de eval()" in capsys.readouterr().out
    assert main(["code", str(repo), "--fail-on", "high"]) == 1
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    assert main(["code", str(repo), "--fail-on", "low"]) == 0


def test_json_and_sarif_outputs(repo, tmp_path):
    out = tmp_path / "report.json"
    assert main(["code", str(repo), "-f", "json", "-o", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["findings"][0]["location"] == "app.py:1"
    sarif = tmp_path / "report.sarif"
    assert main(["code", str(repo), "-f", "sarif", "-o", str(sarif)]) == 0
    assert json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"][0]["ruleId"] == "vulnagent.eval"


def test_zip_input(tmp_path, capsys):
    archive = tmp_path / "code.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("proj/app.py", "eval(x)\n")
    assert main(["code", str(archive), "-f", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["target"] == "code.zip"
    assert report["findings"][0]["location"] == "app.py:1"


def test_errors_exit_with_code_2(tmp_path, capsys):
    assert main(["code", str(tmp_path / "missing")]) == 2
    assert main(["site", "http://127.0.0.1/"]) == 2
    assert "erro:" in capsys.readouterr().err


def test_site_rejects_forbidden_identification_header(capsys):
    assert main(["site", "https://example.com/", "-H", "Cookie: session=1"]) == 2
    assert "Cookie" in capsys.readouterr().err
