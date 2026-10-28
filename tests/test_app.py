from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from vuln_agent import scanners

APP = str(Path(__file__).resolve().parent.parent / "app.py")


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    monkeypatch.setattr(scanners.shutil, "which", lambda name: None)
    for var in ("OPENAI_API_KEY", "VULNAGENT_ALLOWED_ROOTS", "VULNAGENT_DISABLE_LOCAL_PATH"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)


def test_local_folder_scan_renders_masked_results(tmp_path, fake_secrets):
    (tmp_path / "app.py").write_text(f'eval(x)\nAPI_TOKEN = "{fake_secrets["password"]}"\n', encoding="utf-8")
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.text_input[0].input(str(tmp_path))
    at.button[0].click().run()
    assert not at.exception
    assert at.metric[0].value == "2"
    labels = [e.label for e in at.expander]
    assert any("Uso de eval()" in label for label in labels)
    rendered = " ".join(str(c.value) for c in at.code)
    assert fake_secrets["password"] not in rendered


def test_allowlist_blocks_folders_outside_allowed_roots(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("VULNAGENT_ALLOWED_ROOTS", str(allowed))
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.text_input[0].input(str(tmp_path))
    at.button[0].click().run()
    assert "fora das raízes permitidas" in at.error[0].value


def test_local_folder_option_can_be_disabled(monkeypatch):
    monkeypatch.setenv("VULNAGENT_DISABLE_LOCAL_PATH", "1")
    at = AppTest.from_file(APP, default_timeout=30).run()
    origin = next(r for r in at.radio if r.label == "Origem")
    assert origin.options == ["Upload ZIP"]
