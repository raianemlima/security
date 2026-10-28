import io
import stat
import zipfile

import pytest

from vuln_agent.inputs import local_path_enabled, pick_scan_root, resolve_local_path, safe_extract_zip


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            if isinstance(entry, zipfile.ZipInfo):
                zf.writestr(entry, "../../etc/passwd")
            else:
                zf.writestr(*entry)
    buf.seek(0)
    return buf


def test_extracts_normal_archive_and_picks_single_root(tmp_path):
    info = safe_extract_zip(make_zip([("proj/app.py", "print(1)"), ("proj/sub/x.js", "x")]), tmp_path)
    assert info["members"] == 2
    assert pick_scan_root(tmp_path) == tmp_path / "proj"
    assert (tmp_path / "proj" / "sub" / "x.js").read_text() == "x"


def test_rejects_path_traversal(tmp_path):
    with pytest.raises(ValueError, match="path traversal"):
        safe_extract_zip(make_zip([("../evil.py", "x")]), tmp_path / "dest")
    assert not (tmp_path / "evil.py").exists()


def test_rejects_zip_bomb_before_writing(tmp_path):
    archive = make_zip([("bomb.txt", b"\0" * (5 * 1024 * 1024))])
    with pytest.raises(ValueError, match="zip bomb"):
        safe_extract_zip(archive, tmp_path, max_total_bytes=1024 * 1024)
    assert list(tmp_path.iterdir()) == []


def test_rejects_too_many_entries(tmp_path):
    with pytest.raises(ValueError, match="entradas demais"):
        safe_extract_zip(make_zip([(f"f{i}.txt", "x") for i in range(11)]), tmp_path, max_members=10)


def test_skips_symlink_entries(tmp_path):
    link = zipfile.ZipInfo("proj/passwd")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    info = safe_extract_zip(make_zip([link, ("proj/ok.py", "x")]), tmp_path)
    assert info["skipped_symlinks"] == 1
    assert not (tmp_path / "proj" / "passwd").exists()


def test_local_path_allowlist(tmp_path):
    allowed = tmp_path / "repos"
    (allowed / "app").mkdir(parents=True)
    other = tmp_path / "secret"
    other.mkdir()
    assert resolve_local_path(str(allowed / "app"), [allowed.resolve()]) == (allowed / "app").resolve()
    with pytest.raises(ValueError, match="fora das raízes"):
        resolve_local_path(str(other), [allowed.resolve()])
    with pytest.raises(ValueError, match="fora das raízes"):
        resolve_local_path(str(allowed / "app" / ".." / ".." / "secret"), [allowed.resolve()])
    with pytest.raises(ValueError):
        resolve_local_path(str(tmp_path / "missing"), [])
    with pytest.raises(ValueError):
        resolve_local_path("   ", [])


def test_local_path_can_be_disabled(monkeypatch):
    monkeypatch.delenv("VULNAGENT_DISABLE_LOCAL_PATH", raising=False)
    assert local_path_enabled()
    monkeypatch.setenv("VULNAGENT_DISABLE_LOCAL_PATH", "1")
    assert not local_path_enabled()
