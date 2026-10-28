"""Safe intake of code to analyse: bounded ZIP extraction and local-folder allowlist."""
from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path

MAX_ZIP_MEMBERS = 20_000
MAX_ZIP_TOTAL_BYTES = 500 * 1024 * 1024


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def safe_extract_zip(source, dest, *, max_members: int = MAX_ZIP_MEMBERS,
                     max_total_bytes: int = MAX_ZIP_TOTAL_BYTES) -> dict:
    """Extract ``source`` into ``dest`` refusing path traversal, zip bombs and symlinks.

    Sizes come from the central directory; zipfile never writes more than the declared
    ``file_size`` of a member, so summing them bounds what lands on disk.
    """
    dest = Path(dest).resolve()
    with zipfile.ZipFile(source) as zf:
        members = zf.infolist()
        if len(members) > max_members:
            raise ValueError(f"ZIP contém entradas demais ({len(members)}; limite {max_members}).")
        selected, total, skipped_links = [], 0, 0
        for info in members:
            target = (dest / info.filename).resolve()
            if dest != target and dest not in target.parents:
                raise ValueError("ZIP contém caminho inseguro (path traversal).")
            if info.flag_bits & 0x1:
                raise ValueError("ZIP protegido por senha não é suportado.")
            if _is_symlink(info):
                skipped_links += 1
                continue
            total += info.file_size
            if total > max_total_bytes:
                raise ValueError(
                    f"Conteúdo descompactado excede {max_total_bytes // (1024 * 1024)} MB (possível zip bomb).")
            selected.append(info)
        for info in selected:
            zf.extract(info, dest)
    return {"members": len(selected), "bytes": total, "skipped_symlinks": skipped_links}


def pick_scan_root(dest) -> Path:
    """If the archive has a single top-level folder, analyse that folder."""
    dest = Path(dest)
    children = [c for c in dest.iterdir() if c.name != "__MACOSX"]
    return children[0] if len(children) == 1 and children[0].is_dir() else dest


def local_path_enabled() -> bool:
    return os.getenv("VULNAGENT_DISABLE_LOCAL_PATH", "").strip().lower() not in {"1", "true", "yes", "sim"}


def allowed_roots_from_env() -> list[Path]:
    raw = os.getenv("VULNAGENT_ALLOWED_ROOTS", "")
    return [Path(p.strip()).expanduser().resolve() for p in raw.split(os.pathsep) if p.strip()]


def resolve_local_path(raw: str, allowed_roots: list[Path] | None = None) -> Path:
    """Validate a user-typed folder. With VULNAGENT_ALLOWED_ROOTS set, it must live under one of them."""
    if not raw or not raw.strip():
        raise ValueError("Informe o caminho da pasta.")
    path = Path(raw.strip()).expanduser().resolve()
    if not path.is_dir():
        raise ValueError("A pasta informada não existe ou não é uma pasta.")
    roots = allowed_roots_from_env() if allowed_roots is None else allowed_roots
    if roots and not any(path == root or root in path.parents for root in roots):
        raise ValueError("A pasta está fora das raízes permitidas (VULNAGENT_ALLOWED_ROOTS).")
    return path
