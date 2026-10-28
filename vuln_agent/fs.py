"""Bounded, symlink-safe file iteration shared by the local scanners."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable, Iterator


def iter_files(
    root: Path,
    accept: Callable[[Path], bool],
    *,
    skip_dirs: set[str] | frozenset[str],
    max_files: int,
    max_bytes: int,
) -> Iterator[Path]:
    """Yield regular files under ``root`` accepted by ``accept``.

    - Ignored directories are pruned before descending (node_modules is never walked).
    - Only directory names *below* ``root`` are compared, so a project living in
      ``C:\\build\\app`` is still analysed.
    - Symlinks (files or directories) are never followed, so a repository cannot make
      the scanner read files outside the selected folder.
    """
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
        for name in sorted(filenames):
            if count >= max_files:
                return
            path = Path(dirpath) / name
            if not accept(path):
                continue
            try:
                info = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
                continue
            count += 1
            yield path
