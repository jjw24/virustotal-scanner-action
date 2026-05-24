"""File utilities - path resolution and hashing."""

import hashlib
from pathlib import Path


def resolve_scan_paths(paths: list[str]) -> list[Path]:
    """Resolve scan paths into a list of file paths to scan.

    Each path may be:

    * A regular file - included directly.
    * A directory - every regular file inside (non-recursive, sorted by name).

    Args:
        paths: One or more filesystem paths (relative or absolute).

    Returns:
        List of resolved ``Path`` objects for files to scan.

    Raises:
        SystemExit: If any path does not exist on disk.
    """
    files: list[Path] = []
    missing: list[str] = []
    for path_str in paths:
        p = Path(path_str)
        if not p.exists():
            missing.append(path_str)
            continue
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for entry in sorted(p.iterdir()):
                if entry.is_file():
                    files.append(entry)
    if missing:
        raise SystemExit(f"FILE_ERROR: path(s) not found: {', '.join(missing)}")
    return files


def sha256_file(path: Path) -> str:
    """Compute the SHA-256 hex digest of a file.

    Args:
        path: Path to the file to hash.

    Returns:
        The 64-character hex-encoded SHA-256 digest.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
