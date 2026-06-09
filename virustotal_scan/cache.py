"""Cache persistence and whitelist matching for VT scan results."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from virustotal_scan.models import ScanResult


@dataclass
class CacheEntry:
    """A single cache entry for a scanned file.

    Attributes:
        sha256: SHA-256 hash of the scanned file.
        passed: Whether the file passed the scan policy.
        vt_link: Link to the VirusTotal analysis page.
        reason: Categorised failure reason, if any.
        details: Human-readable description of the outcome.
        engine_threats: Mapping from engine name to threat label.
        sandbox_flags: Sandbox verdicts associated with the file.
    """

    sha256: str = ""
    passed: bool = False
    vt_link: str = ""
    reason: str | None = None
    details: str = ""
    engine_threats: dict[str, str] = field(default_factory=dict)
    sandbox_flags: list[str] = field(default_factory=list)
    cached_at: float = 0.0


class FileCacheProvider:
    """JSON file-based cache provider.

    Attributes:
        path: Filesystem path to the JSON cache file.
    """

    def __init__(self, path: Path) -> None:
        """Initialise the cache provider.

        Args:
            path: Filesystem path to the JSON cache file.
        """
        self._path = path

    def load(self) -> dict[str, CacheEntry]:
        """Load the cache from a JSON file on disk.

        Returns:
            dict[str, CacheEntry]: The cached data keyed by file name, or an
                empty dict if the file does not exist.
        """
        if self._path.is_file():
            with open(self._path, "r", encoding="utf-8") as f:
                raw: dict[str, dict[str, Any]] = json.load(f)
            return {k: CacheEntry(**v) for k, v in raw.items()}
        return {}

    def save(self, cache: dict[str, CacheEntry]) -> None:
        """Persist the cache to a JSON file on disk.

        Args:
            cache (dict[str, CacheEntry]): The cache data to persist keyed by
                file name.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump({k: v.__dict__ for k, v in cache.items()}, f, indent=2)


def load_whitelist(path: Path) -> list[dict[str, Any]]:
    """Load whitelist entries from a JSON file.

    Args:
        path (Path): Path to the whitelist JSON file.

    Returns:
        list[dict[str, Any]]: List of whitelist entries, or an empty list if
            the file does not exist.
    """
    if path.is_file():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def matches_whitelist(result: ScanResult, whitelist: list[dict[str, Any]]) -> bool:
    """Check whether a scan result matches a whitelist entry.

    An entry matches when the sha256, engine threats, and sandbox flags are
    all identical.

    Args:
        result (ScanResult): The scan result to check.
        whitelist (list[dict[str, Any]]): List of whitelist entries loaded from
            file.

    Returns:
        bool: True if the result matches a whitelist entry.
    """
    for entry in whitelist:
        if entry.get("sha256") != result.sha256:
            continue
        wl_engines = entry.get("engine_threats", {})
        if set(result.engine_threats.keys()) != set(wl_engines.keys()):
            continue
        if any(result.engine_threats[e] != wl_engines[e] for e in wl_engines):
            continue
        wl_sandbox = set(entry.get("sandbox_flags", []))
        if set(result.sandbox_flags) != wl_sandbox:
            continue
        return True
    return False
