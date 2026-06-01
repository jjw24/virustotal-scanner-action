"""Orchestration pipeline for the full VT scan lifecycle.

Owns the top-level control flow that drives per-file scanning via
``ScanPipeline.execute()``.  Responsibilities:

- Iterate over every provided file path.
- For each file, look up a cache entry keyed by file name.
    - Cache hit (matching SHA-256 + cached as passed): reconstruct a
      ``ScanResult`` from cached data, check the whitelist, report, skip
      the VT API call.
    - Cache miss / stale / not-passed: call VT API via ``scan_file_vt``.
- After VT analysis, consult the whitelist: if the result matches, flip
  it to passed and mark it whitelisted.
- Persist passing (non-whitelisted) results back to the cache immediately
  and flush the cache file to disk after each file.
- On a ``QUOTA_EXCEEDED`` result, stop processing remaining files
  immediately and exit with code 1.
- Report every result as it arrives and emit a final summary.
- Return exit code 0 (all passed) or 1 (any failed).
"""

from pathlib import Path
from typing import Any

from virustotal_scan.analysis import scan_file_vt
from virustotal_scan.cache import CacheEntry, FileCacheProvider, load_whitelist, matches_whitelist
from virustotal_scan.file_utils import sha256_file
from virustotal_scan.models import FailReason, ScanResult
from virustotal_scan.reporters import ResultReporter
from virustotal_scan.vt_client import VTClient


class ScanPipeline:
    """Orchestrates the full VT scan lifecycle.

    Composed of injectable strategies so behaviour can be extended
    without modifying this class (Open/Closed Principle).

    The pipeline follows this decision flow for each file:

    ::

        ┌─ Cache hit (SHA match + passed)? ──> report cached result ──┐
        │                                                             │
        No                                                           next
        │                                                             │
        └─ VT API scan ──> whitelist check ──> report ──> cache ─────┘

    If a scan returns :attr:`FailReason.QUOTA_EXCEEDED` the loop breaks
    immediately and the pipeline exits with code 1.
    """

    def __init__(
        self,
        file_paths: list[Path],
        reporter: ResultReporter,
        cache: FileCacheProvider,
        whitelist_path: Path,
        api_key: str,
        no_cache: bool = False,
    ) -> None:
        """Initialise the pipeline with its strategies and configuration.

        Args:
            file_paths: List of file paths to scan.
            reporter: Strategy for reporting results.
            cache: Strategy for persisting scan cache entries.
            whitelist_path: Path to the whitelist JSON file.
            api_key: VirusTotal API key.
            no_cache: If True, skip cache lookups (still updates cache).
        """
        self._file_paths = file_paths
        self._reporter = reporter
        self._cache = cache
        self._whitelist_path = whitelist_path
        self._api_key = api_key
        self._no_cache = no_cache

    def execute(self) -> int:
        """Run the full scan pipeline over all configured file paths.

        For each file:
        1. Compute the SHA-256 hash.
        2. Attempt a cache lookup (unless ``no_cache``).
           - **Cache hit**: reconstruct ``ScanResult`` from the cached entry,
             apply whitelist check, report, and **skip** the VT API call.
        3. **Cache miss / bypass**: call the VT API via ``scan_file_vt``.
        4. **Whitelist override**: if the VT result is not-passed but matches
           a whitelist entry, flip it to passed.
        5. **Cache write**: persist passing (non-whitelisted) results and
           flush the cache file to disk after every file.
        6. **Early exit**: if the scan result has
           :attr:`FailReason.QUOTA_EXCEEDED`, stop processing remaining
           files immediately.
        7. **Report**: notify the reporter for every result.

        After all files have been processed the reporter receives a final
        summary.

        Returns:
            int: Exit code- ``0`` if every file passed, ``1`` if any failed.
        """
        if not self._file_paths:
            return 0

        meta: dict[str, Any] = {"file_count": len(self._file_paths)}
        vt = VTClient(self._api_key)
        cache = self._cache.load()
        whitelist = load_whitelist(self._whitelist_path)
        results: list[ScanResult] = []

        for file_path in self._file_paths:
            sha = sha256_file(file_path)
            cache_key = file_path.name
            cached = cache.get(cache_key)

            if not self._no_cache and cached and cached.sha256 == sha and cached.passed:
                r = ScanResult(
                    file_name=str(file_path),
                    passed=True,
                    sha256=sha,
                    vt_link=cached.vt_link,
                    step="cache",
                    elapsed_sec=0.0,
                    engine_threats=cached.engine_threats,
                    sandbox_flags=cached.sandbox_flags,
                )
                if matches_whitelist(r, whitelist):
                    r.whitelisted = True
                results.append(r)
                self._reporter.on_progress(r)
                continue

            r = scan_file_vt(vt, file_path)

            # sha256 is only set by scan_file_vt on a successful response;
            # on exceptions (timeout, API error, etc.) it stays empty, so
            # fill in the local hash we already computed.
            if not r.sha256:
                r.sha256 = sha

            if not r.passed and matches_whitelist(r, whitelist):
                r.passed = True
                r.whitelisted = True

            results.append(r)
            self._reporter.on_progress(r)

            if r.passed and not r.whitelisted:
                cache[cache_key] = CacheEntry(
                    sha256=r.sha256,
                    passed=r.passed,
                    vt_link=r.vt_link,
                    reason=r.reason.value if r.reason else None,
                    details=r.details,
                    engine_threats=r.engine_threats,
                    sandbox_flags=r.sandbox_flags,
                )

            self._cache.save(cache)

            if r.reason == FailReason.QUOTA_EXCEEDED:
                break

        self._reporter.on_complete(results, meta)
        return 1 if any(not r.passed for r in results) else 0
