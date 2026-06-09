"""Tests for the scan pipeline orchestration."""

import time
from pathlib import Path
from typing import Any

from virustotal_scan.cache import CacheEntry
from virustotal_scan.models import FailReason, ScanResult
from virustotal_scan.pipeline import ScanPipeline
from virustotal_scan.reporters import ResultReporter


class FakeReporter(ResultReporter):
    def __init__(self) -> None:
        self.progress_calls: list[ScanResult] = []
        self.complete_calls: list[tuple[list[ScanResult], dict]] = []

    def on_progress(self, result: ScanResult) -> None:
        self.progress_calls.append(result)

    def on_complete(self, results: list[ScanResult], meta: dict[str, Any]) -> None:
        self.complete_calls.append((results, meta))


class FakeCache:
    def __init__(self, data: dict[str, CacheEntry] | None = None) -> None:
        self._data = data or {}
        self.saved: list[dict[str, CacheEntry]] = []

    def load(self) -> dict[str, CacheEntry]:
        return self._data

    def save(self, cache: dict[str, CacheEntry]) -> None:
        self.saved.append(cache)


class TestScanPipeline:
    def test_empty_file_paths_returns_zero(self):
        pipe = ScanPipeline(
            file_paths=[],
            reporter=FakeReporter(),
            cache=FakeCache(),
            whitelist_path=Path("/nonexistent"),
            api_key="test-key",
        )
        assert pipe.execute() == 0

    def test_all_passed_returns_zero(self, tmp_path, monkeypatch):
        file_path = tmp_path / "test.zip"
        file_path.write_text("fake content")

        import virustotal_scan.pipeline as pipeline_mod

        monkeypatch.setattr(pipeline_mod, "sha256_file", lambda p: "a" * 64)

        def fake_scan(vt, path, no_cache=False):
            return ScanResult(
                file_name=str(path),
                passed=True,
                sha256="a" * 64,
                vt_link="https://example.com/vt-result",
                step="done",
                elapsed_sec=0.1,
            )

        monkeypatch.setattr(pipeline_mod, "scan_file_vt", fake_scan)

        pipe = ScanPipeline(
            file_paths=[file_path],
            reporter=FakeReporter(),
            cache=FakeCache(),
            whitelist_path=tmp_path / "whitelist.json",
            api_key="test-key",
        )
        rc = pipe.execute()
        assert rc == 0

    def test_failure_reported(self, tmp_path, monkeypatch):
        file_path = tmp_path / "bad.zip"
        file_path.write_text("bad content")

        import virustotal_scan.pipeline as pipeline_mod

        monkeypatch.setattr(pipeline_mod, "sha256_file", lambda p: "b" * 64)

        def fake_scan(vt, path, no_cache=False):
            return ScanResult(
                file_name=str(path),
                passed=False,
                sha256="b" * 64,
                reason=FailReason.DETECTION,
                details="malicious=1",
                step="done",
                elapsed_sec=0.1,
            )

        monkeypatch.setattr(pipeline_mod, "scan_file_vt", fake_scan)

        reporter = FakeReporter()
        pipe = ScanPipeline(
            file_paths=[file_path],
            reporter=reporter,
            cache=FakeCache(),
            whitelist_path=tmp_path / "whitelist.json",
            api_key="test-key",
        )
        rc = pipe.execute()
        assert rc == 1
        assert len(reporter.progress_calls) == 1
        assert reporter.progress_calls[0].passed is False

    def test_cache_hit_with_fresh_entry(self, tmp_path, monkeypatch):
        file_path = tmp_path / "fresh.zip"
        file_path.write_text("fresh content")

        import virustotal_scan.pipeline as pipeline_mod

        monkeypatch.setattr(pipeline_mod, "sha256_file", lambda p: "a" * 64)

        cache_data = {
            "fresh.zip": CacheEntry(
                sha256="a" * 64,
                passed=True,
                vt_link="https://example.com",
                cached_at=time.time() - 86400 * 5,
            )
        }
        reporter = FakeReporter()
        pipe = ScanPipeline(
            file_paths=[file_path],
            reporter=reporter,
            cache=FakeCache(cache_data),
            whitelist_path=tmp_path / "whitelist.json",
            api_key="test-key",
        )
        rc = pipe.execute()
        assert rc == 0
        assert len(reporter.progress_calls) == 1
        assert reporter.progress_calls[0].step == "cache"

    def test_cache_skipped_when_stale(self, tmp_path, monkeypatch):
        file_path = tmp_path / "stale.zip"
        file_path.write_text("stale content")

        import virustotal_scan.pipeline as pipeline_mod

        monkeypatch.setattr(pipeline_mod, "sha256_file", lambda p: "b" * 64)

        cache_data = {
            "stale.zip": CacheEntry(
                sha256="b" * 64,
                passed=True,
                vt_link="https://example.com",
                cached_at=time.time() - 86400 * 60,
            )
        }

        def fake_scan(vt, path, no_cache=False):
            return ScanResult(
                file_name=str(path),
                passed=True,
                sha256="b" * 64,
                vt_link="https://example.com/vt-result",
                step="done",
                elapsed_sec=0.1,
            )

        monkeypatch.setattr(pipeline_mod, "scan_file_vt", fake_scan)

        reporter = FakeReporter()
        pipe = ScanPipeline(
            file_paths=[file_path],
            reporter=reporter,
            cache=FakeCache(cache_data),
            whitelist_path=tmp_path / "whitelist.json",
            api_key="test-key",
        )
        rc = pipe.execute()
        assert rc == 0
        assert len(reporter.progress_calls) == 1
        assert reporter.progress_calls[0].step == "done"


