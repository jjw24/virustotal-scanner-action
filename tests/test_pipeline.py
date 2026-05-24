"""Tests for the scan pipeline orchestration."""

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

        def fake_scan(vt, path):
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

        def fake_scan(vt, path):
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
