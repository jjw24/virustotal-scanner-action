"""Scan result reporters - console output and JSON report writing."""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from virustotal_scan.models import ScanResult


class ResultReporter(ABC):
    """Interface for reporting scan results as they are produced.

    Subclasses implement :meth:`on_progress` (called after each file) and
    :meth:`on_complete` (called once all files are done).
    """

    @abstractmethod
    def on_progress(self, result: ScanResult) -> None:
        """Called after each individual file scan.

        Args:
            result: The scan result for a single file.
        """

    @abstractmethod
    def on_complete(self, results: list[ScanResult], meta: dict[str, Any]) -> None:
        """Called once all scans are finished.

        Args:
            results: All scan results from the pipeline run.
            meta: Top-level metadata (e.g. file count).
        """


class ConsoleReporter(ResultReporter):
    """Prints scan progress and summary to stdout."""

    def on_progress(self, result: ScanResult) -> None:
        """Print per-file scan status to stdout.

        Args:
            result: The scan result for a single file.
        """
        if result.whitelisted:
            status = "PASS(whitelisted)"
        elif result.step == "cache":
            status = "PASS(cache_file)" if result.passed else "FAIL(cache_file)"
        elif result.step == "report":
            status = "PASS(cache_report)" if result.passed else "FAIL(cache_report)"
        elif result.passed:
            status = "PASS"
        else:
            status = "FAIL"
        print(f"[{status}] {result.file_name} | sha256={result.sha256[:12]}... | {result.elapsed_sec:.1f}s")

    def on_complete(self, results: list[ScanResult], meta: dict[str, Any]) -> None:
        """Print a summary block with pass/fail counts and failure details.

        Args:
            results: All scan results from the pipeline run.
            meta: Top-level metadata (e.g. file count).
        """
        total = len(results)
        passed = sum(1 for r in results if r.passed and not r.whitelisted)
        whitelisted = sum(1 for r in results if r.whitelisted)
        failed = sum(1 for r in results if not r.passed)
        print("\n--- Summary ---")
        print(f"{total} scanned | {passed} passed | {whitelisted} whitelisted | {failed} failed")

        failed_results = [r for r in results if not r.passed]
        if failed_results:
            print()
            for r in failed_results:
                print(f"{r.file_name}")
                print(f"  reason: {r.reason.value if r.reason else 'UNKNOWN'}")
                print(f"  {r.details}")
                if r.vt_link:
                    print(f"  {r.vt_link}")
                if r.engine_threats:
                    engine_detections = [f"{e} detection: {t}" for e, t in r.engine_threats.items()]
                    print(f"  engine: {', '.join(engine_detections)}")
                if r.sandbox_flags:
                    print(f"  sandbox: {', '.join(r.sandbox_flags)}")


class GitHubActionReporter(ResultReporter):
    """Decorates :class:`ConsoleReporter` with GitHub Actions log grouping.

    Emits ``::group::`` / ``::endgroup::`` workflow commands so the
    per-file progress and the summary each appear in their own collapsible
    section.  Delegates all output to an internal :class:`ConsoleReporter`.
    """

    def __init__(self) -> None:
        self._inner = ConsoleReporter()
        self._files_open = False

    def on_progress(self, result: ScanResult) -> None:
        """Open the "Files" group on first call, then delegate.

        Args:
            result: The scan result for a single file.
        """
        if not self._files_open:
            print("::group::VirusTotal Scanner - Files")
            self._files_open = True
        self._inner.on_progress(result)

    def on_complete(self, results: list[ScanResult], meta: dict[str, Any]) -> None:
        """Close the "Files" group, open "Summary", delegate, close.

        Args:
            results: All scan results from the pipeline run.
            meta: Top-level metadata (e.g. file count).
        """
        if self._files_open:
            print("::endgroup::")
        print("::group::VirusTotal Scanner - Summary")
        self._inner.on_complete(results, meta)
        print("::endgroup::")


class JsonReportWriter(ResultReporter):
    """Writes the full JSON report to disk after each file scan.

    Results are accumulated in memory and the complete report (meta +
    all results collected so far) is written to disk on every
    ``on_progress`` call so partial output is always available.
    ``on_complete`` is intentionally a no-op - the last ``on_progress``
    already captured the final state.
    """

    def __init__(self, report_path: Path) -> None:
        """Initialise the JSON report writer.

        Args:
            report_path: Path where the JSON report will be written.
        """
        self._report_path = report_path
        self._results: list[ScanResult] = []

    def on_progress(self, result: ScanResult) -> None:
        """Write to the json report on disk after the file scan is complete.

        The on-disk file is overwritten with the full list of results
        accumulated so far so that partial output is available if the
        process is interrupted.

        Args:
            result: The scan result for a single file.
        """
        self._results.append(result)
        self._report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._report_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "meta": {"scanned_files": len(self._results)},
                    "results": [
                        {
                            "file_name": item.file_name,
                            "passed": item.passed,
                            "whitelisted": item.whitelisted,
                            "reason": item.reason.value if item.reason else None,
                            "details": item.details,
                            "sha256": item.sha256,
                            "vt_link": item.vt_link,
                            "flagged_engines": item.flagged_engines,
                            "engine_threats": item.engine_threats,
                            "sandbox_flags": item.sandbox_flags,
                        }
                        for item in self._results
                    ],
                },
                f,
                indent=2,
            )

    def on_complete(self, results: list[ScanResult], meta: dict[str, Any]) -> None:
        """No-op - the last ``on_progress`` already wrote the final state."""


class CompositeReporter(ResultReporter):
    """Holds multiple reporters and calls all of them for every event.

    The pipeline only talks to one ``ResultReporter``, but we often want
    to both print to the console *and* write a JSON report. This class
    wraps a list of reporters and forwards each ``on_progress`` /
    ``on_complete`` call to every one of them.
    """

    def __init__(self, reporters: list[ResultReporter]) -> None:
        """Initialise the composite reporter.

        Args:
            reporters: List of reporter instances to delegate to.
        """
        self._reporters = reporters

    def on_progress(self, result: ScanResult) -> None:
        """Forward a progress event to all wrapped reporters.

        Args:
            result: The scan result for a single file.
        """
        for reporter in self._reporters:
            reporter.on_progress(result)

    def on_complete(self, results: list[ScanResult], meta: dict[str, Any]) -> None:
        """Forward a completion event to all wrapped reporters.

        Args:
            results: All scan results from the pipeline run.
            meta: Top-level metadata (e.g. file count).
        """
        for reporter in self._reporters:
            reporter.on_complete(results, meta)
