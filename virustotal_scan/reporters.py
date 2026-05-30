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
            status = "PASS(cache)"
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
    """Writes a JSON report file for failed results."""

    def __init__(self, report_path: Path) -> None:
        """Initialise the JSON report writer.

        Args:
            report_path: Path where the JSON report will be written.
        """
        self._report_path = report_path

    def on_progress(self, result: ScanResult) -> None:
        """No-op per-file; JSON output is written on completion.

        Args:
            result: The scan result for a single file (unused).
        """
        pass

    def on_complete(self, results: list[ScanResult], meta: dict[str, Any]) -> None:
        """Write a JSON report file with all scan results.

        Only writes to disk when at least one scan has failed.

        Args:
            results: All scan results from the pipeline run.
            meta: Top-level metadata (e.g. file count).
        """
        if not any(not r.passed for r in results):
            return
        self._report_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "meta": meta,
            "results": [
                {
                    "file_name": r.file_name,
                    "passed": r.passed,
                    "whitelisted": r.whitelisted,
                    "reason": r.reason.value if r.reason else None,
                    "details": r.details,
                    "sha256": r.sha256,
                    "vt_link": r.vt_link,
                    "flagged_engines": r.flagged_engines,
                    "engine_threats": r.engine_threats,
                    "sandbox_flags": r.sandbox_flags,
                }
                for r in results
            ],
        }
        with open(self._report_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)


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
