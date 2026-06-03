"""Tests for scan result reporters."""

import json

from virustotal_scan.models import FailReason, ScanResult
from virustotal_scan.reporters import CompositeReporter, ConsoleReporter, GitHubActionReporter, JsonReportWriter


class TestConsoleReporter:
    def test_passed_progress(self, capsys):
        reporter = ConsoleReporter()
        r = ScanResult(
            file_name="/a/file.zip",
            passed=True,
            sha256="a" * 64,
            step="done",
            elapsed_sec=1.5,
        )
        reporter.on_progress(r)
        captured = capsys.readouterr()
        assert "[PASS]" in captured.out
        assert "file.zip" in captured.out

    def test_failed_progress(self, capsys):
        reporter = ConsoleReporter()
        r = ScanResult(
            file_name="/b/file.zip",
            passed=False,
            sha256="a" * 64,
            step="done",
            elapsed_sec=1.5,
        )
        reporter.on_progress(r)
        captured = capsys.readouterr()
        assert "[FAIL]" in captured.out

    def test_cache_progress(self, capsys):
        reporter = ConsoleReporter()
        r = ScanResult(
            file_name="/c/file.zip",
            passed=True,
            sha256="a" * 64,
            step="cache",
            elapsed_sec=0.0,
        )
        reporter.on_progress(r)
        captured = capsys.readouterr()
        assert "PASS(cache_file)" in captured.out

    def test_report_progress_pass(self, capsys):
        reporter = ConsoleReporter()
        r = ScanResult(
            file_name="/e/file.zip",
            passed=True,
            sha256="a" * 64,
            step="report",
            elapsed_sec=0.0,
        )
        reporter.on_progress(r)
        captured = capsys.readouterr()
        assert "PASS(cache_report)" in captured.out

    def test_report_progress_fail(self, capsys):
        reporter = ConsoleReporter()
        r = ScanResult(
            file_name="/f/file.zip",
            passed=False,
            sha256="a" * 64,
            step="report",
            elapsed_sec=0.0,
        )
        reporter.on_progress(r)
        captured = capsys.readouterr()
        assert "FAIL(cache_report)" in captured.out

    def test_whitelisted_progress(self, capsys):
        reporter = ConsoleReporter()
        r = ScanResult(
            file_name="/d/file.zip",
            passed=True,
            whitelisted=True,
            sha256="a" * 64,
            step="done",
            elapsed_sec=0.5,
        )
        reporter.on_progress(r)
        captured = capsys.readouterr()
        assert "PASS(whitelisted)" in captured.out

    def test_summary_all_passed(self, capsys):
        reporter = ConsoleReporter()
        r = ScanResult(
            file_name="/a/file.zip",
            passed=True,
            step="done",
            elapsed_sec=1.0,
        )
        reporter.on_complete([r], {})
        captured = capsys.readouterr()
        assert "1 scanned" in captured.out
        assert "1 passed" in captured.out
        assert "0 failed" in captured.out

    def test_summary_with_failures(self, capsys):
        reporter = ConsoleReporter()
        passed = ScanResult(
            file_name="/p/file.zip",
            passed=True,
            step="done",
            elapsed_sec=1.0,
        )
        failed = ScanResult(
            file_name="/f/file.zip",
            passed=False,
            step="done",
            elapsed_sec=1.0,
            reason=FailReason.DETECTION,
            details="malicious=1",
        )
        reporter.on_complete([passed, failed], {})
        captured = capsys.readouterr()
        assert "2 scanned" in captured.out
        assert "1 failed" in captured.out
        assert "/f/file.zip" in captured.out
        assert "DETECTION" in captured.out


class TestGitHubActionReporter:
    def test_opens_files_group_on_first_progress(self, capsys):
        reporter = GitHubActionReporter()
        r = ScanResult(file_name="/a/file.zip", passed=True, sha256="a" * 64, step="done", elapsed_sec=1.0)
        reporter.on_progress(r)
        captured = capsys.readouterr()
        assert "::group::VirusTotal Scanner - Files" in captured.out

    def test_single_group_for_multiple_progress_calls(self, capsys):
        reporter = GitHubActionReporter()
        r1 = ScanResult(file_name="/a/file.zip", passed=True, sha256="a" * 64, step="done", elapsed_sec=1.0)
        r2 = ScanResult(file_name="/b/file.zip", passed=True, sha256="b" * 64, step="done", elapsed_sec=2.0)
        reporter.on_progress(r1)
        reporter.on_progress(r2)
        captured = capsys.readouterr()
        assert captured.out.count("::group::VirusTotal Scanner - Files") == 1

    def test_closes_files_and_opens_summary_on_complete(self, capsys):
        reporter = GitHubActionReporter()
        r = ScanResult(file_name="/a/file.zip", passed=True, sha256="a" * 64, step="done", elapsed_sec=1.0)
        reporter.on_progress(r)
        reporter.on_complete([r], {})
        captured = capsys.readouterr()
        assert "::endgroup::" in captured.out
        assert "::group::VirusTotal Scanner - Summary" in captured.out

    def test_closes_summary_on_complete(self, capsys):
        reporter = GitHubActionReporter()
        r = ScanResult(file_name="/a/file.zip", passed=True, sha256="a" * 64, step="done", elapsed_sec=1.0)
        reporter.on_progress(r)
        reporter.on_complete([r], {})
        captured = capsys.readouterr()
        assert captured.out.rstrip().endswith("::endgroup::")

    def test_inner_reporter_still_receives_calls(self, capsys):
        reporter = GitHubActionReporter()
        r = ScanResult(file_name="/a/file.zip", passed=True, sha256="a" * 64, step="done", elapsed_sec=1.0)
        reporter.on_progress(r)
        captured = capsys.readouterr()
        assert "[PASS]" in captured.out

    def test_no_progress_emits_summary_group_only(self, capsys):
        reporter = GitHubActionReporter()
        reporter.on_complete([], {})
        captured = capsys.readouterr()
        assert "::group::VirusTotal Scanner - Summary" in captured.out
        assert "::group::VirusTotal Scanner - Files" not in captured.out


class TestJsonReportWriter:
    def test_writes_all_results(self, tmp_path):
        path = tmp_path / "report.json"
        writer = JsonReportWriter(path)
        r = ScanResult(file_name="/a/file.zip", passed=True, sha256="a" * 64)
        writer.on_progress(r)
        assert path.is_file()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data["results"]) == 1
        assert data["results"][0]["passed"] is True

    def test_writes_failures(self, tmp_path):
        path = tmp_path / "report.json"
        writer = JsonReportWriter(path)
        r = ScanResult(
            file_name="/f/file.zip",
            passed=False,
            sha256="a" * 64,
            reason=FailReason.DETECTION,
            details="malicious=1",
        )
        writer.on_progress(r)
        assert path.is_file()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data["results"]) == 1
        assert data["results"][0]["passed"] is False

    def test_incremental_write(self, tmp_path):
        path = tmp_path / "report.json"
        writer = JsonReportWriter(path)
        r1 = ScanResult(file_name="/a.zip", passed=True, sha256="a" * 64)
        r2 = ScanResult(file_name="/b.zip", passed=False, sha256="b" * 64, reason=FailReason.DETECTION)
        writer.on_progress(r1)
        writer.on_progress(r2)
        writer.on_complete([r1, r2], {"scanned_files": 2})
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["meta"]["file_count"] == 2
        assert len(data["results"]) == 2
        assert data["results"][0]["passed"] is True
        assert data["results"][1]["passed"] is False


class TestCompositeReporter:
    def test_delegates_progress(self):
        calls = []

        class FakeReporter:
            def on_progress(self, r):
                calls.append("progress")

            def on_complete(self, results, meta):
                calls.append("complete")

        composite = CompositeReporter([FakeReporter(), FakeReporter()])
        r = ScanResult(file_name="/x.zip", passed=True)
        composite.on_progress(r)
        assert calls.count("progress") == 2

    def test_delegates_complete(self):
        calls = []

        class FakeReporter:
            def on_progress(self, r):
                calls.append("progress")

            def on_complete(self, results, meta):
                calls.append("complete")

        composite = CompositeReporter([FakeReporter(), FakeReporter()])
        composite.on_complete([], {})
        assert calls.count("complete") == 2
