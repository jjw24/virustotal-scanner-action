"""Tests for domain models - FailReason and ScanResult."""

from virustotal_scan.models import ScanResult


def test_scan_result_defaults():
    r = ScanResult(
        file_name="/tmp/test.zip",
        passed=False,
    )
    assert r.reason is None
    assert r.details == ""
    assert r.sha256 == ""
    assert r.vt_link == ""
    assert r.step == ""
    assert r.elapsed_sec == 0.0
    assert r.flagged_engines == []
    assert r.engine_threats == {}
    assert r.sandbox_flags == []
    assert r.whitelisted is False
    assert r.file_name == "/tmp/test.zip"
    assert r.passed is False
