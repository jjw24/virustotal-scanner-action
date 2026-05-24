"""Tests for cache persistence and whitelist matching."""

import json
from typing import Any

import pytest

from virustotal_scan.cache import CacheEntry, FileCacheProvider, load_whitelist, matches_whitelist
from virustotal_scan.models import ScanResult


@pytest.fixture
def whitelist_entry() -> dict[str, Any]:
    return {
        "sha256": "a" * 64,
        "engine_threats": {"EngineA": "Trojan.Generic"},
        "sandbox_flags": [],
    }


class TestCacheEntryDefaults:
    def test_defaults(self):
        entry = CacheEntry()
        assert entry.sha256 == ""
        assert entry.passed is False
        assert entry.vt_link == ""
        assert entry.reason is None
        assert entry.details == ""
        assert entry.engine_threats == {}
        assert entry.sandbox_flags == []

    def test_custom_values(self):
        entry = CacheEntry(
            sha256="abc123",
            passed=True,
            vt_link="https://example.com",
            reason="some reason",
            details="some details",
            engine_threats={"EngineA": "Trojan.Generic", "EngineB": "Malware"},
            sandbox_flags=["flag1", "flag2"],
        )
        assert entry.sha256 == "abc123"
        assert entry.passed is True
        assert entry.vt_link == "https://example.com"
        assert entry.reason == "some reason"
        assert entry.details == "some details"
        assert entry.engine_threats == {"EngineA": "Trojan.Generic", "EngineB": "Malware"}
        assert entry.sandbox_flags == ["flag1", "flag2"]


class TestFileCacheProvider:
    def test_load_missing_file(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        provider = FileCacheProvider(path)
        assert provider.load() == {}

    def test_save_and_load(self, tmp_path):
        path = tmp_path / "cache.json"
        provider = FileCacheProvider(path)
        data = {"key": CacheEntry(sha256="abc", passed=True)}
        provider.save(data)
        assert provider.load() == data

    def test_load_existing_file(self, tmp_path):
        path = tmp_path / "cache.json"
        data = {"key": {"sha256": "abc"}}
        path.write_text(json.dumps(data), encoding="utf-8")
        provider = FileCacheProvider(path)
        loaded = provider.load()
        assert loaded == {"key": CacheEntry(sha256="abc")}


class TestLoadWhitelist:
    def test_missing_file_returns_empty(self, tmp_path):
        assert load_whitelist(tmp_path / "missing.json") == []

    def test_loads_content(self, tmp_path):
        path = tmp_path / "wl.json"
        entries = [{"file_name": "/a/b.zip"}]
        path.write_text(json.dumps(entries), encoding="utf-8")
        assert load_whitelist(path) == entries


class TestMatchesWhitelist:
    def test_exact_match(self, whitelist_entry):
        result = ScanResult(
            file_name="/some/file.zip",
            passed=False,
            sha256="a" * 64,
            engine_threats={"EngineA": "Trojan.Generic"},
            sandbox_flags=[],
        )
        assert matches_whitelist(result, [whitelist_entry]) is True

    def test_matches_ignores_file_name(self, whitelist_entry):
        result = ScanResult(
            file_name="/different/path.zip",
            passed=False,
            sha256="a" * 64,
            engine_threats={"EngineA": "Trojan.Generic"},
            sandbox_flags=[],
        )
        assert matches_whitelist(result, [whitelist_entry]) is True

    def test_different_sha256(self, whitelist_entry):
        result = ScanResult(
            file_name="/some/file.zip",
            passed=False,
            sha256="b" * 64,
            engine_threats={"EngineA": "Trojan.Generic"},
            sandbox_flags=[],
        )
        assert matches_whitelist(result, [whitelist_entry]) is False

    def test_different_engine_threats(self, whitelist_entry):
        result = ScanResult(
            file_name="/some/file.zip",
            passed=False,
            sha256="a" * 64,
            engine_threats={"EngineA": "Different"},
            sandbox_flags=[],
        )
        assert matches_whitelist(result, [whitelist_entry]) is False

    def test_extra_engine_threats(self, whitelist_entry):
        result = ScanResult(
            file_name="/some/file.zip",
            passed=False,
            sha256="a" * 64,
            engine_threats={"EngineA": "Trojan.Generic", "EngineB": "Malware"},
            sandbox_flags=[],
        )
        assert matches_whitelist(result, [whitelist_entry]) is False

    def test_empty_whitelist(self):
        result = ScanResult(file_name="/x.zip", passed=False)
        assert matches_whitelist(result, []) is False

    def test_different_sandbox_flags(self, whitelist_entry):
        result = ScanResult(
            file_name="/some/file.zip",
            passed=False,
            sha256="a" * 64,
            engine_threats={"EngineA": "Trojan.Generic"},
            sandbox_flags=["flag1"],
        )
        assert matches_whitelist(result, [whitelist_entry]) is False

    def test_matching_sandbox_flags(self):
        entry = {
            "sha256": "a" * 64,
            "engine_threats": {"EngineA": "Trojan.Generic"},
            "sandbox_flags": ["flag1", "flag2"],
        }
        result = ScanResult(
            file_name="/x.zip",
            passed=False,
            sha256="a" * 64,
            engine_threats={"EngineA": "Trojan.Generic"},
            sandbox_flags=["flag2", "flag1"],
        )
        assert matches_whitelist(result, [entry]) is True

    def test_missing_sandbox_flags_in_entry(self):
        entry = {
            "sha256": "a" * 64,
            "engine_threats": {},
        }
        result = ScanResult(file_name="/x.zip", passed=False, sha256="a" * 64, sandbox_flags=[])
        assert matches_whitelist(result, [entry]) is True

    def test_second_entry_matches(self):
        entry1 = {"sha256": "b" * 64, "engine_threats": {}, "sandbox_flags": []}
        entry2 = {"sha256": "a" * 64, "engine_threats": {"EngineA": "Trojan.Generic"}, "sandbox_flags": []}
        result = ScanResult(
            file_name="/x.zip",
            passed=False,
            sha256="a" * 64,
            engine_threats={"EngineA": "Trojan.Generic"},
        )
        assert matches_whitelist(result, [entry1, entry2]) is True

    def test_matches_with_empty_engine_threats(self):
        entry = {
            "sha256": "a" * 64,
            "engine_threats": {},
        }
        result = ScanResult(file_name="/x.zip", passed=False, sha256="a" * 64)
        assert matches_whitelist(result, [entry]) is True
