"""Tests for analysis helpers - evaluate_stats, engine_threat_map, flagged_engine_names."""

import pytest

from virustotal_scan.analysis import engine_threat_map, evaluate_stats, flagged_engine_names
from virustotal_scan.models import FailReason


class TestEvaluateStats:
    def test_clean(self):
        assert evaluate_stats({"malicious": 0, "suspicious": 0}) is None

    def test_malicious_detected(self):
        assert evaluate_stats({"malicious": 1, "suspicious": 0}) == FailReason.DETECTION

    def test_suspicious_detected(self):
        assert evaluate_stats({"malicious": 0, "suspicious": 1}) == FailReason.DETECTION

    def test_both_detected(self):
        assert evaluate_stats({"malicious": 2, "suspicious": 3}) == FailReason.DETECTION

    def test_none_values(self):
        assert evaluate_stats({}) is None

    def test_missing_keys(self):
        assert evaluate_stats({"malicious": None, "suspicious": None}) is None


class TestEngineThreatMap:
    def test_basic(self):
        analysis = {
            "attributes": {
                "results": {
                    "EngineA": {"category": "malicious", "result": "Win32.Trojan.Generic"},
                    "EngineB": {"category": "suspicious", "result": "Trojan.GenericKD"},
                    "EngineC": {"category": "harmless", "result": None},
                    "EngineD": {"category": "malicious", "result": ""},
                }
            }
        }
        threats = engine_threat_map(analysis)
        assert threats == {
            "EngineA": "Win32.Trojan.Generic",
            "EngineB": "Trojan.GenericKD",
            "EngineD": "unknown",
        }

    def test_empty_results(self):
        analysis = {"attributes": {"results": {}}}
        assert engine_threat_map(analysis) == {}

    def test_no_results_key(self):
        assert engine_threat_map({}) == {}

    def test_non_dict_result_value(self):
        analysis = {"attributes": {"results": {"EngineX": None}}}
        assert engine_threat_map(analysis) == {}


class TestFlaggedEngineNames:
    def test_flagged_engines(self):
        analysis = {
            "attributes": {
                "results": {
                    "SafeEngine": {"category": "harmless"},
                    "BadEngine": {"category": "malicious"},
                    "SusEngine": {"category": "suspicious"},
                    "OtherEngine": {"category": "undetected"},
                }
            }
        }
        names = flagged_engine_names(analysis)
        assert "BadEngine" in names
        assert "SusEngine" in names
        assert "SafeEngine" not in names
        assert "OtherEngine" not in names

    def test_empty_results(self):
        assert flagged_engine_names({"attributes": {"results": {}}}) == []

    def test_no_results_key(self):
        assert flagged_engine_names({}) == []
