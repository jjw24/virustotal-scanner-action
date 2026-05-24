"""Analysis helpers and per-file scan logic."""

import time
from pathlib import Path
from typing import Any, Optional

import requests

from virustotal_scan.models import FailReason, ScanResult
from virustotal_scan.vt_client import VTClient


def flagged_engine_names(analysis_data: dict[str, Any]) -> list[str]:
    """Return the names of engines that flagged the file.

    Only engines from VirusTotal with a category of malicious or suspicious are included.
    This returns just the engine names, not the threat labels, for those
    see :func:`engine_threat_map`.

    Args:
        analysis_data: The analysis response from VirusTotal.

    Returns:
        List of engine names that flagged the file.
    """
    results = analysis_data.get("attributes", {}).get("results") or {}
    names = []
    for engine, engine_result in results.items():
        if not isinstance(engine_result, dict):
            continue
        category = engine_result.get("category", "")
        if category in ("malicious", "suspicious"):
            names.append(engine)
    return names


def engine_threat_map(analysis_data: dict[str, Any]) -> dict[str, str]:
    """Build a map of engine name to threat label for flagged engines.

    Only includes engines from VirusTotal whose category is malicious or suspicious.
    The threat label is the specific malware name reported by that engine
    (e.g. ``"Trojan.Generic"``, ``"Heur.ML.PE"``).

    Args:
        analysis_data: The analysis response from VirusTotal.

    Returns:
        Mapping from engine name to threat label for each flagged engine.
    """
    results = analysis_data.get("attributes", {}).get("results") or {}
    threats = {}
    for engine, engine_result in results.items():
        if not isinstance(engine_result, dict):
            continue
        category = engine_result.get("category", "")
        if category in ("malicious", "suspicious"):
            result = engine_result.get("result", "unknown")
            threats[engine] = result if result else "unknown"
    return threats


def evaluate_stats(stats: dict[str, Any]) -> Optional[FailReason]:
    """Decide whether the scan stats indicate a detection warranting failure.

    This is the function that determines the pass/fail outcome of a scan.
    Any malicious or suspicious result from any engine causes a detection.

    Args:
        stats: The analysis stats dict (keys like ``malicious``, ``suspicious``).

    Returns:
        ``FailReason.DETECTION`` if any engine flagged the file, else ``None``.
    """
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    if malicious > 0 or suspicious > 0:
        return FailReason.DETECTION
    return None


def scan_file_vt(vt_client: VTClient, file_path: Path) -> ScanResult:
    """Run the full scan pipeline for a single file and produce a result.

    Responsibility chain:
      1. Upload the file to VirusTotal via the VT client.
      2. Check analysis stats to decide pass/fail (via :func:`evaluate_stats`).
      3. Poll for sandbox verdicts and append any flags.
      4. Populate the :class:`ScanResult` with reason, details, and metadata.
      5. Catch and map any request/network/timeout errors to the appropriate
         ``FailReason`` so the pipeline can continue with remaining files.

    Args:
        vt_client: An initialised VTClient instance.
        file_path: Path to the file to scan.

    Returns:
        A ScanResult populated with the scan outcome, reason, details,
        flagged engines, threat labels, sandbox flags, and elapsed time.
    """
    start_time = time.monotonic()
    result = ScanResult(
        file_name=str(file_path),
        passed=False,
        step="upload",
    )
    try:
        stats, file_sha, analysis = vt_client.scan_file(file_path)
        result.sha256 = file_sha
        result.vt_link = f"https://www.virustotal.com/gui/file/{file_sha}/detection"
        result.flagged_engines = flagged_engine_names(analysis)
        result.engine_threats = engine_threat_map(analysis)
        fail_reason = evaluate_stats(stats)

        try:
            sandbox_verdicts = {}
            for attempt in range(3):
                file_report = vt_client.get_file_report(file_sha)
                sandbox_verdicts = file_report.get("data", {}).get("attributes", {}).get("sandbox_verdicts", {})
                if sandbox_verdicts:
                    break
                time.sleep(15)

            for sandbox_name, verdict in sandbox_verdicts.items():
                verdict_category = verdict.get("category", "")
                if verdict_category not in ("harmless", "undetected"):
                    result.sandbox_flags.append(f"{sandbox_name} ({verdict_category})")
        except Exception:
            pass

        if fail_reason:
            result.reason = fail_reason
            result.details = (
                f"malicious={stats.get('malicious', 0)} suspicious={stats.get('suspicious', 0)}"
            )
            result.step = "done"
        elif result.sandbox_flags:
            result.passed = False
            result.reason = FailReason.DETECTION
            result.details = f"Sandbox flags: {', '.join(result.sandbox_flags)}"
            result.step = "done"
        else:
            result.passed = True
            result.step = "done"
    except TimeoutError as e:
        result.reason = FailReason.ANALYSIS_TIMEOUT
        result.details = str(e)
        result.step = "polling"
    except requests.HTTPError as e:
        result.reason = FailReason.VT_API_ERROR
        error_body = ""
        if e.response is not None:
            try:
                error_body = e.response.json().get("error", {}).get("message", e.response.text[:500])
            except Exception:
                error_body = e.response.text[:500]
        result.details = f"{e.request.method} {e.request.url} status={e.response.status_code if e.response else '?'} {error_body}"
        result.step = "upload"
    except requests.RequestException as e:
        result.reason = FailReason.VT_API_ERROR
        result.details = str(e)
    except Exception as e:
        result.reason = FailReason.VT_API_ERROR
        result.details = str(e)
    result.elapsed_sec = time.monotonic() - start_time
    return result
