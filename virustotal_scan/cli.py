"""Command-line interface and entry point for the VirusTotal scanner."""

import argparse
import os
import sys
from pathlib import Path

from virustotal_scan._config import CACHE_PATH, REPORT_PATH, WHITELIST_PATH, env_float
from virustotal_scan.cache import FileCacheProvider
from virustotal_scan.file_utils import resolve_scan_paths
from virustotal_scan.pipeline import ScanPipeline
from virustotal_scan.reporters import (CompositeReporter, ConsoleReporter, GitHubActionReporter, JsonReportWriter,
                                       ResultReporter)


def _split_paths_string(raw: str) -> list[str]:
    """Split a comma/newline-delimited path string into individual items.

    Args:
        raw: A string with paths separated by commas or newlines.

    Returns:
        List of stripped, non-empty path strings.
    """
    parts = []
    for part in raw.replace("\n", ",").split(","):
        part = part.strip()
        if part:
            parts.append(part)
    return parts


def main() -> None:
    """Parse CLI arguments and run the VirusTotal scan pipeline.

    Exits the process with status 0 if all scans passed, 1 otherwise.
    """
    parser = argparse.ArgumentParser(description="VirusTotal file scanner")
    parser.add_argument(
        "--scan-paths",
        default=None,
        help="Comma/newline-separated file or directory paths (falls back to VT_SCAN_PATHS env var)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        default=None,
        help="Skip cache lookup but still update cache (falls back to VT_NO_CACHE env var)",
    )
    parser.add_argument(
        "--cache-path",
        default=None,
        help="Path to cache file (falls back to VT_CACHE_PATH env var, default: vt_cache.json)",
    )
    parser.add_argument(
        "--whitelist-path",
        default=None,
        help="Path to whitelist file (falls back to VT_WHITELIST_PATH env var, default: vt_whitelist.json)",
    )
    parser.add_argument(
        "--report-path",
        default=None,
        help="Path to JSON report output (falls back to VT_REPORT_PATH env var, default: vt_report.json)",
    )
    args = parser.parse_args()

    raw = args.scan_paths if args.scan_paths is not None else os.getenv("VT_SCAN_PATHS", "")
    if not raw.strip():
        print("No scan paths provided. Use --scan-paths or set VT_SCAN_PATHS env var.")
        sys.exit(1)

    no_cache = args.no_cache if args.no_cache is not None else os.getenv("VT_NO_CACHE", "").lower() == "true"

    api_key = os.getenv("VT_API_KEY", "")
    if not api_key:
        print("VT_API_KEY is not set. Add a VirusTotal API key as environment variable VT_API_KEY.")
        sys.exit(1)

    cache_path = Path(args.cache_path if args.cache_path is not None else os.getenv("VT_CACHE_PATH", str(CACHE_PATH)))
    whitelist_path = Path(
        args.whitelist_path if args.whitelist_path is not None else os.getenv("VT_WHITELIST_PATH", str(WHITELIST_PATH))
    )
    report_path = Path(
        args.report_path if args.report_path is not None else os.getenv("VT_REPORT_PATH", str(REPORT_PATH))
    )

    paths = _split_paths_string(raw)
    print(
        f"VirusTotal scan | paths={paths} | no_cache={no_cache} | "
        f"cache={cache_path} | whitelist={whitelist_path} | "
        f"VT_REQUEST_INTERVAL_SEC={env_float('VT_REQUEST_INTERVAL_SEC', 15)}"
    )

    file_paths = resolve_scan_paths(paths)
    print(f"Resolved {len(file_paths)} file(s) from {len(paths)} path(s)")

    console: ResultReporter
    if os.getenv("USE_GITHUB_ACTION_REPORTER") == "true":
        console = GitHubActionReporter()
    else:
        console = ConsoleReporter()
    reporter = CompositeReporter(
        [
            console,
            JsonReportWriter(report_path),
        ]
    )

    pipeline = ScanPipeline(
        file_paths=file_paths,
        reporter=reporter,
        cache=FileCacheProvider(cache_path),
        whitelist_path=whitelist_path,
        api_key=api_key,
        no_cache=no_cache,
    )

    exit_code = pipeline.execute()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
