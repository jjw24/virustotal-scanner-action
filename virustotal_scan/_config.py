"""Constants, paths, and environment variable helpers for the VT scanner."""

import os
from pathlib import Path

VT_API_BASE = "https://www.virustotal.com/api/v3"
CACHE_PATH = Path("vt_cache.json")
WHITELIST_PATH = Path("vt_whitelist.json")
REPORT_PATH = Path("vt_report.json")
LARGE_FILE_BYTES = 32 * 1024 * 1024


def env_int(name: str, default: int) -> int:
    """Read an environment variable as an integer with a fallback default.

    Args:
        name: Name of the environment variable to read.
        default: Value returned when the variable is unset or empty.

    Returns:
        The parsed integer value, or the default.
    """
    val = os.getenv(name, "")
    if not val:
        return default
    return int(val)


def env_float(name: str, default: float) -> float:
    """Read an environment variable as a float with a fallback default.

    Args:
        name: Name of the environment variable to read.
        default: Value returned when the variable is unset or empty.

    Returns:
        The parsed float value, or the default.
    """
    val = os.getenv(name, "")
    if not val:
        return default
    return float(val)
