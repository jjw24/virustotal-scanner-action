"""Domain models for VirusTotal file scan results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class FailReason(str, Enum):
    """Enumeration of failure reasons for VirusTotal scans.

    Attributes:
        FILE_ERROR: The file could not be read or processed locally.
        VT_API_ERROR: The VirusTotal API returned an error.
        ANALYSIS_TIMEOUT: The analysis did not complete within the timeout.
        DETECTION: One or more engines flagged the file.
        QUOTA_EXCEEDED: The VirusTotal API quota was exceeded.
    """

    FILE_ERROR = "FILE_ERROR"
    VT_API_ERROR = "VT_API_ERROR"
    ANALYSIS_TIMEOUT = "ANALYSIS_TIMEOUT"
    DETECTION = "DETECTION"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"


@dataclass
class ScanResult:
    """Result of scanning a single file with VirusTotal.

    Attributes:
        file_name: Name of the scanned file.
        passed: Whether the file passed the scan policy.
        reason: Categorised failure reason, if any.
        details: Human-readable description of the outcome.
        sha256: SHA-256 hash of the file.
        vt_link: Link to the VirusTotal analysis page.
        step: Processing step at which the result was produced.
        elapsed_sec: Time taken for the scan in seconds.
        flagged_engines: Names of engines that flagged the file.
        engine_threats: Mapping from engine name to threat label.
        sandbox_flags: Sandbox verdicts associated with the file.
        whitelisted: Whether the file matched a whitelist rule.
    """

    file_name: str
    passed: bool
    reason: Optional[FailReason] = None
    details: str = ""
    sha256: str = ""
    vt_link: str = ""
    step: str = ""
    elapsed_sec: float = 0.0
    flagged_engines: list[str] = field(default_factory=list)
    engine_threats: dict[str, str] = field(default_factory=dict)
    sandbox_flags: list[str] = field(default_factory=list)
    whitelisted: bool = False
