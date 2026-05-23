"""VirusTotal v3 API client with throttling and retry logic."""

import time
from pathlib import Path
from typing import Any

import requests
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from virustotal_scan._config import VT_API_BASE, LARGE_FILE_BYTES, env_float, env_int
from virustotal_scan.file_utils import sha256_file


def _is_retryable(exception: BaseException) -> bool:
    """Determine whether an exception should trigger a retry.

    Args:
        exception: The exception raised during an API call.

    Returns:
        True if the caller should retry, False otherwise.
    """
    if isinstance(exception, requests.HTTPError):
        code = exception.response.status_code if exception.response is not None else 0
        return code == 429 or code >= 500
    if isinstance(exception, requests.RequestException):
        return True
    return False


def _wait_retry(retry_state) -> float:
    """Compute the sleep duration before the next retry attempt.

    When VirusTotal throttles it replies with HTTP 429 and a
    ``Retry-After`` header that tells us how many seconds to wait.
    This function honours that header so we don't hammer the server
    again before it's ready.  If the header is missing or unreadable
    we fall back to an exponential back-off (2× multiplier, 15–120 s).

    Args:
        retry_state: The current tenacity retry state.

    Returns:
        Seconds to wait before retrying.
    """
    exception = retry_state.outcome.exception()
    if isinstance(exception, requests.HTTPError) and exception.response is not None:
        retry_after = exception.response.headers.get("Retry-After")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass
    return wait_exponential(multiplier=2, min=15, max=120)(retry_state)


class VTClient:
    """Client for the VirusTotal v3 API with throttling and retry logic."""

    def __init__(self, api_key: str) -> None:
        """Initialize the client with an API key.

        Args:
            api_key: A VirusTotal API key.
        """
        self._session = requests.Session()
        self._session.headers["x-apikey"] = api_key
        self._interval = env_float("VT_REQUEST_INTERVAL_SEC", 15.0)
        self._last_request = 0.0

    def _throttle(self) -> None:
        """Sleep if necessary to honour the configured request interval."""
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._interval:
            time.sleep(self._interval - elapsed)

    @retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(6),
        wait=_wait_retry,
        reraise=True,
    )
    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send an authenticated request to the VirusTotal API.

        Args:
            method: HTTP method (e.g. ``"GET"``, ``"POST"``).
            path: URL path relative to the API base (e.g. ``/files/{id}``).
            **kwargs: Additional arguments forwarded to ``requests.Session.request``.

        Returns:
            The server response.
        """
        self._throttle()
        url = f"{VT_API_BASE}{path}"
        resp = self._session.request(method, url, **kwargs)
        self._last_request = time.monotonic()
        if resp.status_code >= 400:
            resp.raise_for_status()
        return resp

    def upload_file(self, file_path: Path) -> str:
        """Upload a file to VirusTotal and return the analysis ID.

        Files >= 32 MiB use the large-upload endpoint.

        Args:
            file_path: Path to the file to upload.

        Returns:
            The analysis ID assigned by VirusTotal.
        """
        size = file_path.stat().st_size
        if size >= LARGE_FILE_BYTES:
            upload_url = self._request("GET", "/files/upload_url").json()["data"]
            with open(file_path, "rb") as f:
                up = requests.post(
                    upload_url,
                    files={"file": (file_path.name, f)},
                    headers={"x-apikey": self._session.headers["x-apikey"]},
                    timeout=env_int("VT_DOWNLOAD_TIMEOUT_SEC", 120) * 2,
                )
            up.raise_for_status()
            return up.json()["data"]["id"]
        with open(file_path, "rb") as f:
            resp = self._request(
                "POST",
                "/files",
                files={"file": (file_path.name, f)},
                timeout=env_int("VT_DOWNLOAD_TIMEOUT_SEC", 120) * 2,
            )
        return resp.json()["data"]["id"]

    def get_file_report(self, sha256: str) -> dict[str, Any]:
        """Fetch the file report for a given SHA-256 hash.

        Args:
            sha256: The SHA-256 digest of the file.

        Returns:
            The raw JSON response from the VirusTotal API.
        """
        resp = self._request("GET", f"/files/{sha256}")
        return resp.json()

    def wait_for_analysis(self, analysis_id: str) -> dict[str, Any]:
        """Poll the analysis endpoint until the analysis completes.

        Args:
            analysis_id: The analysis ID returned by VirusTotal.

        Returns:
            The completed analysis data.

        Raises:
            RuntimeError: If the analysis ended with a failed status.
            TimeoutError: If the analysis does not complete within the
                configured polling timeout.
        """
        deadline = time.monotonic() + env_int("VT_ANALYSIS_POLL_TIMEOUT_SEC", 600)
        polls = 0
        status = "unknown"
        while time.monotonic() < deadline:
            polls += 1
            data = self._request("GET", f"/analyses/{analysis_id}").json()["data"]
            status = data["attributes"].get("status")
            if status == "completed":
                return data
            if status == "failed":
                raise RuntimeError(f"analysis failed: {analysis_id}")
            time.sleep(min(30, self._interval))
        raise TimeoutError(f"polls={polls} last_status={status}")
