"""VirusTotal v3 API client with throttling and retry logic."""

import time
from pathlib import Path
from typing import Any

import requests
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


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
