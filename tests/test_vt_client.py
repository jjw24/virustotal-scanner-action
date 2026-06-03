import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from virustotal_scan.vt_client import VTClient, _is_retryable, _wait_retry

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_resp(status_code: int) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    return resp


def _mock_http_resp(status_code=200, json_data=None):
    """Factory for creating mock requests.Response objects."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
    return resp


class MockRetryState:
    def __init__(self, exception):
        self.outcome = MagicMock()
        self.outcome.exception.return_value = exception


# ------------------------------------------------------------------
# _is_retryable
# ------------------------------------------------------------------


class TestIsRetryable:
    @pytest.mark.parametrize("code", [429, 500, 502, 503])
    def test_retryable_http_errors(self, code):
        exception = requests.HTTPError(response=_make_resp(code))
        assert _is_retryable(exception) is True

    @pytest.mark.parametrize("code", [400, 401, 403, 404, 422])
    def test_non_retryable_http_errors(self, code):
        exception = requests.HTTPError(response=_make_resp(code))
        assert _is_retryable(exception) is False

    def test_http_error_without_response(self):
        exception = requests.HTTPError(response=None)
        assert _is_retryable(exception) is False

    @pytest.mark.parametrize("exception", [requests.ConnectionError(), requests.Timeout()])
    def test_request_exception_is_retryable(self, exception):
        assert _is_retryable(exception) is True

    def test_other_exception_not_retryable(self):
        assert _is_retryable(ValueError("x")) is False


# ------------------------------------------------------------------
# _wait_retry
# ------------------------------------------------------------------


class TestWaitRetry:
    def test_uses_retry_after_header(self):
        resp = _make_resp(429)
        resp.headers["Retry-After"] = "42"
        exception = requests.HTTPError(response=resp)
        state = MockRetryState(exception)
        assert _wait_retry(state) == 42.0

    @patch("virustotal_scan.vt_client.wait_exponential")
    def test_ignores_invalid_retry_after(self, mock_we):
        resp = _make_resp(429)
        resp.headers["Retry-After"] = "not-a-number"
        exception = requests.HTTPError(response=resp)
        state = MockRetryState(exception)
        mock_we.return_value.return_value = 15.0
        assert _wait_retry(state) == 15.0
        mock_we.assert_called_once_with(multiplier=2, min=15, max=120)

    @patch("virustotal_scan.vt_client.wait_exponential")
    def test_falls_back_when_no_header(self, mock_we):
        exception = requests.ConnectionError()
        state = MockRetryState(exception)
        mock_we.return_value.return_value = 30.0
        assert _wait_retry(state) == 30.0

    @patch("virustotal_scan.vt_client.wait_exponential")
    def test_falls_back_when_no_response(self, mock_we):
        exception = requests.HTTPError(response=None)
        state = MockRetryState(exception)
        mock_we.return_value.return_value = 15.0
        assert _wait_retry(state) == 15.0


# ------------------------------------------------------------------
# VTClient
# ------------------------------------------------------------------


class TestVTClient(unittest.TestCase):
    def setUp(self):
        self.client = VTClient(api_key="test-key-123")
        self.mock_request = MagicMock()
        self.client._session.request = self.mock_request

    def tearDown(self):
        self.client = None
        self.mock_request = None

    # -- init --

    def test_sets_api_key_header(self):
        assert self.client._session.headers["x-apikey"] == "test-key-123"

    def test_default_interval(self):
        assert self.client._interval == 15.0

    # -- throttle --

    def test_sleeps_when_below_interval(self):
        self.client._last_request = 0.0
        self.client._interval = 10.0
        with patch("time.monotonic", return_value=5.0), patch("time.sleep") as mock_sleep:
            self.client._throttle()
        mock_sleep.assert_called_once_with(5.0)

    def test_does_not_sleep_when_above_interval(self):
        self.client._last_request = 0.0
        self.client._interval = 10.0
        with patch("time.monotonic", return_value=15.0), patch("time.sleep") as mock_sleep:
            self.client._throttle()
        mock_sleep.assert_not_called()

    # -- request --

    @patch("time.sleep")
    def test_sends_authenticated_request(self, mock_sleep):
        resp = _mock_http_resp(200)
        self.mock_request.return_value = resp
        with patch("time.monotonic", return_value=10.0):
            result = self.client._request("GET", "/files/abc")
        self.mock_request.assert_called_once_with("GET", "https://www.virustotal.com/api/v3/files/abc")
        assert result is resp

    @patch("time.sleep")
    def test_request_raises_on_http_error(self, mock_sleep):
        resp = _mock_http_resp(404)
        self.mock_request.return_value = resp
        with patch("time.monotonic", return_value=10.0):
            with pytest.raises(requests.HTTPError):
                self.client._request("GET", "/files/abc")

    # -- upload_file --

    @patch("builtins.open", MagicMock())
    @patch("pathlib.Path.stat", MagicMock(return_value=MagicMock(st_size=100)))
    @patch("time.sleep")
    def test_upload_small_file_hits_files_endpoint(self, mock_sleep):
        resp = _mock_http_resp(200, json_data={"data": {"id": "x"}})
        self.mock_request.return_value = resp
        result = self.client.upload_file(Path("/fake/file.exe"))
        self.mock_request.assert_called_once()
        method, url = self.mock_request.call_args[0][0], self.mock_request.call_args[0][1]
        assert method == "POST"
        assert url == "https://www.virustotal.com/api/v3/files"
        assert result == "x"

    @patch("virustotal_scan.vt_client.requests.post")
    @patch("builtins.open", MagicMock())
    @patch("pathlib.Path.stat", MagicMock(return_value=MagicMock(st_size=64_000_000)))
    @patch("time.sleep")
    def test_upload_large_file_hits_upload_url_endpoint(self, mock_sleep, mock_post):
        url_resp = _mock_http_resp(200, json_data={"data": "https://up.vt.com/upload"})
        upload_resp = _mock_http_resp(200, json_data={"data": {"id": "y"}})
        self.mock_request.return_value = url_resp
        mock_post.return_value = upload_resp
        result = self.client.upload_file(Path("/fake/file.exe"))
        self.mock_request.assert_called_once()
        method, url = self.mock_request.call_args[0][0], self.mock_request.call_args[0][1]
        assert method == "GET"
        assert url == "https://www.virustotal.com/api/v3/files/upload_url"
        mock_post.assert_called_once()
        assert mock_post.call_args[0][0] == "https://up.vt.com/upload"
        assert result == "y"

    # -- get_file_report --

    @patch("time.sleep")
    def test_get_file_report_requests_correct_url(self, mock_sleep):
        resp = _mock_http_resp(200)
        self.mock_request.return_value = resp
        self.client.get_file_report("abc123")
        self.mock_request.assert_called_once()
        method, url = self.mock_request.call_args[0]
        assert method == "GET"
        assert url == "https://www.virustotal.com/api/v3/files/abc123"

    # -- wait_for_analysis --

    @patch("time.sleep")
    def test_wait_returns_when_completed(self, mock_sleep):
        completed_data = {"data": {"attributes": {"status": "completed"}}}
        resp = _mock_http_resp(200, json_data=completed_data)
        self.mock_request.return_value = resp
        with patch("time.monotonic", return_value=100.0):
            result = self.client.wait_for_analysis("id-123")
        assert result == completed_data["data"]

    @patch("time.sleep")
    def test_wait_raises_on_failed_status(self, mock_sleep):
        failed_data = {"data": {"attributes": {"status": "failed"}}}
        resp = _mock_http_resp(200, json_data=failed_data)
        self.mock_request.return_value = resp
        with patch("time.monotonic", return_value=100.0):
            with pytest.raises(RuntimeError, match="analysis failed"):
                self.client.wait_for_analysis("id-123")

    @patch("virustotal_scan.vt_client.env_int", return_value=0)
    @patch("time.sleep")
    def test_wait_raises_on_timeout(self, mock_sleep, mock_env_int):
        pending_data = {"data": {"attributes": {"status": "in-progress"}}}
        resp = _mock_http_resp(200, json_data=pending_data)
        self.mock_request.return_value = resp
        with patch("time.monotonic", side_effect=[100.0, 100.0, 100.0, 100.0]):
            with pytest.raises(TimeoutError, match="polls="):
                self.client.wait_for_analysis("id-123")

    # -- scan_file --

    @patch.object(VTClient, "get_file_report")
    @patch("virustotal_scan.vt_client.sha256_file", return_value="abc")
    @patch("time.sleep")
    def test_scan_uses_vt_cached_report_when_hash_exists(self, mock_sleep, mock_sha256, mock_gfr):
        mock_gfr.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                    "last_analysis_results": {"EngineA": {"category": "undetected"}},
                }
            }
        }
        with patch.object(self.client, "upload_file") as mock_uf:
            stats, sha, _, source = self.client.scan_file(Path("/fake/path"))
        assert stats == {"malicious": 0, "suspicious": 0}
        assert sha == "abc"
        assert source == "report"
        mock_uf.assert_not_called()

    @patch.object(VTClient, "get_file_report")
    @patch("virustotal_scan.vt_client.sha256_file", return_value="abc")
    @patch("time.sleep")
    def test_scan_uploads_when_vt_cached_report_missing(self, mock_sleep, mock_sha256, mock_gfr):
        missing = requests.Response()
        missing.status_code = 404
        mock_gfr.side_effect = requests.HTTPError(response=missing)
        analysis_data = {
            "attributes": {
                "stats": {"malicious": 1, "suspicious": 0},
            }
        }
        with patch.object(self.client, "upload_file", return_value="id-456"):
            with patch.object(self.client, "wait_for_analysis", return_value=analysis_data):
                stats, sha, _, source = self.client.scan_file(Path("/fake/path"))
        assert stats == {"malicious": 1, "suspicious": 0}
        assert sha == "abc"
        assert source == "upload"
