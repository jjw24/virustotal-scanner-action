from unittest.mock import MagicMock, patch

import pytest
import requests

from virustotal_scan.vt_client import VTClient, _is_retryable, _wait_retry


# ------------------------------------------------------------------
# _is_retryable
# ------------------------------------------------------------------

def _make_resp(status_code: int) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    return resp


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

class MockRetryState:
    def __init__(self, exception):
        self.outcome = MagicMock()
        self.outcome.exception.return_value = exception


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
