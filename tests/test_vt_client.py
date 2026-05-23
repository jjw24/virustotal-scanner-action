import pytest
import requests

from virustotal_scan.vt_client import _is_retryable


def _make_resp(status_code: int) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    return resp


class TestIsRetryable:
    def test_rate_limit_is_retryable(self):
        exc = requests.HTTPError(response=_make_resp(429))
        assert _is_retryable(exc) is True

    @pytest.mark.parametrize("code", [500, 502, 503])
    def test_server_error_is_retryable(self, code):
        exc = requests.HTTPError(response=_make_resp(code))
        assert _is_retryable(exc) is True

    @pytest.mark.parametrize("code", [400, 401, 403, 404, 422])
    def test_client_error_not_retryable(self, code):
        exc = requests.HTTPError(response=_make_resp(code))
        assert _is_retryable(exc) is False

    @pytest.mark.parametrize("exc", [requests.ConnectionError(), requests.Timeout()])
    def test_request_exception_is_retryable(self, exc):
        assert _is_retryable(exc) is True

    def test_other_exception_not_retryable(self):
        assert _is_retryable(ValueError("x")) is False
