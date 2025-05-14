# Copyright 2025 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test cases for the firebase_admin._retry module."""

import time
import email.utils
from itertools import repeat
from unittest.mock import call
import pytest
import httpx
from pytest_mock import MockerFixture
import respx

from firebase_admin._retry import HttpxRetry, HttpxRetryTransport

_TEST_URL = 'http://firebase.test.url/'

@pytest.fixture
def base_url() -> str:
    """Provides a consistent base URL for tests."""
    return _TEST_URL

class TestHttpxRetryTransport():
    @pytest.mark.asyncio
    @respx.mock
    async def test_no_retry_on_success(self, base_url: str, mocker: MockerFixture):
        """Test that a successful response doesn't trigger retries."""
        retry_config = HttpxRetry(max_retries=3, status_forcelist=[500])
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        route = respx.post(base_url).mock(return_value=httpx.Response(200, text="Success"))

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        response = await client.post(base_url)

        assert response.status_code == 200
        assert response.text == "Success"
        assert route.call_count == 1
        mock_sleep.assert_not_called()

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_retry_on_non_retryable_status(self, base_url: str, mocker: MockerFixture):
        """Test that a non-retryable error status doesn't trigger retries."""
        retry_config = HttpxRetry(max_retries=3, status_forcelist=[500, 503])
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        route = respx.post(base_url).mock(return_value=httpx.Response(404, text="Not Found"))

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        response = await client.post(base_url)

        assert response.status_code == 404
        assert response.text == "Not Found"
        assert route.call_count == 1
        mock_sleep.assert_not_called()

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_on_status_code_success_on_last_retry(
            self, base_url: str, mocker: MockerFixture
    ):
        """Test retry on status code from status_forcelist, succeeding on the last attempt."""
        retry_config = HttpxRetry(max_retries=2, status_forcelist=[503, 500], backoff_factor=0.5)
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        route = respx.post(base_url).mock(side_effect=[
            httpx.Response(503, text="Attempt 1 Failed"),
            httpx.Response(500, text="Attempt 2 Failed"),
            httpx.Response(200, text="Attempt 3 Success"),
        ])

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        response = await client.post(base_url)

        assert response.status_code == 200
        assert response.text == "Attempt 3 Success"
        assert route.call_count == 3
        assert mock_sleep.call_count == 2
        # Check sleep calls (backoff_factor is 0.5)
        mock_sleep.assert_has_calls([call(0.0), call(1.0)])

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_exhausted_returns_last_response(
            self, base_url: str, mocker: MockerFixture
    ):
        """Test that the last response is returned when retries are exhausted."""
        retry_config = HttpxRetry(max_retries=1, status_forcelist=[500], backoff_factor=0)
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        route = respx.post(base_url).mock(side_effect=[
            httpx.Response(500, text="Attempt 1 Failed"),
            httpx.Response(500, text="Attempt 2 Failed (Final)"),
            # Should stop after previous response
            httpx.Response(200, text="This should not be reached"),
        ])

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        response = await client.post(base_url)

        assert response.status_code == 500
        assert response.text == "Attempt 2 Failed (Final)"
        assert route.call_count == 2 # Initial call + 1 retry
        assert mock_sleep.call_count == 1 # Slept before the single retry

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_after_header_seconds(self, base_url: str, mocker: MockerFixture):
        """Test respecting Retry-After header with seconds value."""
        retry_config = HttpxRetry(
            max_retries=1, respect_retry_after_header=True, backoff_factor=100)
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        route = respx.post(base_url).mock(side_effect=[
            httpx.Response(429, text="Too Many Requests", headers={'Retry-After': '10'}),
            httpx.Response(200, text="OK"),
        ])

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        response = await client.post(base_url)

        assert response.status_code == 200
        assert route.call_count == 2
        assert mock_sleep.call_count == 1
        # Assert sleep was called with the value from Retry-After header
        mock_sleep.assert_called_once_with(10.0)

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_after_header_http_date(self, base_url: str, mocker: MockerFixture):
        """Test respecting Retry-After header with an HTTP-date value."""
        retry_config = HttpxRetry(
            max_retries=1, respect_retry_after_header=True, backoff_factor=100)
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        # Calculate a future time and format as HTTP-date
        retry_delay_seconds = 60
        time_at_request = time.time()
        retry_time = time_at_request + retry_delay_seconds
        http_date = email.utils.formatdate(retry_time)

        route = respx.post(base_url).mock(side_effect=[
            httpx.Response(503, text="Maintenance", headers={'Retry-After': http_date}),
            httpx.Response(200, text="OK"),
        ])

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        # Patch time.time() within the test context to control the baseline for date calculation
        # Set the mock time to be *just before* the Retry-After time
        mocker.patch('time.time', return_value=time_at_request)
        response = await client.post(base_url)

        assert response.status_code == 200
        assert route.call_count == 2
        assert mock_sleep.call_count == 1
        # Check that sleep was called with approximately the correct delay
        # Allow for small floating point inaccuracies
        mock_sleep.assert_called_once()
        args, _ = mock_sleep.call_args
        assert args[0] == pytest.approx(retry_delay_seconds, abs=2)

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_after_ignored_when_disabled(self, base_url: str, mocker: MockerFixture):
        """Test Retry-After header is ignored if `respect_retry_after_header` is `False`."""
        retry_config = HttpxRetry(
            max_retries=3, respect_retry_after_header=False, status_forcelist=[429],
            backoff_factor=0.5, backoff_max=10)
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        route = respx.post(base_url).mock(side_effect=[
            httpx.Response(429, text="Too Many Requests", headers={'Retry-After': '60'}),
            httpx.Response(429, text="Too Many Requests", headers={'Retry-After': '60'}),
            httpx.Response(429, text="Too Many Requests", headers={'Retry-After': '60'}),
            httpx.Response(200, text="OK"),
        ])

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        response = await client.post(base_url)

        assert response.status_code == 200
        assert route.call_count == 4
        assert mock_sleep.call_count == 3

        # Assert sleep was called with the calculated backoff times:
        # After first attempt: delay = 0
        # After retry 1 (attempt 2): delay = 0.5 * (2**(2-1)) = 0.5 * 2 = 1.0
        # After retry 2 (attempt 3): delay = 0.5 * (2**(3-1)) = 0.5 * 4 = 2.0
        expected_sleeps = [call(0), call(1.0), call(2.0)]
        mock_sleep.assert_has_calls(expected_sleeps)

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_after_header_missing_backoff_fallback(
            self, base_url: str, mocker: MockerFixture
    ):
        """Test Retry-After header is ignored if `respect_retry_after_header`is `True` but header is
        not set."""
        retry_config = HttpxRetry(
            max_retries=3, respect_retry_after_header=True, status_forcelist=[429],
            backoff_factor=0.5, backoff_max=10)
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        route = respx.post(base_url).mock(side_effect=[
            httpx.Response(429, text="Too Many Requests"),
            httpx.Response(429, text="Too Many Requests"),
            httpx.Response(429, text="Too Many Requests"),
            httpx.Response(200, text="OK"),
        ])

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        response = await client.post(base_url)

        assert response.status_code == 200
        assert route.call_count == 4
        assert mock_sleep.call_count == 3

        # Assert sleep was called with the calculated backoff times:
        # After first attempt: delay = 0
        # After retry 1 (attempt 2): delay = 0.5 * (2**(2-1)) = 0.5 * 2 = 1.0
        # After retry 2 (attempt 3): delay = 0.5 * (2**(3-1)) = 0.5 * 4 = 2.0
        expected_sleeps = [call(0), call(1.0), call(2.0)]
        mock_sleep.assert_has_calls(expected_sleeps)

    @pytest.mark.asyncio
    @respx.mock
    async def test_exponential_backoff(self, base_url: str, mocker: MockerFixture):
        """Test that sleep time increases exponentially with `backoff_factor`."""
        # status=3 allows 3 retries (attempts 2, 3, 4)
        retry_config = HttpxRetry(
            max_retries=3, status_forcelist=[500], backoff_factor=0.1, backoff_max=10.0)
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        route = respx.post(base_url).mock(side_effect=[
            httpx.Response(500, text="Fail 1"),
            httpx.Response(500, text="Fail 2"),
            httpx.Response(500, text="Fail 3"),
            httpx.Response(200, text="Success"),
        ])

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        response = await client.post(base_url)

        assert response.status_code == 200
        assert route.call_count == 4
        assert mock_sleep.call_count == 3

        # Check expected backoff times:
        # After first attempt: delay = 0
        # After retry 1 (attempt 2): delay = 0.1 * (2**(2-1)) = 0.1 * 2 = 0.2
        # After retry 2 (attempt 3): delay = 0.1 * (2**(3-1)) = 0.1 * 4 = 0.4
        expected_sleeps = [call(0), call(0.2), call(0.4)]
        mock_sleep.assert_has_calls(expected_sleeps)

    @pytest.mark.asyncio
    @respx.mock
    async def test_backoff_max(self, base_url: str, mocker: MockerFixture):
        """Test that backoff time respects `backoff_max`."""
        # status=4 allows 4 retries. backoff_factor=1 causes rapid increase.
        retry_config = HttpxRetry(
            max_retries=4, status_forcelist=[500], backoff_factor=1, backoff_max=3.0)
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        route = respx.post(base_url).mock(side_effect=[
            httpx.Response(500, text="Fail 1"),
            httpx.Response(500, text="Fail 2"),
            httpx.Response(500, text="Fail 2"),
            httpx.Response(500, text="Fail 4"),
            httpx.Response(200, text="Success"),
        ])

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        response = await client.post(base_url)

        assert response.status_code == 200
        assert route.call_count == 5
        assert mock_sleep.call_count == 4

        # Check expected backoff times:
        # After first attempt: delay = 0
        # After retry 1 (attempt 2): delay = 1*(2**(2-1)) = 2. Clamped by max(0, min(3.0, 2)) = 2.0
        # After retry 2 (attempt 3): delay = 1*(2**(3-1)) = 4. Clamped by max(0, min(3.0, 4)) = 3.0
        # After retry 3 (attempt 4): delay = 1*(2**(4-1)) = 8. Clamped by max(0, min(3.0, 8)) = 3.0
        expected_sleeps = [call(0.0), call(2.0), call(3.0), call(3.0)]
        mock_sleep.assert_has_calls(expected_sleeps)

    @pytest.mark.asyncio
    @respx.mock
    async def test_backoff_jitter(self, base_url: str, mocker: MockerFixture):
        """Test that `backoff_jitter` adds randomness within bounds."""
        retry_config = HttpxRetry(
            max_retries=3, status_forcelist=[500], backoff_factor=0.2, backoff_jitter=0.1)
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        route = respx.post(base_url).mock(side_effect=[
            httpx.Response(500, text="Fail 1"),
            httpx.Response(500, text="Fail 2"),
            httpx.Response(500, text="Fail 3"),
            httpx.Response(200, text="Success"),
        ])

        mock_sleep = mocker.patch('asyncio.sleep', return_value=None)
        response = await client.post(base_url)

        assert response.status_code == 200
        assert route.call_count == 4
        assert mock_sleep.call_count == 3

        # Check expected backoff times are within the expected range [base - jitter, base + jitter]
        # After first attempt: delay = 0
        # After retry 1 (attempt 2): delay = 0.2 * (2**(2-1)) = 0.2 * 2 = 0.4 +/- 0.1
        # After retry 2 (attempt 3): delay = 0.2 * (2**(3-1)) = 0.2 * 4 = 0.8 +/- 0.1
        expected_sleeps = [
            call(pytest.approx(0.0, abs=0.1)),
            call(pytest.approx(0.4, abs=0.1)),
            call(pytest.approx(0.8, abs=0.1))
        ]
        mock_sleep.assert_has_calls(expected_sleeps)

    @pytest.mark.asyncio
    @respx.mock
    async def test_error_not_retryable(self, base_url):
        """Test that non-HTTP errors are raised immediately if not retryable."""
        retry_config = HttpxRetry(max_retries=3)
        transport = HttpxRetryTransport(retry=retry_config)
        client = httpx.AsyncClient(transport=transport)

        # Mock a connection error
        route = respx.post(base_url).mock(
            side_effect=repeat(httpx.ConnectError("Connection failed")))

        with pytest.raises(httpx.ConnectError, match="Connection failed"):
            await client.post(base_url)

        assert route.call_count == 1


class TestHttpxRetry():
    _TEST_REQUEST = httpx.Request('POST', _TEST_URL)

    def test_httpx_retry_copy(self, base_url):
        """Test that `HttpxRetry.copy()` creates a deep copy."""
        original = HttpxRetry(max_retries=5, status_forcelist=[500, 503], backoff_factor=0.5)
        original.history.append((base_url, None, None)) # Add something mutable

        copied = original.copy()

        # Assert they are different objects
        assert original is not copied
        assert original.history is not copied.history

        # Assert values are the same initially
        assert copied.retries_left == original.retries_left
        assert copied.status_forcelist == original.status_forcelist
        assert copied.backoff_factor == original.backoff_factor
        assert len(copied.history) == 1

        # Modify the copy and check original is unchanged
        copied.retries_left = 1
        copied.status_forcelist = [404]
        copied.history.append((base_url, None, None))

        assert original.retries_left == 5
        assert original.status_forcelist == [500, 503]
        assert len(original.history) == 1

    def test_parse_retry_after_seconds(self):
        retry = HttpxRetry()
        assert retry._parse_retry_after('10') == 10.0
        assert retry._parse_retry_after('  30  ') == 30.0


    def test_parse_retry_after_http_date(self, mocker: MockerFixture):
        mocker.patch('time.time', return_value=1000.0)
        retry = HttpxRetry()
        # Date string representing 1015 seconds since epoch
        http_date = email.utils.formatdate(1015.0)
        # time.time() is mocked to 1000.0, so delay should be 15s
        assert retry._parse_retry_after(http_date) == pytest.approx(15.0)

    def test_parse_retry_after_past_http_date(self, mocker: MockerFixture):
        """Test that a past date results in 0 seconds."""
        mocker.patch('time.time', return_value=1000.0)
        retry = HttpxRetry()
        http_date = email.utils.formatdate(990.0) # 10s in the past
        assert retry._parse_retry_after(http_date) == 0.0

    def test_parse_retry_after_invalid_date(self):
        retry = HttpxRetry()
        with pytest.raises(httpx.RemoteProtocolError, match='Invalid Retry-After header'):
            retry._parse_retry_after('Invalid Date Format')

    def test_get_backoff_time_calculation(self):
        retry = HttpxRetry(
            max_retries=6, status_forcelist=[503], backoff_factor=0.5, backoff_max=10.0)
        response = httpx.Response(503)
        # No history -> attempt 1 -> no backoff before first request
        # Note: get_backoff_time() is typically called *before* the *next* request,
        # so history length reflects completed attempts.
        assert retry.get_backoff_time() == 0.0

        # Simulate attempt 1 completed
        retry.increment(self._TEST_REQUEST, response)
        # History len 1, attempt 2 -> base case 0
        assert retry.get_backoff_time() == pytest.approx(0)

        # Simulate attempt 2 completed
        retry.increment(self._TEST_REQUEST, response)
        # History len 2, attempt 3 -> 0.5*(2^1) = 1.0
        assert retry.get_backoff_time() == pytest.approx(1.0)

        # Simulate attempt 3 completed
        retry.increment(self._TEST_REQUEST, response)
        # History len 3, attempt 4 -> 0.5*(2^2) = 2.0
        assert retry.get_backoff_time() == pytest.approx(2.0)

        # Simulate attempt 4 completed
        retry.increment(self._TEST_REQUEST, response)
        # History len 4, attempt 5 -> 0.5*(2^3) = 4.0
        assert retry.get_backoff_time() == pytest.approx(4.0)

        # Simulate attempt 5 completed
        retry.increment(self._TEST_REQUEST, response)
        # History len 5, attempt 6 -> 0.5*(2^4) = 8.0
        assert retry.get_backoff_time() == pytest.approx(8.0)

        # Simulate attempt 6 completed
        retry.increment(self._TEST_REQUEST, response)
        # History len 6, attempt 7 -> 0.5*(2^5) = 16.0 Clamped to 10
        assert retry.get_backoff_time() == pytest.approx(10.0)
