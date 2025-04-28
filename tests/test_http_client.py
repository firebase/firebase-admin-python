# Copyright 2017 Google Inc.
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

"""Tests for firebase_admin._http_client."""
from typing import Dict, Optional, Union
import pytest
import httpx
import respx
from pytest_localserver import http
from pytest_mock import MockerFixture
import requests

from firebase_admin import _http_client, _utils
from firebase_admin._retry import HttpxRetry, HttpxRetryTransport
from firebase_admin._http_client import (
    HttpxAsyncClient,
    GoogleAuthCredentialFlow,
    DEFAULT_TIMEOUT_SECONDS
)
from tests import testutils


_TEST_URL = 'http://firebase.test.url/'

@pytest.fixture
def default_retry_config() -> HttpxRetry:
    """Provides a fresh copy of the default retry config instance."""
    return _http_client.DEFAULT_HTTPX_RETRY_CONFIG

class TestHttpClient:
    def test_http_client_default_session(self):
        client = _http_client.HttpClient()
        assert client.session is not None
        assert client.base_url == ''
        recorder = self._instrument(client, 'body')
        resp = client.request('get', _TEST_URL)
        assert resp.status_code == 200
        assert resp.text == 'body'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == _TEST_URL

    def test_http_client_custom_session(self):
        session = requests.Session()
        client = _http_client.HttpClient(session=session)
        assert client.session is session
        assert client.base_url == ''
        recorder = self._instrument(client, 'body')
        resp = client.request('get', _TEST_URL)
        assert resp.status_code == 200
        assert resp.text == 'body'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == _TEST_URL

    def test_base_url(self):
        client = _http_client.HttpClient(base_url=_TEST_URL)
        assert client.session is not None
        assert client.base_url == _TEST_URL
        recorder = self._instrument(client, 'body')
        resp = client.request('get', 'foo')
        assert resp.status_code == 200
        assert resp.text == 'body'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == _TEST_URL + 'foo'

    def test_metrics_headers(self):
        client = _http_client.HttpClient()
        assert client.session is not None
        recorder = self._instrument(client, 'body')
        resp = client.request('get', _TEST_URL)
        assert resp.status_code == 200
        assert resp.text == 'body'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == _TEST_URL
        assert recorder[0].headers['X-GOOG-API-CLIENT'] == _utils.get_metrics_header()

    def test_credential(self):
        client = _http_client.HttpClient(
            credential=testutils.MockGoogleCredential())
        assert client.session is not None
        recorder = self._instrument(client, 'body')
        resp = client.request('get', _TEST_URL)
        assert resp.status_code == 200
        assert resp.text == 'body'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == _TEST_URL
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    @pytest.mark.parametrize('options, timeout', [
        ({}, _http_client.DEFAULT_TIMEOUT_SECONDS),
        ({'timeout': 7}, 7),
        ({'timeout': 0}, 0),
        ({'timeout': None}, None),
    ])
    def test_timeout(self, options, timeout):
        client = _http_client.HttpClient(**options)
        assert client.timeout == timeout
        recorder = self._instrument(client, 'body')
        client.request('get', _TEST_URL)
        assert len(recorder) == 1
        if timeout is None:
            assert recorder[0]._extra_kwargs['timeout'] is None
        else:
            assert recorder[0]._extra_kwargs['timeout'] == pytest.approx(timeout, 0.001)


    def _instrument(self, client, payload, status=200):
        recorder = []
        adapter = testutils.MockAdapter(payload, status, recorder)
        client.session.mount(_TEST_URL, adapter)
        return recorder


class TestHttpRetry:
    """Unit tests for the default HTTP retry configuration."""

    ENTITY_ENCLOSING_METHODS = ['post', 'put', 'patch']
    ALL_METHODS = ENTITY_ENCLOSING_METHODS + ['get', 'delete', 'head', 'options']

    @classmethod
    def setup_class(cls):
        # Turn off exponential backoff for faster execution.
        _http_client.DEFAULT_RETRY_CONFIG.backoff_factor = 0

        # Start a test server instance scoped to the class.
        server = http.ContentServer()
        server.start()
        cls.httpserver = server

    @classmethod
    def teardown_class(cls):
        cls.httpserver.stop()

    def setup_method(self):
        # Clean up any state in the server before starting a new test case.
        self.httpserver.requests = []

    @pytest.mark.parametrize('method', ALL_METHODS)
    def test_retry_on_503(self, method):
        self.httpserver.serve_content({}, 503)
        client = _http_client.JsonHttpClient(
            credential=testutils.MockGoogleCredential(), base_url=self.httpserver.url)
        body = None
        if method in self.ENTITY_ENCLOSING_METHODS:
            body = {'key': 'value'}
        with pytest.raises(requests.exceptions.HTTPError) as excinfo:
            client.request(method, '/', json=body)
        assert excinfo.value.response.status_code == 503
        assert len(self.httpserver.requests) == 5

    @pytest.mark.parametrize('method', ALL_METHODS)
    def test_retry_on_500(self, method):
        self.httpserver.serve_content({}, 500)
        client = _http_client.JsonHttpClient(
            credential=testutils.MockGoogleCredential(), base_url=self.httpserver.url)
        body = None
        if method in self.ENTITY_ENCLOSING_METHODS:
            body = {'key': 'value'}
        with pytest.raises(requests.exceptions.HTTPError) as excinfo:
            client.request(method, '/', json=body)
        assert excinfo.value.response.status_code == 500
        assert len(self.httpserver.requests) == 5

    def test_no_retry_on_404(self):
        self.httpserver.serve_content({}, 404)
        client = _http_client.JsonHttpClient(
            credential=testutils.MockGoogleCredential(), base_url=self.httpserver.url)
        with pytest.raises(requests.exceptions.HTTPError) as excinfo:
            client.request('get', '/')
        assert excinfo.value.response.status_code == 404
        assert len(self.httpserver.requests) == 1

class TestHttpxAsyncClient:
    def test_init_default(self, mocker: MockerFixture, default_retry_config: HttpxRetry):
        """Test client initialization with default settings (no credentials)."""

        # Mock httpx.AsyncClient and HttpxRetryTransport init to check args passed to them
        mock_async_client_init = mocker.patch('httpx.AsyncClient.__init__', return_value=None)
        mock_transport_init = mocker.patch(
            'firebase_admin._retry.HttpxRetryTransport.__init__', return_value=None
        )

        client = HttpxAsyncClient()

        assert client.base_url == ''
        assert client.timeout == DEFAULT_TIMEOUT_SECONDS
        assert client._headers == _http_client.METRICS_HEADERS
        assert client._retry_config == default_retry_config

        # Check httpx.AsyncClient call args
        _, init_kwargs = mock_async_client_init.call_args
        assert init_kwargs.get('http2') is True
        assert init_kwargs.get('timeout') == DEFAULT_TIMEOUT_SECONDS
        assert init_kwargs.get('headers') == _http_client.METRICS_HEADERS
        assert init_kwargs.get('auth') is None
        assert 'mounts' in init_kwargs
        assert 'http://' in init_kwargs['mounts']
        assert 'https://' in init_kwargs['mounts']
        assert isinstance(init_kwargs['mounts']['http://'], HttpxRetryTransport)
        assert isinstance(init_kwargs['mounts']['https://'], HttpxRetryTransport)

        # Check that HttpxRetryTransport was initialized with the default retry config
        assert mock_transport_init.call_count >= 1
        _, transport_call_kwargs = mock_transport_init.call_args_list[0]
        assert transport_call_kwargs.get('retry') == default_retry_config
        assert transport_call_kwargs.get('http2') is True

    def test_init_with_credentials(self, mocker: MockerFixture, default_retry_config: HttpxRetry):
        """Test client initialization with credentials."""

        # Mock GoogleAuthCredentialFlow, httpx.AsyncClient and HttpxRetryTransport init to
        # check args passed to them
        mock_auth_flow_init = mocker.patch(
            'firebase_admin._http_client.GoogleAuthCredentialFlow.__init__', return_value=None
        )
        mock_async_client_init = mocker.patch('httpx.AsyncClient.__init__', return_value=None)
        mock_transport_init = mocker.patch(
            'firebase_admin._retry.HttpxRetryTransport.__init__', return_value=None
        )

        mock_credential = testutils.MockGoogleCredential()
        client = HttpxAsyncClient(credential=mock_credential)

        assert client.base_url == ''
        assert client.timeout == DEFAULT_TIMEOUT_SECONDS
        assert client._headers == _http_client.METRICS_HEADERS
        assert client._retry_config == default_retry_config

        # Verify GoogleAuthCredentialFlow was initialized with the credential
        mock_auth_flow_init.assert_called_once_with(mock_credential)

        # Check httpx.AsyncClient call args
        _, init_kwargs = mock_async_client_init.call_args
        assert init_kwargs.get('http2') is True
        assert init_kwargs.get('timeout') == DEFAULT_TIMEOUT_SECONDS
        assert init_kwargs.get('headers') == _http_client.METRICS_HEADERS
        assert isinstance(init_kwargs.get('auth'), GoogleAuthCredentialFlow)
        assert 'mounts' in init_kwargs
        assert 'http://' in init_kwargs['mounts']
        assert 'https://' in init_kwargs['mounts']
        assert isinstance(init_kwargs['mounts']['http://'], HttpxRetryTransport)
        assert isinstance(init_kwargs['mounts']['https://'], HttpxRetryTransport)

        # Check that HttpxRetryTransport was initialized with the default retry config
        assert mock_transport_init.call_count >= 1
        _, transport_call_kwargs = mock_transport_init.call_args_list[0]
        assert transport_call_kwargs.get('retry') == default_retry_config
        assert transport_call_kwargs.get('http2') is True

    def test_init_with_custom_settings(self, mocker: MockerFixture):
        """Test client initialization with custom settings."""

        # Mock httpx.AsyncClient and HttpxRetryTransport init to check args passed to them
        mock_auth_flow_init = mocker.patch(
            'firebase_admin._http_client.GoogleAuthCredentialFlow.__init__', return_value=None
        )
        mock_async_client_init = mocker.patch('httpx.AsyncClient.__init__', return_value=None)
        mock_transport_init = mocker.patch(
            'firebase_admin._retry.HttpxRetryTransport.__init__', return_value=None
        )

        mock_credential = testutils.MockGoogleCredential()
        headers = {'X-Custom': 'Test'}
        custom_retry = HttpxRetry(status=1, status_forcelist=[429], backoff_factor=0)
        timeout = 60
        http2 = False

        expected_headers = {**headers, **_http_client.METRICS_HEADERS}

        client = HttpxAsyncClient(
            credential=mock_credential, base_url=_TEST_URL, headers=headers,
            retry_config=custom_retry, timeout=timeout, http2=http2)

        assert client.base_url == _TEST_URL
        assert client._headers == expected_headers
        assert client._retry_config == custom_retry
        assert client.timeout == timeout

        # Verify GoogleAuthCredentialFlow was initialized with the credential
        mock_auth_flow_init.assert_called_once_with(mock_credential)
        # Verify original headers are not mutated
        assert headers == {'X-Custom': 'Test'}

        # Check httpx.AsyncClient call args
        _, init_kwargs = mock_async_client_init.call_args
        assert init_kwargs.get('http2') is False
        assert init_kwargs.get('timeout') == timeout
        assert init_kwargs.get('headers') == expected_headers
        assert isinstance(init_kwargs.get('auth'), GoogleAuthCredentialFlow)
        assert 'mounts' in init_kwargs
        assert 'http://' in init_kwargs['mounts']
        assert 'https://' in init_kwargs['mounts']
        assert isinstance(init_kwargs['mounts']['http://'], HttpxRetryTransport)
        assert isinstance(init_kwargs['mounts']['https://'], HttpxRetryTransport)

        # Check that HttpxRetryTransport was initialized with the default retry config
        assert mock_transport_init.call_count >= 1
        _, transport_call_kwargs = mock_transport_init.call_args_list[0]
        assert transport_call_kwargs.get('retry') == custom_retry
        assert transport_call_kwargs.get('http2') is False


    @respx.mock
    @pytest.mark.asyncio
    async def test_request(self):
        """Test client request."""

        client = HttpxAsyncClient()

        responses = [
            respx.MockResponse(200, http_version='HTTP/2', content='body'),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        resp = await client.request('post', _TEST_URL)
        assert resp.status_code == 200
        assert resp.text == 'body'
        assert route.call_count == 1

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        self.check_headers(request.headers, has_auth=False)

    @respx.mock
    @pytest.mark.asyncio
    async def test_request_raise_for_status(self):
        """Test client request raise for status error."""

        client = HttpxAsyncClient()

        responses = [
            respx.MockResponse(404, http_version='HTTP/2', content='Status error'),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            resp = await client.request('post', _TEST_URL)
        resp = exc_info.value.response
        assert resp.status_code == 404
        assert resp.text == 'Status error'
        assert route.call_count == 1

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        self.check_headers(request.headers, has_auth=False)


    @respx.mock
    @pytest.mark.asyncio
    async def test_request_with_base_url(self):
        """Test client request with base_url."""

        client = HttpxAsyncClient(base_url=_TEST_URL)

        url_extension = 'post/123'
        responses = [
            respx.MockResponse(200, http_version='HTTP/2', content='body'),
        ]
        route = respx.request('POST', _TEST_URL + url_extension).mock(side_effect=responses)

        resp = await client.request('POST', url_extension)
        assert resp.status_code == 200
        assert resp.text == 'body'
        assert route.call_count == 1

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL + url_extension
        self.check_headers(request.headers, has_auth=False)

    @respx.mock
    @pytest.mark.asyncio
    async def test_request_with_timeout(self):
        """Test client request with timeout."""

        timeout = 60
        client = HttpxAsyncClient(timeout=timeout)
        responses = [
            respx.MockResponse(200, http_version='HTTP/2', content='body'),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        resp = await client.request('POST', _TEST_URL)
        assert resp.status_code == 200
        assert resp.text == 'body'
        assert route.call_count == 1

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        self.check_headers(request.headers, has_auth=False)

    @respx.mock
    @pytest.mark.asyncio
    async def test_request_with_credential(self):
        """Test client request with credentials."""

        mock_credential = testutils.MockGoogleCredential()
        client = HttpxAsyncClient(credential=mock_credential)

        responses = [
            respx.MockResponse(200, http_version='HTTP/2', content='test'),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        resp = await client.request('post', _TEST_URL)

        assert resp.status_code == 200
        assert resp.text == 'test'
        assert route.call_count == 1

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        self.check_headers(request.headers)

    @respx.mock
    @pytest.mark.asyncio
    async def test_request_with_headers(self):
        """Test client request with credentials."""

        mock_credential = testutils.MockGoogleCredential()
        headers = httpx.Headers({'X-Custom': 'Test'})
        client = HttpxAsyncClient(credential=mock_credential, headers=headers)

        responses = [
            respx.MockResponse(200, http_version='HTTP/2', content='body'),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        resp = await client.request('post', _TEST_URL)
        assert resp.status_code == 200
        assert resp.text == 'body'
        assert route.call_count == 1

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        self.check_headers(request.headers, expected_headers=headers)


    @respx.mock
    @pytest.mark.asyncio
    async def test_response_get_headers(self):
        """Test the headers() helper method."""

        client = HttpxAsyncClient()
        expected_headers = {'X-Custom': 'Test'}

        responses = [
            respx.MockResponse(200, http_version='HTTP/2', headers=expected_headers),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        headers = await client.headers('post', _TEST_URL)

        self.check_headers(
            headers, expected_headers=expected_headers, has_auth=False, has_metrics=False
        )
        assert route.call_count == 1

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        self.check_headers(request.headers, has_auth=False)

    @respx.mock
    @pytest.mark.asyncio
    async def test_response_get_body_and_response(self):
        """Test the body_and_response() helper method."""

        client = HttpxAsyncClient()
        expected_body = {'key': 'value'}

        responses = [
            respx.MockResponse(200, http_version='HTTP/2', json=expected_body),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        body, resp = await client.body_and_response('post', _TEST_URL)

        assert resp.status_code == 200
        assert body == expected_body
        assert route.call_count == 1

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        self.check_headers(request.headers, has_auth=False)


    @respx.mock
    @pytest.mark.asyncio
    async def test_response_get_body(self):
        """Test the body() helper method."""

        client = HttpxAsyncClient()
        expected_body = {'key': 'value'}

        responses = [
            respx.MockResponse(200, http_version='HTTP/2', json=expected_body),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        body = await client.body('post', _TEST_URL)

        assert body == expected_body
        assert route.call_count == 1

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        self.check_headers(request.headers, has_auth=False)

    @respx.mock
    @pytest.mark.asyncio
    async def test_response_get_headers_and_body(self):
        """Test the headers_and_body() helper method."""

        client = HttpxAsyncClient()
        expected_headers = {'X-Custom': 'Test'}
        expected_body = {'key': 'value'}

        responses = [
            respx.MockResponse(
                200, http_version='HTTP/2', json=expected_body, headers=expected_headers),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        headers, body = await client.headers_and_body('post', _TEST_URL)

        assert body == expected_body
        self.check_headers(
            headers, expected_headers=expected_headers, has_auth=False, has_metrics=False
        )
        assert route.call_count == 1

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        self.check_headers(request.headers, has_auth=False)

    @pytest.mark.asyncio
    async def test_aclose(self):
        """Test that aclose calls the underlying client's aclose."""

        client = HttpxAsyncClient()
        assert client._async_client.is_closed is False
        await client.aclose()
        assert client._async_client.is_closed is True


    def check_headers(
            self,
            headers: Union[httpx.Headers, Dict[str, str]],
            expected_headers: Optional[Union[httpx.Headers, Dict[str, str]]] = None,
            has_auth: bool = True,
            has_metrics: bool = True
    ):
        if expected_headers:
            for header_key in expected_headers.keys():
                assert header_key in headers
                assert headers.get(header_key) == expected_headers.get(header_key)

        if has_auth:
            assert 'Authorization' in headers
            assert headers.get('Authorization') == 'Bearer mock-token'

        if has_metrics:
            for header_key in _http_client.METRICS_HEADERS:
                assert header_key in headers
                assert headers.get(header_key) == _http_client.METRICS_HEADERS.get(header_key)


class TestGoogleAuthCredentialFlow:

    @respx.mock
    @pytest.mark.asyncio
    async def test_auth_headers_retry(self):
        """Test invalid credential retry."""

        mock_credential = testutils.MockGoogleCredential()
        client = HttpxAsyncClient(credential=mock_credential)

        responses = [
            respx.MockResponse(401, http_version='HTTP/2', content='Auth error'),
            respx.MockResponse(401, http_version='HTTP/2', content='Auth error'),
            respx.MockResponse(200, http_version='HTTP/2', content='body'),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        resp = await client.request('post', _TEST_URL)
        assert resp.status_code == 200
        assert resp.text == 'body'
        assert route.call_count == 3

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        headers = request.headers
        assert 'Authorization' in headers
        assert headers.get('Authorization') == 'Bearer mock-token'

    @respx.mock
    @pytest.mark.asyncio
    async def test_auth_headers_retry_exhausted(self, mocker: MockerFixture):
        """Test invalid credential retry exhausted."""

        mock_credential = testutils.MockGoogleCredential()
        mock_credential_patch = mocker.spy(mock_credential, 'refresh')
        client = HttpxAsyncClient(credential=mock_credential)

        responses = [
            respx.MockResponse(401, http_version='HTTP/2', content='Auth error'),
            respx.MockResponse(401, http_version='HTTP/2', content='Auth error'),
            respx.MockResponse(401, http_version='HTTP/2', content='Auth error'),
            # Should stop after previous response
            respx.MockResponse(200, http_version='HTTP/2', content='body'),
        ]
        route = respx.request('POST', _TEST_URL).mock(side_effect=responses)

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            resp = await client.request('post', _TEST_URL)
        resp = exc_info.value.response
        assert resp.status_code == 401
        assert resp.text == 'Auth error'
        assert route.call_count == 3

        assert mock_credential_patch.call_count == 3

        request = route.calls.last.request
        assert request.method == 'POST'
        assert request.url == _TEST_URL
        headers = request.headers
        assert 'Authorization' in headers
        assert headers.get('Authorization') == 'Bearer mock-token'
