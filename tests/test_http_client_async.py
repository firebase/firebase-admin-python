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
from __future__ import absolute_import
import aiohttp

import pytest
from pytest_localserver import http
from google.auth.transport import requests

from firebase_admin import _http_client_async
from tests import testutils


_TEST_URL = 'http://firebase.test.url/'

@pytest.mark.asyncio
async def test_http_client_default_session():
    client = _http_client_async.HttpClientAsync()
    assert client.session is not None
    assert isinstance(client.session, aiohttp.ClientSession)
    assert client.base_url == ''
    await client.close()

@pytest.mark.asyncio
async def test_http_client_custom_session():
    session, recorder = make_mock_client_session()
    client = _http_client_async.HttpClientAsync(session=session)
    assert client.session is session
    assert client.base_url == ''
    resp = await client.request('GET', _TEST_URL)
    assert resp.status_code == 200
    assert resp.text == 'body'
    print(recorder)
    assert len(recorder) == 1
    # assert recorder[0]
    assert recorder[0].method == 'GET'
    assert recorder[0].url == _TEST_URL
    await client.close()

@pytest.mark.asyncio
async def test_base_url():
    session, recorder = make_mock_client_session()
    client = _http_client_async.HttpClientAsync(base_url=_TEST_URL, session=session)
    assert client.session is not None
    assert client.base_url == _TEST_URL
    resp = await client.request('GET', 'foo')
    assert resp.status_code == 200
    assert resp.text == 'body'
    assert len(recorder) == 1
    assert recorder[0].method == 'GET'
    assert recorder[0].url == _TEST_URL + 'foo'
    await client.close()

@pytest.mark.asyncio
async def test_credential_async():
    credential = testutils.MockGoogleCredentialAsync()
    client = _http_client_async.HttpClientAsync(
        credential=credential)
    assert client.session is not None
    session, recorder = make_mock_authorized_session(credential)
    client._session = session
    resp = await client.request('GET', _TEST_URL)
    assert resp.status_code == 200
    assert resp.text == 'body'
    assert len(recorder) == 1
    print(recorder[0].extra_kwargs)
    assert recorder[0].method == 'GET'
    assert recorder[0].url == _TEST_URL
    assert recorder[0].extra_kwargs['headers']['authorization'] == 'Bearer mock-token'
    await client.close()

@pytest.mark.asyncio
@pytest.mark.parametrize('options, timeout', [
    ({}, _http_client_async.DEFAULT_TIMEOUT_SECONDS),
    ({'timeout': 7}, 7),
    ({'timeout': 0}, 0),
    ({'timeout': None}, None),
])
async def test_timeout(options, timeout):
    session, recorder = make_mock_client_session()
    client = _http_client_async.HttpClientAsync(**options, session=session)
    assert client.timeout == timeout
    await client.request('get', _TEST_URL)
    assert len(recorder) == 1
    if timeout is None:
        assert recorder[0].extra_kwargs['timeout'] is None
    else:
        assert recorder[0].extra_kwargs['timeout'] == pytest.approx(timeout, 0.001)
    await client.close()

def make_mock_client_session(payload='body', status=200):
    recorder = []
    session = testutils.MockClientSession(payload, status, recorder)
    client = _http_client_async.HttpClientAsync(session=session)
    return session, recorder

def make_mock_authorized_session(credentials, payload='body', status=200):
    recorder = []
    session = testutils.MockAuthorizedSession(payload, status, recorder, credentials)
    client = _http_client_async.HttpClientAsync(session=session)
    return session, recorder


class TestHttpRetry:
    """Unit tests for the default HTTP retry configuration."""

    ENTITY_ENCLOSING_METHODS = ['post', 'put', 'patch']
    ALL_METHODS = ENTITY_ENCLOSING_METHODS + ['get', 'delete', 'head', 'options']

    @classmethod
    def setup_class(cls):
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

    @pytest.mark.asyncio
    @pytest.mark.parametrize('method', ALL_METHODS)
    async def test_retry_on_503(self, method):
        self.httpserver.serve_content({}, 503)
        client = _http_client_async.JsonHttpClientAsync(
            credential=testutils.MockGoogleCredentialAsync(), base_url=self.httpserver.url)
        body = None
        if method in self.ENTITY_ENCLOSING_METHODS:
            body = {'key': 'value'}
        with pytest.raises(aiohttp.ClientError) as excinfo:
            await client.request(method, '/', json=body)
        assert excinfo.value.status == 503
        assert len(self.httpserver.requests) == 5
        await client.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize('method', ALL_METHODS)
    async def test_retry_on_500(self, method):
        self.httpserver.serve_content({}, 500)
        client = _http_client_async.JsonHttpClientAsync(
            credential=testutils.MockGoogleCredentialAsync(), base_url=self.httpserver.url)
        body = None
        if method in self.ENTITY_ENCLOSING_METHODS:
            body = {'key': 'value'}
        with pytest.raises(aiohttp.ClientError) as excinfo:
            await client.request(method, '/', json=body)
        assert excinfo.value.status == 500
        assert len(self.httpserver.requests) == 5
        await client.close()

    @pytest.mark.asyncio
    async def test_no_retry_on_404(self):
        self.httpserver.serve_content({}, 404)
        client = _http_client_async.JsonHttpClientAsync(
            credential=testutils.MockGoogleCredentialAsync(), base_url=self.httpserver.url)
        with pytest.raises(aiohttp.ClientError) as excinfo:
            await client.request('get', '/')
        await client.close()
        assert excinfo.value.status == 404
        assert len(self.httpserver.requests) == 1
