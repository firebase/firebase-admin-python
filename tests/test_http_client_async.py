# Copyright 2022 Google Inc.
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

"""Tests for firebase_admin._http_client_async."""
from __future__ import absolute_import
import asyncio

import aiohttp
import pytest
from pytest_localserver import http

from firebase_admin import _http_client_async
from tests import testutils


_TEST_URL = 'http://firebase.test.url/'

def make_mock_client_session(payload='body', status=200):
    recorder = []
    session = testutils.MockClientSession(payload, status, recorder)
    return session, recorder

def make_mock_authorized_session(credentials, payload='body', status=200):
    recorder = []
    session = testutils.MockAuthorizedSession(payload, status, recorder, credentials)
    return session, recorder

class TestHttpClient:
    def seutp_method(self):
        self.client = None

    def teardown_method(self):
        if self.client is not None:
            asyncio.get_event_loop().run_until_complete(self.client.close())

    @pytest.mark.asyncio
    async def test_http_client_default_session(self):
        self.client = _http_client_async.HttpClientAsync()
        assert self.client.session is not None
        assert isinstance(self.client.session, aiohttp.ClientSession)
        assert self.client.base_url == ''

    @pytest.mark.asyncio
    async def test_http_client_custom_session(self):
        session, recorder = make_mock_client_session()
        self.client = _http_client_async.HttpClientAsync(session=session)
        assert self.client.session is session
        assert self.client.base_url == ''
        resp = await self.client.request('GET', _TEST_URL)
        assert resp.status == 200
        content = await resp.content()
        assert content.decode() == 'body'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == _TEST_URL

    @pytest.mark.asyncio
    async def test_base_url(self):
        session, recorder = make_mock_client_session()
        self.client = _http_client_async.HttpClientAsync(base_url=_TEST_URL, session=session)
        assert self.client.session is not None
        assert self.client.base_url == _TEST_URL
        resp = await self.client.request('GET', 'foo')
        assert resp.status == 200
        content = await resp.content()
        assert content.decode() == 'body'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == _TEST_URL + 'foo'

    @pytest.mark.asyncio
    async def test_credential_async(self):
        credential = testutils.MockGoogleCredentialAsync()
        self.client = _http_client_async.HttpClientAsync(
            credential=credential)
        assert self.client.session is not None
        session, recorder = make_mock_authorized_session(credential)
        self.client._session = session
        resp = await self.client.request('GET', _TEST_URL)
        assert resp.status == 200
        content = await resp.content()
        assert content.decode() == 'body'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == _TEST_URL
        assert recorder[0].extra_kwargs['headers']['authorization'] == 'Bearer mock-token'

    @pytest.mark.asyncio
    @pytest.mark.parametrize('options, timeout', [
        ({}, _http_client_async.DEFAULT_TIMEOUT_SECONDS),
        ({'timeout': 7}, 7),
        ({'timeout': 0}, 0),
        ({'timeout': None}, None),
    ])
    async def test_timeout(self, options, timeout):
        session, recorder = make_mock_client_session()
        self.client = _http_client_async.HttpClientAsync(**options, session=session)
        assert self.client.timeout == timeout
        await self.client.request('get', _TEST_URL)
        assert len(recorder) == 1
        if timeout is None:
            assert recorder[0].extra_kwargs['timeout'] is None
        else:
            assert recorder[0].extra_kwargs['timeout'] == pytest.approx(timeout, 0.001)


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
        self.client = None
        # Clean up any state in the server before starting a new test case.
        self.httpserver.requests = []

    def teardown_method(self):
        if self.client is not None:
            asyncio.get_event_loop().run_until_complete(self.client.close())

    @pytest.mark.asyncio
    @pytest.mark.parametrize('method', ALL_METHODS)
    async def test_retry_on_503(self, method):
        self.httpserver.serve_content({}, 503)
        self.client = _http_client_async.JsonHttpClientAsync(
            credential=testutils.MockGoogleCredentialAsync(), base_url=self.httpserver.url)
        body = None
        if method in self.ENTITY_ENCLOSING_METHODS:
            body = {'key': 'value'}
        with pytest.raises(aiohttp.ClientError) as excinfo:
            await self.client.request(method, '/', json=body)
        assert excinfo.value.response.status == 503
        assert len(self.httpserver.requests) == 5

    @pytest.mark.asyncio
    @pytest.mark.parametrize('method', ALL_METHODS)
    async def test_retry_on_500(self, method):
        self.httpserver.serve_content({}, 500)
        self.client = _http_client_async.JsonHttpClientAsync(
            credential=testutils.MockGoogleCredentialAsync(), base_url=self.httpserver.url)
        body = None
        if method in self.ENTITY_ENCLOSING_METHODS:
            body = {'key': 'value'}
        with pytest.raises(aiohttp.ClientError) as excinfo:
            await self.client.request(method, '/', json=body)
        assert excinfo.value.response.status == 500
        assert len(self.httpserver.requests) == 5

    @pytest.mark.asyncio
    async def test_no_retry_on_404(self):
        self.httpserver.serve_content({}, 404)
        self.client = _http_client_async.JsonHttpClientAsync(
            credential=testutils.MockGoogleCredentialAsync(), base_url=self.httpserver.url)
        with pytest.raises(aiohttp.ClientError) as excinfo:
            await self.client.request('get', '/')
        assert excinfo.value.response.status == 404
        assert len(self.httpserver.requests) == 1
