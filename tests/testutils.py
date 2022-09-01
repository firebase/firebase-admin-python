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

"""Common utility classes and functions for testing."""
import io
import os

from unittest.mock import MagicMock
import pytest

import aiohttp
from aiohttp import streams
from google.auth import credentials
from google.auth import _credentials_async
from google.auth import transport
from google.auth.transport import _aiohttp_requests as aiohttp_requests
from requests import adapters
from requests import models

import firebase_admin


def resource_filename(filename):
    """Returns the absolute path to a test resource."""
    return os.path.join(os.path.dirname(__file__), 'data', filename)


def resource(filename):
    """Returns the contents of a test resource."""
    with open(resource_filename(filename), 'r', encoding="utf-8") as file_obj:
        return file_obj.read()


def cleanup_apps():
    with firebase_admin._apps_lock:
        apps = list(firebase_admin._apps.values())
        for app in apps:
            firebase_admin.delete_app(app)

def run_without_project_id(func):
    env_vars = ['GCLOUD_PROJECT', 'GOOGLE_CLOUD_PROJECT']
    env_values = []
    for env_var in env_vars:
        gcloud_project = os.environ.get(env_var)
        if gcloud_project:
            del os.environ[env_var]
        env_values.append(gcloud_project)
    try:
        func()
    finally:
        for idx, env_var in enumerate(env_vars):
            gcloud_project = env_values[idx]
            if gcloud_project:
                os.environ[env_var] = gcloud_project


async def run_without_project_id_async(func):
    env_vars = ['GCLOUD_PROJECT', 'GOOGLE_CLOUD_PROJECT']
    env_values = []
    for env_var in env_vars:
        gcloud_project = os.environ.get(env_var)
        if gcloud_project:
            del os.environ[env_var]
        env_values.append(gcloud_project)
    try:
        await func()
    finally:
        for idx, env_var in enumerate(env_vars):
            gcloud_project = env_values[idx]
            if gcloud_project:
                os.environ[env_var] = gcloud_project

def new_monkeypatch():
    return pytest.MonkeyPatch()


class MockResponse(transport.Response):
    def __init__(self, status, response):
        self._status = status
        self._response = response

    @property
    def status(self):
        return self._status

    @property
    def headers(self):
        return {}

    @property
    def data(self):
        return self._response.encode()

class MockRequest(transport.Request):
    """A mock HTTP requests implementation.

    This can be used whenever an HTTP interaction needs to be mocked
    for testing purposes. For example HTTP calls to fetch public key
    certificates, and HTTP calls to retrieve access tokens can be
    mocked using this class.
    """

    def __init__(self, status, response):
        self.response = MockResponse(status, response)
        self.log = []

    def __call__(self, *args, **kwargs): # pylint: disable=arguments-differ
        self.log.append((args, kwargs))
        return self.response


class MockFailedRequest(transport.Request):
    """A mock HTTP request that fails by raising an exception."""

    def __init__(self, error):
        self.error = error
        self.log = []

    def __call__(self, *args, **kwargs): # pylint: disable=arguments-differ
        self.log.append((args, kwargs))
        raise self.error


class MockAsyncResponse(aiohttp_requests._CombinedResponse):
    def __init__(self, status, response):
        super().__init__(response)
        self._status = status
        self._response = response
        self._raw_content = response

    @property
    def status(self):
        return self._status

    @property
    def headers(self):
        return {}

    @property
    def data(self):
        return self._response.encode()

    async def content(self):
        return self._response.encode()

class MockAsyncRequest(aiohttp_requests.Request):
    """A mock async HTTP requests implementation.

    This can be used whenever an async HTTP interaction needs to be mocked
    for testing purposes. For example HTTP calls to fetch public key
    certificates, and HTTP calls to retrieve access tokens can be
    mocked using this class.
    """

    def __init__(self, status, response):
        super().__init__()
        self.response = MockAsyncResponse(status, response)
        self.log = []

    async def __call__(self, *args, **kwargs): # pylint: disable=arguments-differ
        self.log.append((args, kwargs))
        return self.response


class MockFailedAsyncRequest(aiohttp_requests.Request):
    """A mock HTTP request that fails by raising an exception."""

    def __init__(self, error):
        super().__init__()
        self.error = error
        self.log = []

    async def __call__(self, *args, **kwargs): # pylint: disable=arguments-differ
        self.log.append((args, kwargs))
        raise self.error

# Temporarily disable the lint rule. For more information see:
# https://github.com/googleapis/google-auth-library-python/pull/561
# pylint: disable=abstract-method
class MockGoogleCredential(credentials.Credentials):
    """A mock Google authentication credential."""
    def refresh(self, request):
        self.token = 'mock-token'

class MockGoogleCredentialAsync(_credentials_async.Credentials):
    """A mock Google authentication async credential."""
    async def refresh(self, request):  # pylint: disable=invalid-overridden-method
        self.token = 'mock-token'


class MockCredential(firebase_admin.credentials.Base):
    """A mock Firebase credential implementation."""

    def __init__(self):
        self._g_credential = MockGoogleCredential()

    def get_credential(self):
        return self._g_credential

class MockCredentialAsync(firebase_admin.credentials.Base):
    """A mock Firebase async credential implementation."""

    def __init__(self):
        self._g_credential_async = MockGoogleCredentialAsync()

    def get_credential_async(self):
        return self._g_credential_async

class MockMultiRequestAdapter(adapters.HTTPAdapter):
    """A mock HTTP adapter that supports multiple responses for the Python requests module."""
    def __init__(self, responses, statuses, recorder):
        """Constructs a MockMultiRequestAdapter.

        The lengths of the responses and statuses parameters must match.

        Each incoming request consumes a response and a status, in order. If all responses and
        statuses are exhausted, further requests will reuse the last response and status.
        """
        adapters.HTTPAdapter.__init__(self)
        if len(responses) != len(statuses):
            raise ValueError('The lengths of responses and statuses do not match.')
        self._current_response = 0
        self._responses = list(responses)  # Make a copy.
        self._statuses = list(statuses)
        self._recorder = recorder

    def send(self, request, **kwargs): # pylint: disable=arguments-differ
        request._extra_kwargs = kwargs
        self._recorder.append(request)
        resp = models.Response()
        resp.url = request.url
        resp.status_code = self._statuses[self._current_response]
        resp.raw = io.BytesIO(self._responses[self._current_response].encode())
        self._current_response = min(self._current_response + 1, len(self._responses) - 1)
        return resp


class MockAdapter(MockMultiRequestAdapter):
    """A mock HTTP adapter for the Python requests module."""
    def __init__(self, data, status, recorder):
        super().__init__([data], [status], recorder)

    @property
    def status(self):
        return self._statuses[0]

    @property
    def data(self):
        return self._responses[0]

class MockClientResponse(aiohttp.ClientResponse):
    def __init__(self, method, url, payload, status, recorder): # pylint: disable=super-init-not-called
        self._cache = {}
        self._url = url

        mock_reader = AsyncMock(spec=streams.StreamReader)
        mock_reader.read.return_value = str.encode(payload)
        self.content = mock_reader
        self.status = status
        self.recorder = recorder
        self._headers = []

class MockSession(aiohttp.ClientSession):
    def __init__(self, payload, status, recorder, credentials=None):
        super().__init__(credentials)
        self.payload = payload
        self.status = status
        self.recorder = recorder
        self.current_response = 0

    async def _request(self, method, url, *args, **kwargs): # pylint: disable=arguments-differ
        self.method = method
        self.url = url
        self.args = args
        self.extra_kwargs = kwargs
        self.recorder.append(self)
        self.current_response += 1
        return MockClientResponse(method, url, self.payload, self.status, self.recorder)

class MockClientSession(MockSession):
    def __init__(self, payload, status, recorder):
        super().__init__(payload, status, recorder)

class MockAuthorizedSession(MockClientSession, aiohttp_requests.AuthorizedSession):
    def __init__(self, payload, status, recorder, credentials):
        super().__init__(payload, status, recorder)
        self.credentials = credentials

# Custom async mock class since unittest.mock.AsyncMock is only avaible in python 3.8+
class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):  # pylint: disable=invalid-overridden-method
        return super().__call__(*args, **kwargs)
