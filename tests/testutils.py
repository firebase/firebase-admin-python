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
import os

from google.auth import credentials
from google.auth import transport
from requests import adapters
from requests import models
import six

import firebase_admin


def resource_filename(filename):
    """Returns the absolute path to a test resource."""
    return os.path.join(os.path.dirname(__file__), 'data', filename)


def resource(filename):
    """Returns the contents of a test resource."""
    with open(resource_filename(filename), 'r') as file_obj:
        return file_obj.read()


def cleanup_apps():
    with firebase_admin._apps_lock:
        apps = list(firebase_admin._apps.values())
        for app in apps:
            firebase_admin.delete_app(app)


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

    def __call__(self, *args, **kwargs):
        return self.response


class MockGoogleCredential(credentials.Credentials):
    """A mock Google authentication credential."""
    def refresh(self, request):
        self.token = 'mock-token'


class MockCredential(firebase_admin.credentials.Base):
    """A mock Firebase credential implementation."""

    def __init__(self):
        self._g_credential = MockGoogleCredential()

    def get_credential(self):
        return self._g_credential


class MockAdapter(adapters.HTTPAdapter):
    """A mock HTTP adapter for the Python requests module."""
    def __init__(self, data, status, recorder):
        adapters.HTTPAdapter.__init__(self)
        self._data = data
        self._status = status
        self._recorder = recorder

    def send(self, request, **kwargs):
        del kwargs
        self._recorder.append(request)
        resp = models.Response()
        resp.url = request.url
        resp.status_code = self._status
        resp.raw = six.BytesIO(self._data.encode())
        return resp
