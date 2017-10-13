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
import requests

from firebase_admin import _http_client
from tests import testutils


_TEST_URL = 'http://firebase.test.url/'


def test_http_client_default_session():
    client = _http_client.HttpClient()
    assert client.session is not None
    assert client.base_url == ''
    recorder = _instrument(client, 'body')
    resp = client.request('get', _TEST_URL)
    assert resp.status_code == 200
    assert resp.text == 'body'
    assert len(recorder) == 1
    assert recorder[0].method == 'GET'
    assert recorder[0].url == _TEST_URL

def test_http_client_custom_session():
    session = requests.Session()
    client = _http_client.HttpClient(session=session)
    assert client.session is session
    assert client.base_url == ''
    recorder = _instrument(client, 'body')
    resp = client.request('get', _TEST_URL)
    assert resp.status_code == 200
    assert resp.text == 'body'
    assert len(recorder) == 1
    assert recorder[0].method == 'GET'
    assert recorder[0].url == _TEST_URL

def test_base_url():
    client = _http_client.HttpClient(base_url=_TEST_URL)
    assert client.session is not None
    assert client.base_url == _TEST_URL
    recorder = _instrument(client, 'body')
    resp = client.request('get', 'foo')
    assert resp.status_code == 200
    assert resp.text == 'body'
    assert len(recorder) == 1
    assert recorder[0].method == 'GET'
    assert recorder[0].url == _TEST_URL + 'foo'

def _instrument(client, payload, status=200):
    recorder = []
    adapter = testutils.MockAdapter(payload, status, recorder)
    client.session.mount(_TEST_URL, adapter)
    return recorder
