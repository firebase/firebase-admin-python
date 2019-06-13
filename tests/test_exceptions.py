# Copyright 2019 Google Inc.
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


import requests
from requests import models

from firebase_admin import exceptions
from firebase_admin import _utils


def test_timeout_error():
    error = requests.exceptions.Timeout('Test error')
    firebase_error = _utils.handle_requests_error(error)
    assert isinstance(firebase_error, exceptions.DeadlineExceededError)
    assert str(firebase_error) == 'Timed out while making an API call: Test error'
    assert firebase_error.cause is error
    assert firebase_error.http_response is None

def test_connection_error():
    error = requests.exceptions.ConnectionError('Test error')
    firebase_error = _utils.handle_requests_error(error)
    assert isinstance(firebase_error, exceptions.UnavailableError)
    assert str(firebase_error) == 'Failed to establish a connection: Test error'
    assert firebase_error.cause is error
    assert firebase_error.http_response is None

def test_unknown_transport_error():
    error = requests.exceptions.RequestException('Test error')
    firebase_error = _utils.handle_requests_error(error)
    assert isinstance(firebase_error, exceptions.UnknownError)
    assert str(firebase_error) == 'Unknown error while making a remote service call: Test error'
    assert firebase_error.cause is error
    assert firebase_error.http_response is None

def test_http_response():
    resp = models.Response()
    resp.status_code = 500
    error = requests.exceptions.RequestException('Test error', response=resp)
    firebase_error = _utils.handle_requests_error(error)
    assert isinstance(firebase_error, exceptions.InternalError)
    assert str(firebase_error) == 'Test error'
    assert firebase_error.cause is error
    assert firebase_error.http_response is resp

def test_http_response_with_unknown_status():
    resp = models.Response()
    resp.status_code = 501
    error = requests.exceptions.RequestException('Test error', response=resp)
    firebase_error = _utils.handle_requests_error(error)
    assert isinstance(firebase_error, exceptions.UnknownError)
    assert str(firebase_error) == 'Test error'
    assert firebase_error.cause is error
    assert firebase_error.http_response is resp

def test_http_response_with_message():
    resp = models.Response()
    resp.status_code = 500
    error = requests.exceptions.RequestException('Test error', response=resp)
    firebase_error = _utils.handle_requests_error(error, message='Explicit error message')
    assert isinstance(firebase_error, exceptions.InternalError)
    assert str(firebase_error) == 'Explicit error message'
    assert firebase_error.cause is error
    assert firebase_error.http_response is resp

def test_http_response_with_status():
    resp = models.Response()
    resp.status_code = 500
    error = requests.exceptions.RequestException('Test error', response=resp)
    firebase_error = _utils.handle_requests_error(error, code=503)
    assert isinstance(firebase_error, exceptions.UnavailableError)
    assert str(firebase_error) == 'Test error'
    assert firebase_error.cause is error
    assert firebase_error.http_response is resp

def test_http_response_with_message_and_status():
    resp = models.Response()
    resp.status_code = 500
    error = requests.exceptions.RequestException('Test error', response=resp)
    firebase_error = _utils.handle_requests_error(
        error, message='Explicit error message', code=503)
    assert isinstance(firebase_error, exceptions.UnavailableError)
    assert str(firebase_error) == 'Explicit error message'
    assert firebase_error.cause is error
    assert firebase_error.http_response is resp
