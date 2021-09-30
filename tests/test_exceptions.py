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

import io
import json
import socket

import httplib2
import pytest
import requests
from requests import models

from googleapiclient import errors
from firebase_admin import exceptions
from firebase_admin import _utils
from firebase_admin import _gapic_utils


_NOT_FOUND_ERROR_DICT = {
    'status': 'NOT_FOUND',
    'message': 'test error'
}


_NOT_FOUND_PAYLOAD = json.dumps({
    'error': _NOT_FOUND_ERROR_DICT,
})


class TestRequests:

    def test_timeout_error(self):
        error = requests.exceptions.Timeout('Test error')
        firebase_error = _utils.handle_requests_error(error)
        assert isinstance(firebase_error, exceptions.DeadlineExceededError)
        assert str(firebase_error) == 'Timed out while making an API call: Test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is None

    def test_requests_connection_error(self):
        error = requests.exceptions.ConnectionError('Test error')
        firebase_error = _utils.handle_requests_error(error)
        assert isinstance(firebase_error, exceptions.UnavailableError)
        assert str(firebase_error) == 'Failed to establish a connection: Test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is None

    def test_unknown_transport_error(self):
        error = requests.exceptions.RequestException('Test error')
        firebase_error = _utils.handle_requests_error(error)
        assert isinstance(firebase_error, exceptions.UnknownError)
        assert str(firebase_error) == 'Unknown error while making a remote service call: Test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is None

    def test_http_response(self):
        resp, error = self._create_response()
        firebase_error = _utils.handle_requests_error(error)
        assert isinstance(firebase_error, exceptions.InternalError)
        assert str(firebase_error) == 'Test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is resp

    def test_http_response_with_unknown_status(self):
        resp, error = self._create_response(status=501)
        firebase_error = _utils.handle_requests_error(error)
        assert isinstance(firebase_error, exceptions.UnknownError)
        assert str(firebase_error) == 'Test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is resp

    def test_http_response_with_message(self):
        resp, error = self._create_response()
        firebase_error = _utils.handle_requests_error(error, message='Explicit error message')
        assert isinstance(firebase_error, exceptions.InternalError)
        assert str(firebase_error) == 'Explicit error message'
        assert firebase_error.cause is error
        assert firebase_error.http_response is resp

    def test_http_response_with_code(self):
        resp, error = self._create_response()
        firebase_error = _utils.handle_requests_error(error, code=exceptions.UNAVAILABLE)
        assert isinstance(firebase_error, exceptions.UnavailableError)
        assert str(firebase_error) == 'Test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is resp

    def test_http_response_with_message_and_code(self):
        resp, error = self._create_response()
        firebase_error = _utils.handle_requests_error(
            error, message='Explicit error message', code=exceptions.UNAVAILABLE)
        assert isinstance(firebase_error, exceptions.UnavailableError)
        assert str(firebase_error) == 'Explicit error message'
        assert firebase_error.cause is error
        assert firebase_error.http_response is resp

    def test_handle_platform_error(self):
        resp, error = self._create_response(payload=_NOT_FOUND_PAYLOAD)
        firebase_error = _utils.handle_platform_error_from_requests(error)
        assert isinstance(firebase_error, exceptions.NotFoundError)
        assert str(firebase_error) == 'test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is resp

    def test_handle_platform_error_with_no_response(self):
        error = requests.exceptions.RequestException('Test error')
        firebase_error = _utils.handle_platform_error_from_requests(error)
        assert isinstance(firebase_error, exceptions.UnknownError)
        assert str(firebase_error) == 'Unknown error while making a remote service call: Test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is None

    def test_handle_platform_error_with_no_error_code(self):
        resp, error = self._create_response(payload='no error code')
        firebase_error = _utils.handle_platform_error_from_requests(error)
        assert isinstance(firebase_error, exceptions.InternalError)
        message = 'Unexpected HTTP response with status: 500; body: no error code'
        assert str(firebase_error) == message
        assert firebase_error.cause is error
        assert firebase_error.http_response is resp

    def test_handle_platform_error_with_custom_handler(self):
        resp, error = self._create_response(payload=_NOT_FOUND_PAYLOAD)
        invocations = []

        def _custom_handler(cause, message, error_dict):
            invocations.append((cause, message, error_dict))
            return exceptions.InvalidArgumentError('Custom message', cause, cause.response)

        firebase_error = _utils.handle_platform_error_from_requests(error, _custom_handler)

        assert isinstance(firebase_error, exceptions.InvalidArgumentError)
        assert str(firebase_error) == 'Custom message'
        assert firebase_error.cause is error
        assert firebase_error.http_response is resp
        assert len(invocations) == 1
        args = invocations[0]
        assert len(args) == 3
        assert args[0] is error
        assert args[1] == 'test error'
        assert args[2] == _NOT_FOUND_ERROR_DICT

    def test_handle_platform_error_with_custom_handler_ignore(self):
        resp, error = self._create_response(payload=_NOT_FOUND_PAYLOAD)
        invocations = []

        def _custom_handler(cause, message, error_dict):
            invocations.append((cause, message, error_dict))

        firebase_error = _utils.handle_platform_error_from_requests(error, _custom_handler)

        assert isinstance(firebase_error, exceptions.NotFoundError)
        assert str(firebase_error) == 'test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is resp
        assert len(invocations) == 1
        args = invocations[0]
        assert len(args) == 3
        assert args[0] is error
        assert args[1] == 'test error'
        assert args[2] == _NOT_FOUND_ERROR_DICT

    def _create_response(self, status=500, payload=None):
        resp = models.Response()
        resp.status_code = status
        if payload:
            resp.raw = io.BytesIO(payload.encode())
        exc = requests.exceptions.RequestException('Test error', response=resp)
        return resp, exc


class TestGoogleApiClient:

    @pytest.mark.parametrize('error', [
        socket.timeout('Test error'),
        socket.error('Read timed out')
    ])
    def test_googleapicleint_timeout_error(self, error):
        firebase_error = _gapic_utils.handle_googleapiclient_error(error)
        assert isinstance(firebase_error, exceptions.DeadlineExceededError)
        assert str(firebase_error) == 'Timed out while making an API call: {0}'.format(error)
        assert firebase_error.cause is error
        assert firebase_error.http_response is None

    def test_googleapiclient_connection_error(self):
        error = httplib2.ServerNotFoundError('Test error')
        firebase_error = _gapic_utils.handle_googleapiclient_error(error)
        assert isinstance(firebase_error, exceptions.UnavailableError)
        assert str(firebase_error) == 'Failed to establish a connection: Test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is None

    def test_unknown_transport_error(self):
        error = socket.error('Test error')
        firebase_error = _gapic_utils.handle_googleapiclient_error(error)
        assert isinstance(firebase_error, exceptions.UnknownError)
        assert str(firebase_error) == 'Unknown error while making a remote service call: Test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is None

    def test_http_response(self):
        error = self._create_http_error()
        firebase_error = _gapic_utils.handle_googleapiclient_error(error)
        assert isinstance(firebase_error, exceptions.InternalError)
        assert str(firebase_error) == str(error)
        assert firebase_error.cause is error
        assert firebase_error.http_response.status_code == 500
        assert firebase_error.http_response.content.decode() == 'Body'

    def test_http_response_with_unknown_status(self):
        error = self._create_http_error(status=501)
        firebase_error = _gapic_utils.handle_googleapiclient_error(error)
        assert isinstance(firebase_error, exceptions.UnknownError)
        assert str(firebase_error) == str(error)
        assert firebase_error.cause is error
        assert firebase_error.http_response.status_code == 501
        assert firebase_error.http_response.content.decode() == 'Body'

    def test_http_response_with_message(self):
        error = self._create_http_error()
        firebase_error = _gapic_utils.handle_googleapiclient_error(
            error, message='Explicit error message')
        assert isinstance(firebase_error, exceptions.InternalError)
        assert str(firebase_error) == 'Explicit error message'
        assert firebase_error.cause is error
        assert firebase_error.http_response.status_code == 500
        assert firebase_error.http_response.content.decode() == 'Body'

    def test_http_response_with_code(self):
        error = self._create_http_error()
        firebase_error = _gapic_utils.handle_googleapiclient_error(
            error, code=exceptions.UNAVAILABLE)
        assert isinstance(firebase_error, exceptions.UnavailableError)
        assert str(firebase_error) == str(error)
        assert firebase_error.cause is error
        assert firebase_error.http_response.status_code == 500
        assert firebase_error.http_response.content.decode() == 'Body'

    def test_http_response_with_message_and_code(self):
        error = self._create_http_error()
        firebase_error = _gapic_utils.handle_googleapiclient_error(
            error, message='Explicit error message', code=exceptions.UNAVAILABLE)
        assert isinstance(firebase_error, exceptions.UnavailableError)
        assert str(firebase_error) == 'Explicit error message'
        assert firebase_error.cause is error
        assert firebase_error.http_response.status_code == 500
        assert firebase_error.http_response.content.decode() == 'Body'

    def test_handle_platform_error(self):
        error = self._create_http_error(payload=_NOT_FOUND_PAYLOAD)
        firebase_error = _gapic_utils.handle_platform_error_from_googleapiclient(error)
        assert isinstance(firebase_error, exceptions.NotFoundError)
        assert str(firebase_error) == 'test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response.status_code == 500
        assert firebase_error.http_response.content.decode() == _NOT_FOUND_PAYLOAD

    def test_handle_platform_error_with_no_response(self):
        error = socket.error('Test error')
        firebase_error = _gapic_utils.handle_platform_error_from_googleapiclient(error)
        assert isinstance(firebase_error, exceptions.UnknownError)
        assert str(firebase_error) == 'Unknown error while making a remote service call: Test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response is None

    def test_handle_platform_error_with_no_error_code(self):
        error = self._create_http_error(payload='no error code')
        firebase_error = _gapic_utils.handle_platform_error_from_googleapiclient(error)
        assert isinstance(firebase_error, exceptions.InternalError)
        message = 'Unexpected HTTP response with status: 500; body: no error code'
        assert str(firebase_error) == message
        assert firebase_error.cause is error
        assert firebase_error.http_response.status_code == 500
        assert firebase_error.http_response.content.decode() == 'no error code'

    def test_handle_platform_error_with_custom_handler(self):
        error = self._create_http_error(payload=_NOT_FOUND_PAYLOAD)
        invocations = []

        def _custom_handler(cause, message, error_dict, http_response):
            invocations.append((cause, message, error_dict, http_response))
            return exceptions.InvalidArgumentError('Custom message', cause, http_response)

        firebase_error = _gapic_utils.handle_platform_error_from_googleapiclient(
            error, _custom_handler)

        assert isinstance(firebase_error, exceptions.InvalidArgumentError)
        assert str(firebase_error) == 'Custom message'
        assert firebase_error.cause is error
        assert firebase_error.http_response.status_code == 500
        assert firebase_error.http_response.content.decode() == _NOT_FOUND_PAYLOAD
        assert len(invocations) == 1
        args = invocations[0]
        assert len(args) == 4
        assert args[0] is error
        assert args[1] == 'test error'
        assert args[2] == _NOT_FOUND_ERROR_DICT
        assert args[3] is not None

    def test_handle_platform_error_with_custom_handler_ignore(self):
        error = self._create_http_error(payload=_NOT_FOUND_PAYLOAD)
        invocations = []

        def _custom_handler(cause, message, error_dict, http_response):
            invocations.append((cause, message, error_dict, http_response))

        firebase_error = _gapic_utils.handle_platform_error_from_googleapiclient(
            error, _custom_handler)

        assert isinstance(firebase_error, exceptions.NotFoundError)
        assert str(firebase_error) == 'test error'
        assert firebase_error.cause is error
        assert firebase_error.http_response.status_code == 500
        assert firebase_error.http_response.content.decode() == _NOT_FOUND_PAYLOAD
        assert len(invocations) == 1
        args = invocations[0]
        assert len(args) == 4
        assert args[0] is error
        assert args[1] == 'test error'
        assert args[2] == _NOT_FOUND_ERROR_DICT
        assert args[3] is not None

    def _create_http_error(self, status=500, payload='Body'):
        resp = httplib2.Response({'status': status})
        return errors.HttpError(resp, payload.encode())
