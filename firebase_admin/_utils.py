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

"""Internal utilities common to all modules."""

import json
import socket

import googleapiclient
import httplib2
import requests
import six

import firebase_admin
from firebase_admin import exceptions


_ERROR_CODE_TO_EXCEPTION_TYPE = {
    400: exceptions.InvalidArgumentError,
    401: exceptions.UnauthenticatedError,
    403: exceptions.PermissionDeniedError,
    404: exceptions.NotFoundError,
    409: exceptions.ConflictError,
    429: exceptions.ResourceExhaustedError,
    500: exceptions.InternalError,
    503: exceptions.UnavailableError,

    exceptions.INVALID_ARGUMENT: exceptions.InvalidArgumentError,
    exceptions.FAILED_PRECONDITION: exceptions.FailedPreconditionError,
    exceptions.OUT_OF_RANGE: exceptions.OutOfRangeError,
    exceptions.UNAUTHENTICATED: exceptions.UnauthenticatedError,
    exceptions.PERMISSION_DENIED: exceptions.PermissionDeniedError,
    exceptions.NOT_FOUND: exceptions.NotFoundError,
    exceptions.ABORTED: exceptions.AbortedError,
    exceptions.ALREADY_EXISTS: exceptions.AlreadyExistsError,
    exceptions.RESOURCE_EXHAUSTED: exceptions.ResourceExhaustedError,
    exceptions.CANCELLED: exceptions.CancelledError,
    exceptions.DATA_LOSS: exceptions.DataLossError,
    exceptions.UNKNOWN: exceptions.UnknownError,
    exceptions.INTERNAL: exceptions.InternalError,
    exceptions.UNAVAILABLE: exceptions.UnavailableError,
    exceptions.DEADLINE_EXCEEDED: exceptions.DeadlineExceededError,
}


_HTTP_STATUS_TO_ERROR_CODE = {
    400: exceptions.INVALID_ARGUMENT,
    401: exceptions.UNAUTHENTICATED,
    403: exceptions.PERMISSION_DENIED,
    404: exceptions.NOT_FOUND,
    409: exceptions.CONFLICT,
    429: exceptions.RESOURCE_EXHAUSTED,
    500: exceptions.INTERNAL,
    503: exceptions.UNAVAILABLE,
}


def _get_initialized_app(app):
    if app is None:
        return firebase_admin.get_app()
    elif isinstance(app, firebase_admin.App):
        initialized_app = firebase_admin.get_app(app.name)
        if app is not initialized_app:
            raise ValueError('Illegal app argument. App instance not '
                             'initialized via the firebase module.')
        return app
    else:
        raise ValueError('Illegal app argument. Argument must be of type '
                         ' firebase_admin.App, but given "{0}".'.format(type(app)))


def get_app_service(app, name, initializer):
    app = _get_initialized_app(app)
    return app._get_service(name, initializer) # pylint: disable=protected-access


def handle_platform_error_from_requests(error, handle_func=None):
    """Constructs a ``FirebaseError`` from the given requests error.

    This can be used to handle errors returned by Google Cloud Platform (GCP) APIs.

    Args:
        error: An error raised by the reqests module while making an HTTP call to a GCP API.
        handle_func: A function that can be used to handle platform errors in a custom way. When
            specified, this function will be called with four arguments -- parsed error response,
            error message, source exception from requests and the HTTP response object.

    Returns:
        FirebaseError: A ``FirebaseError`` that can be raised to the user code.
    """
    if error.response is None:
        return handle_requests_error(error)

    response = error.response
    content = response.content.decode()
    status_code = response.status_code
    error_dict, code, message = _parse_platform_error(content, status_code)
    exc = None
    if handle_func:
        exc = handle_func(error_dict, message, error, error.response)

    return exc if exc else handle_requests_error(error, message, code)


def handle_requests_error(error, message=None, code=None):
    """Constructs a ``FirebaseError`` from the given requests error.

    Args:
        error: An error raised by the reqests module while making an HTTP call.
        message: A message to be included in the resulting ``FirebaseError`` (optional). If not
            specified the string representation of the ``error`` argument is used as the message.
        code: An HTTP status code or GCP error code that will be used to determine the resulting
            error type (optional). If not specified the HTTP status code on the error response is
            used.

    Returns:
        FirebaseError: A ``FirebaseError`` that can be raised to the user code.
    """
    if isinstance(error, requests.exceptions.Timeout):
        return exceptions.DeadlineExceededError(
            message='Timed out while making an API call: {0}'.format(error),
            cause=error)
    elif isinstance(error, requests.exceptions.ConnectionError):
        return exceptions.UnavailableError(
            message='Failed to establish a connection: {0}'.format(error),
            cause=error)
    elif error.response is None:
        return exceptions.UnknownError(
            message='Unknown error while making a remote service call: {0}'.format(error),
            cause=error)

    if not code:
        code = error.response.status_code
    if not message:
        message = str(error)

    err_type = _lookup_error_type(code)
    return err_type(message=message, cause=error, http_response=error.response)


def handle_platform_error_from_googleapiclient(error, handle_func=None):
    """Constructs a ``FirebaseError`` from the given googleapiclient error.

    This can be used to handle errors returned by Google Cloud Platform (GCP) APIs.

    Args:
        error: An error raised by the googleapiclient while making an HTTP call to a GCP API.
        handle_func: A function that can be used to handle platform errors in a custom way. When
            specified, this function will be called with four arguments -- parsed error response,
            error message, source exception from googleapiclient and a HTTP response object.

    Returns:
        FirebaseError: A ``FirebaseError`` that can be raised to the user code.
    """
    if not isinstance(error, googleapiclient.errors.HttpError):
        return handle_googleapiclient_error(error)

    content = error.content.decode()
    status_code = error.resp.status
    error_dict, code, message = _parse_platform_error(content, status_code)
    exc = None
    if handle_func:
        http_response = _http_response_from_googleapiclient_error(error)
        exc = handle_func(error_dict, message, error, http_response)

    return exc if exc else handle_googleapiclient_error(error, message, code)


def handle_googleapiclient_error(error, message=None, code=None):
    """Constructs a ``FirebaseError`` from the given googleapiclient error.

    Args:
        error: An error raised by the googleapiclient module while making an HTTP call.
        message: A message to be included in the resulting ``FirebaseError`` (optional). If not
            specified the string representation of the ``error`` argument is used as the message.
        code: An HTTP status code or GCP error code that will be used to determine the resulting
            error type (optional). If not specified the HTTP status code on the error response is
            used.

    Returns:
        FirebaseError: A ``FirebaseError`` that can be raised to the user code.
    """
    if isinstance(error, socket.timeout) or (
            isinstance(error, socket.error) and 'timed out' in str(error)):
        return exceptions.DeadlineExceededError(
            message='Timed out while making an API call: {0}'.format(error),
            cause=error)
    elif isinstance(error, httplib2.ServerNotFoundError):
        return exceptions.UnavailableError(
            message='Failed to establish a connection: {0}'.format(error),
            cause=error)
    elif not isinstance(error, googleapiclient.errors.HttpError):
        return exceptions.UnknownError(
            message='Unknown error while making a remote service call: {0}'.format(error),
            cause=error)

    if not code:
        code = error.resp.status
    if not message:
        message = str(error)

    http_response = _http_response_from_googleapiclient_error(error)
    err_type = _lookup_error_type(code)
    return err_type(message=message, cause=error, http_response=http_response)


def _http_response_from_googleapiclient_error(error):
    """Creates a requests HTTP Response object from the given googleapiclient error."""
    resp = requests.models.Response()
    resp.raw = six.BytesIO(error.content)
    resp.status_code = error.resp.status
    return resp


def _lookup_error_type(code):
    """Maps an error code to an exception type."""
    return _ERROR_CODE_TO_EXCEPTION_TYPE.get(code, exceptions.UnknownError)


def _parse_platform_error(content, status_code):
    """Parses an HTTP error response from a Google Cloud Platform API and extracts the error code
    and message fields.

    Args:
        content: Decoded content of the response body.
        status_code: HTTP status code.

    Returns:
        tuple: A tuple containing error code and message.
    """
    data = {}
    try:
        parsed_body = json.loads(content)
        if isinstance(parsed_body, dict):
            data = parsed_body
    except ValueError:
        pass

    error_dict = data.get('error', {})
    code = error_dict.get('status')
    if not code:
        code = _HTTP_STATUS_TO_ERROR_CODE.get(status_code, exceptions.UNKNOWN)

    msg = error_dict.get('message')
    if not msg:
        msg = 'Unexpected HTTP response with status: {0}; body: {1}'.format(status_code, content)
    return error_dict, code, msg
