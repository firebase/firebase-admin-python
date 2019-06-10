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

import requests

import firebase_admin
from firebase_admin import exceptions


_STATUS_TO_EXCEPTION_TYPE = {
    400: exceptions.InvalidArgumentError,
    401: exceptions.UnautenticatedError,
    403: exceptions.PermissionDeniedError,
    404: exceptions.NotFoundError,
    409: exceptions.ConflictError,
    429: exceptions.ResourceExhaustedError,
    500: exceptions.InternalError,
    503: exceptions.UnavailableError,
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

def handle_requests_error(error, message=None, status=None):
    """Constructs a FirebaseError from the given requests error."""
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

    if not status:
        status = error.response.status_code
    if not message:
        message = str(error)
    err_type = _STATUS_TO_EXCEPTION_TYPE.get(status, exceptions.UnknownError)
    return err_type(message=message, cause=error, http_response=error.response)
