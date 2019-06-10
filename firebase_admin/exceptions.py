# Copyright 20190 Google Inc.
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

"""Firebase Exceptions module.

This module defines the base types for exceptions and the platform-wide error codes as outlined in
https://cloud.google.com/apis/design/errors.
"""


INVALID_ARGUMENT = 'INVALID_ARGUMENT'
FAILED_PRECONDITION = 'FAILED_PRECONDITION'
OUT_OF_RANGE = 'OUT_OF_RANGE'
UNAUTHENTICATED = 'UNAUTHENTICATED'
PERMISSION_DENIED = 'PERMISSION_DENIED'
NOT_FOUND = 'NOT_FOUND'
CONFLICT = 'CONFLICT'
ABORTED = 'ABORTED'
ALREADY_EXISTS = 'ALREADY_EXISTS'
RESOURCE_EXHAUSTED = 'RESOURCE_EXHAUSTED'
CANCELLED = 'CANCELLED'
DATA_LOSS = 'DATA_LOSS'
UNKNOWN = 'UNKNOWN'
INTERNAL = 'INTERNAL'
UNAVAILABLE = 'UNAVAILABLE'
DEADLINE_EXCEEDED = 'DEADLINE_EXCEEDED'


class FirebaseError(Exception):
    """Base class for all errors raised by the Admin SDK."""

    def __init__(self, code, message, cause=None, http_response=None):
        Exception.__init__(self, message)
        self._code = code
        self._cause = cause
        self._http_response = http_response

    @property
    def code(self):
        return self._code

    @property
    def cause(self):
        return self._cause

    @property
    def http_response(self):
        return self._http_response


class InvalidArgumentError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, INVALID_ARGUMENT, message, cause, http_response)


class FailedPreconditionError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, FAILED_PRECONDITION, message, cause, http_response)


class OutOfRangeError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, OUT_OF_RANGE, message, cause, http_response)


class UnautenticatedError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, UNAUTHENTICATED, message, cause, http_response)


class PermissionDeniedError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, PERMISSION_DENIED, message, cause, http_response)


class NotFoundError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, NOT_FOUND, message, cause, http_response)


class ConflictError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, CONFLICT, message, cause, http_response)


class AbortedError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, ABORTED, message, cause, http_response)


class AlreadyExistsError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, ALREADY_EXISTS, message, cause, http_response)


class ResourceExhaustedError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, RESOURCE_EXHAUSTED, message, cause, http_response)


class CancelledError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, CANCELLED, message, cause, http_response)


class DataLossError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, DATA_LOSS, message, cause, http_response)


class UnknownError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, UNKNOWN, message, cause, http_response)


class InternalError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, INTERNAL, message, cause, http_response)


class UnavailableError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, UNAVAILABLE, message, cause, http_response)


class DeadlineExceededError(FirebaseError):

    def __init__(self, message, cause=None, http_response=None):
        FirebaseError.__init__(self, DEADLINE_EXCEEDED, message, cause, http_response)
