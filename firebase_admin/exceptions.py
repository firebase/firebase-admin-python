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


ALREADY_EXISTS = 'ALREADY_EXISTS'
INVALID_ARGUMENT = 'INVALID_ARGUMENT'
FAILED_PRECONDITION = 'FAILED_PRECONDITION'
UNAUTHENTICATED = 'UNAUTHENTICATED'
PERMISSION_DENIED = 'PERMISSION_DENIED'
NOT_FOUND = 'NOT_FOUND'
UNKNOWN = 'UNKNOWN'
INTERNAL = 'INTERNAL'
UNAVAILABLE = 'UNAVAILABLE'
DEADLINE_EXCEEDED = 'DEADLINE_EXCEEDED'


class FirebaseError(Exception):

    def __init__(self, code, message, cause=None, http_response=None):
        Exception.__init__(self, message)
        self._code = code
        self._cause = cause
        self._http_response = http_response
        print('CONST', self._http_response)

    @property
    def code(self):
        return self._code

    @property
    def cause(self):
        return self._cause

    @property
    def http_response(self):
        return self._http_response
