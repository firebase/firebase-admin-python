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

"""Firebase user management sub module."""

import json
import re

import requests
import six
from six.moves import urllib


INTERNAL_ERROR = 'INTERNAL_ERROR'
USER_NOT_FOUND_ERROR = 'USER_NOT_FOUND_ERROR'
USER_CREATE_ERROR = 'USER_CREATE_ERROR'
USER_UPDATE_ERROR = 'USER_UPDATE_ERROR'
USER_DELETE_ERROR = 'USER_DELETE_ERROR'
USER_DOWNLOAD_ERROR = 'LIST_USERS_ERROR'

MAX_LIST_USERS_RESULTS = 1000
MAX_CLAIMS_PAYLOAD_SIZE = 1000
RESERVED_CLAIMS = set([
    'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash', 'exp', 'iat',
    'iss', 'jti', 'nbf', 'nonce', 'sub', 'firebase',
])


class _Unspecified(object):
    pass

# Use this internally, until sentinels are available in the public API.
_UNSPECIFIED = _Unspecified()


class _Validator(object):
    """A collection of data validation utilities."""

    @classmethod
    def validate_uid(cls, uid, required=False):
        if uid is None and not required:
            return None
        if not isinstance(uid, six.string_types) or not uid or len(uid) > 128:
            raise ValueError(
                'Invalid uid: "{0}". The uid must be a non-empty string with no more than 128 '
                'characters.'.format(uid))
        return uid

    @classmethod
    def validate_email(cls, email, required=False):
        if email is None and not required:
            return None
        if not isinstance(email, six.string_types):
            raise ValueError(
                'Invalid email: "{0}". Email must be a non-empty string.'.format(email))
        parts = email.split('@')
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError('Malformed email address string: "{0}".'.format(email))
        return email

    @classmethod
    def validate_phone(cls, phone, required=False):
        """Validates the specified phone number.

        Phone number vlidation is very lax here. Backend will enforce E.164 spec compliance, and
        normalize accordingly. Here we check if the number starts with + sign, and contains at
        least one alphanumeric character.
        """
        if phone is None and not required:
            return None
        if not isinstance(phone, six.string_types):
            raise ValueError('Invalid phone number: "{0}". Phone number must be a non-empty '
                             'string.'.format(phone))
        if not phone.startswith('+') or not re.search('[a-zA-Z0-9]', phone):
            raise ValueError('Invalid phone number: "{0}". Phone number must be a valid, E.164 '
                             'compliant identifier.'.format(phone))
        return phone

    @classmethod
    def validate_password(cls, password, required=False):
        if password is None and not required:
            return None
        if not isinstance(password, six.string_types) or len(password) < 6:
            raise ValueError(
                'Invalid password string. Password must be a string at least 6 characters long.')
        return password

    @classmethod
    def validate_display_name(cls, display_name, required=False):
        if display_name is None and not required:
            return None
        if not isinstance(display_name, six.string_types) or not display_name:
            raise ValueError(
                'Invalid display name: "{0}". Display name must be a non-empty '
                'string.'.format(display_name))
        return display_name

    @classmethod
    def validate_photo_url(cls, photo_url, required=False):
        if photo_url is None and not required:
            return None
        if not isinstance(photo_url, six.string_types) or not photo_url:
            raise ValueError(
                'Invalid photo URL: "{0}". Photo URL must be a non-empty '
                'string.'.format(photo_url))
        try:
            parsed = urllib.parse.urlparse(photo_url)
            if not parsed.netloc:
                raise ValueError('Malformed photo URL: "{0}".'.format(photo_url))
            return photo_url
        except Exception:
            raise ValueError('Malformed photo URL: "{0}".'.format(photo_url))

    @classmethod
    def validate_timestamp(cls, timestamp, label, required=False):
        if timestamp is None and not required:
            return None
        if isinstance(timestamp, bool):
            raise ValueError('Boolean value specified as timestamp.')
        try:
            timestamp_int = int(timestamp)
            if timestamp_int <= 0:
                raise ValueError('{0} timestamp must be a positive interger.'.format(label))
            return timestamp_int
        except TypeError:
            raise ValueError('Invalid type for timestamp value: {0}.'.format(timestamp))

    @classmethod
    def validate_custom_claims(cls, custom_claims, required=False):
        """Validates the specified custom claims.

        Custom claims must be specified as a JSON string. The string must not exceed 1000
        characters, and the parsed JSON payload must not contain reserved JWT claims.
        """
        if custom_claims is None and not required:
            return None
        claims_str = str(custom_claims)
        if len(claims_str) > MAX_CLAIMS_PAYLOAD_SIZE:
            raise ValueError(
                'Custom claims payload must not exceed {0} '
                'characters.'.format(MAX_CLAIMS_PAYLOAD_SIZE))
        try:
            parsed = json.loads(claims_str)
        except Exception:
            raise ValueError('Failed to parse custom claims string as JSON.')

        if not isinstance(parsed, dict):
            raise ValueError('Custom claims must be parseable as a JSON object.')
        invalid_claims = RESERVED_CLAIMS.intersection(set(parsed.keys()))
        if len(invalid_claims) > 1:
            joined = ', '.join(sorted(invalid_claims))
            raise ValueError('Claims "{0}" are reserved, and must not be set.'.format(joined))
        elif len(invalid_claims) == 1:
            raise ValueError(
                'Claim "{0}" is reserved, and must not be set.'.format(invalid_claims.pop()))
        return claims_str


class ApiCallError(Exception):
    """Represents an Exception encountered while invoking the Firebase user management API."""

    def __init__(self, code, message, error=None):
        Exception.__init__(self, message)
        self.code = code
        self.detail = error


class UserManager(object):
    """Provides methods for interacting with the Google Identity Toolkit."""

    def __init__(self, client):
        self._client = client

    def get_user(self, **kwargs):
        """Gets the user data corresponding to the provided key."""
        if 'uid' in kwargs:
            key, key_type = kwargs.pop('uid'), 'user ID'
            payload = {'localId' : [_Validator.validate_uid(key, required=True)]}
        elif 'email' in kwargs:
            key, key_type = kwargs.pop('email'), 'email'
            payload = {'email' : [_Validator.validate_email(key, required=True)]}
        elif 'phone_number' in kwargs:
            key, key_type = kwargs.pop('phone_number'), 'phone number'
            payload = {'phoneNumber' : [_Validator.validate_phone(key, required=True)]}
        else:
            raise ValueError('Unsupported keyword arguments: {0}.'.format(kwargs))

        try:
            response = self._client.request('post', 'getAccountInfo', json=payload)
        except requests.exceptions.RequestException as error:
            msg = 'Failed to get user by {0}: {1}.'.format(key_type, key)
            self._handle_http_error(INTERNAL_ERROR, msg, error)
        else:
            if not response or not response.get('users'):
                raise ApiCallError(
                    USER_NOT_FOUND_ERROR,
                    'No user record found for the provided {0}: {1}.'.format(key_type, key))
            return response['users'][0]

    def list_users(self, page_token=None, max_results=MAX_LIST_USERS_RESULTS):
        """Retrieves a batch of users."""
        if page_token is not None:
            if not isinstance(page_token, six.string_types) or not page_token:
                raise ValueError('Page token must be a non-empty string.')
        if not isinstance(max_results, int):
            raise ValueError('Max results must be an integer.')
        elif max_results < 1 or max_results > MAX_LIST_USERS_RESULTS:
            raise ValueError(
                'Max results must be a positive integer less than '
                '{0}.'.format(MAX_LIST_USERS_RESULTS))

        payload = {'maxResults': max_results}
        if page_token:
            payload['nextPageToken'] = page_token
        try:
            return self._client.request('post', 'downloadAccount', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(USER_DOWNLOAD_ERROR, 'Failed to download user accounts.', error)

    def create_user(self, uid=None, display_name=None, email=None, phone_number=None,
                    photo_url=None, password=None, disabled=None, email_verified=None):
        """Creates a new user account with the specified properties."""
        payload = {
            'localId': _Validator.validate_uid(uid),
            'displayName': _Validator.validate_display_name(display_name),
            'email': _Validator.validate_email(email),
            'phoneNumber': _Validator.validate_phone(phone_number),
            'photoUrl': _Validator.validate_photo_url(photo_url),
            'password': _Validator.validate_password(password),
            'emailVerified': bool(email_verified) if email_verified is not None else None,
            'disabled': bool(disabled) if disabled is not None else None,
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        try:
            response = self._client.request('post', 'signupNewUser', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(USER_CREATE_ERROR, 'Failed to create new user.', error)
        else:
            if not response or not response.get('localId'):
                raise ApiCallError(USER_CREATE_ERROR, 'Failed to create new user.')
            return response.get('localId')

    def update_user(self, uid, display_name=_UNSPECIFIED, email=None, phone_number=_UNSPECIFIED,
                    photo_url=_UNSPECIFIED, password=None, disabled=None, email_verified=None,
                    valid_since=None, custom_claims=_UNSPECIFIED):
        """Updates an existing user account with the specified properties"""
        payload = {
            'localId': _Validator.validate_uid(uid, required=True),
            'email': _Validator.validate_email(email),
            'password': _Validator.validate_password(password),
            'validSince': _Validator.validate_timestamp(valid_since, 'valid_since'),
            'emailVerified': bool(email_verified) if email_verified is not None else None,
            'disableUser': bool(disabled) if disabled is not None else None,
        }

        remove = []
        if display_name is not _UNSPECIFIED:
            if display_name is None:
                remove.append('DISPLAY_NAME')
            else:
                payload['displayName'] = _Validator.validate_display_name(display_name)
        if photo_url is not _UNSPECIFIED:
            if photo_url is None:
                remove.append('PHOTO_URL')
            else:
                payload['photoUrl'] = _Validator.validate_photo_url(photo_url)
        if remove:
            payload['deleteAttribute'] = remove

        if phone_number is not _UNSPECIFIED:
            if phone_number is None:
                payload['deleteProvider'] = ['phone']
            else:
                payload['phoneNumber'] = _Validator.validate_phone(phone_number)

        if custom_claims is not _UNSPECIFIED:
            if custom_claims is None:
                custom_claims = {}
            json_claims = json.dumps(custom_claims) if isinstance(
                custom_claims, dict) else custom_claims
            payload['customAttributes'] = _Validator.validate_custom_claims(json_claims)

        payload = {k: v for k, v in payload.items() if v is not None}
        try:
            response = self._client.request('post', 'setAccountInfo', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(
                USER_UPDATE_ERROR, 'Failed to update user: {0}.'.format(uid), error)
        else:
            if not response or not response.get('localId'):
                raise ApiCallError(USER_UPDATE_ERROR, 'Failed to update user: {0}.'.format(uid))
            return response.get('localId')

    def delete_user(self, uid):
        """Deletes the user identified by the specified user ID."""
        _Validator.validate_uid(uid, required=True)
        try:
            response = self._client.request('post', 'deleteAccount', json={'localId' : uid})
        except requests.exceptions.RequestException as error:
            self._handle_http_error(
                USER_DELETE_ERROR, 'Failed to delete user: {0}.'.format(uid), error)
        else:
            if not response or not response.get('kind'):
                raise ApiCallError(USER_DELETE_ERROR, 'Failed to delete user: {0}.'.format(uid))

    def _handle_http_error(self, code, msg, error):
        if error.response is not None:
            msg += '\nServer response: {0}'.format(error.response.content.decode())
        else:
            msg += '\nReason: {0}'.format(error)
        raise ApiCallError(code, msg, error)


class UserIterator(object):
    """An iterator that allows iterating over user accounts, one at a time.

    This implementation loads a page of users into memory, and iterates on them. When the whole
    page has been traversed, it loads another page. This class never keeps more than one page
    of entries in memory.
    """

    def __init__(self, current_page):
        if not current_page:
            raise ValueError('Current page must not be None.')
        self._current_page = current_page
        self._index = 0

    def next(self):
        if self._index == len(self._current_page.users):
            if self._current_page.has_next_page:
                self._current_page = self._current_page.get_next_page()
                self._index = 0
        if self._index < len(self._current_page.users):
            result = self._current_page.users[self._index]
            self._index += 1
            return result
        raise StopIteration

    def __next__(self):
        return self.next()

    def __iter__(self):
        return self
