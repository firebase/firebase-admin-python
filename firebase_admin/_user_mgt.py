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

from google.auth import transport
import requests
import six
from six.moves import urllib

import firebase_admin


INTERNAL_ERROR = 'INTERNAL_ERROR'
USER_NOT_FOUND_ERROR = 'USER_NOT_FOUND_ERROR'
USER_CREATE_ERROR = 'USER_CREATE_ERROR'
USER_UPDATE_ERROR = 'USER_UPDATE_ERROR'
USER_DELETE_ERROR = 'USER_DELETE_ERROR'
USER_DOWNLOAD_ERROR = 'LIST_USERS_ERROR'

ID_TOOLKIT_URL = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/'

MAX_LIST_USERS_RESULTS = 1000
MAX_CLAIMS_PAYLOAD_SIZE = 1000
RESERVED_CLAIMS = set([
    'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash', 'exp', 'iat',
    'iss', 'jti', 'nbf', 'nonce', 'sub', 'firebase',
])


class _Validator(object):
    """A collection of data validation utilities.

    Methods provided in this class raise ValueErrors if any validations fail. Normal returns
    signal success.
    """

    @classmethod
    def validate_uid(cls, uid):
        if not isinstance(uid, six.string_types) or not uid or len(uid) > 128:
            raise ValueError(
                'Invalid uid: "{0}". The uid must be a non-empty string with no more than 128 '
                'characters.'.format(uid))

    @classmethod
    def validate_email(cls, email):
        if not isinstance(email, six.string_types) or not email:
            raise ValueError(
                'Invalid email: "{0}". Email must be a non-empty string.'.format(email))
        parts = email.split('@')
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError('Malformed email address string: "{0}".'.format(email))

    @classmethod
    def validate_phone(cls, phone):
        """Validates the specified phone number.

        Phone number vlidation is very lax here. Backend will enforce E.164 spec compliance, and
        normalize accordingly. Here we check if the number starts with + sign, and contains at
        least one alphanumeric character.
        """
        if not isinstance(phone, six.string_types) or not phone:
            raise ValueError('Invalid phone number: "{0}". Phone number must be a non-empty '
                             'string.'.format(phone))
        if not phone.startswith('+') or not re.search('[a-zA-Z0-9]', phone):
            raise ValueError('Invalid phone number: "{0}". Phone number must be a valid, E.164 '
                             'compliant identifier.'.format(phone))

    @classmethod
    def validate_password(cls, password):
        if not isinstance(password, six.string_types) or len(password) < 6:
            raise ValueError(
                'Invalid password string. Password must be a string at least 6 characters long.')

    @classmethod
    def validate_email_verified(cls, email_verified):
        if not isinstance(email_verified, bool):
            raise ValueError(
                'Invalid email verified status: "{0}". Email verified status must be '
                'boolean.'.format(email_verified))

    @classmethod
    def validate_display_name(cls, display_name):
        if not isinstance(display_name, six.string_types) or not display_name:
            raise ValueError(
                'Invalid display name: "{0}". Display name must be a non-empty '
                'string.'.format(display_name))

    @classmethod
    def validate_photo_url(cls, photo_url):
        if not isinstance(photo_url, six.string_types) or not photo_url:
            raise ValueError(
                'Invalid photo URL: "{0}". Photo URL must be a non-empty '
                'string.'.format(photo_url))
        try:
            parsed = urllib.parse.urlparse(photo_url)
            if not parsed.netloc:
                raise ValueError('Malformed photo URL: "{0}".'.format(photo_url))
        except Exception:
            raise ValueError('Malformed photo URL: "{0}".'.format(photo_url))

    @classmethod
    def validate_valid_since(cls, valid_since):
        # isinstance(True, int) is True hence the extra check
        if valid_since is None or isinstance(valid_since, bool) or not isinstance(valid_since, int):
            raise ValueError(
                'Invalid time string for: "{0}". Valid Since must be an int'.format(valid_since))
        if int(valid_since) <= 0:
            raise ValueError(
                'Invalid valid_since: must be a positive interger. {0}'.format(valid_since))

    @classmethod
    def validate_disabled(cls, disabled):
        if not isinstance(disabled, bool):
            raise ValueError(
                'Invalid disabled status: "{0}". Disabled status must be '
                'boolean.'.format(disabled))

    @classmethod
    def validate_delete_list(cls, delete_attr):
        if not isinstance(delete_attr, list) or not delete_attr:
            raise ValueError(
                'Invalid delete list: "{0}". Delete list must be a '
                'non-empty list.'.format(delete_attr))

    @classmethod
    def validate_custom_claims(cls, custom_claims):
        """Validates the specified custom claims.

        Custom claims must be specified as a JSON string.The string must not exceed 1000
        characters, and the parsed JSON payload must not contain reserved JWT claims.
        """
        if not isinstance(custom_claims, six.string_types) or not custom_claims:
            raise ValueError(
                'Invalid custom claims: "{0}". Custom claims must be a non-empty JSON '
                'string.'.format(custom_claims))

        if len(custom_claims) > MAX_CLAIMS_PAYLOAD_SIZE:
            raise ValueError(
                'Custom claims payload must not exceed {0} '
                'characters.'.format(MAX_CLAIMS_PAYLOAD_SIZE))
        try:
            parsed = json.loads(custom_claims)
        except Exception:
            raise ValueError('Failed to parse custom claims string as JSON.')
        else:
            if not isinstance(parsed, dict):
                raise ValueError('Custom claims must be parseable as a JSON object.')
            invalid_claims = RESERVED_CLAIMS.intersection(set(parsed.keys()))
            if len(invalid_claims) > 1:
                joined = ', '.join(sorted(invalid_claims))
                raise ValueError('Claims "{0}" are reserved, and must not be set.'.format(joined))
            elif len(invalid_claims) == 1:
                raise ValueError(
                    'Claim "{0}" is reserved, and must not be set.'.format(invalid_claims.pop()))


class ApiCallError(Exception):
    """Represents an Exception encountered while invoking the Firebase user management API."""

    def __init__(self, code, message, error=None):
        Exception.__init__(self, message)
        self.code = code
        self.detail = error


class UserManager(object):
    """Provides methods for interacting with the Google Identity Toolkit."""

    _VALIDATORS = {
        'customAttributes' : _Validator.validate_custom_claims,
        'deleteAttribute' : _Validator.validate_delete_list,
        'deleteProvider' : _Validator.validate_delete_list,
        'disabled' : _Validator.validate_disabled,
        'disableUser' : _Validator.validate_disabled,
        'displayName' : _Validator.validate_display_name,
        'email' : _Validator.validate_email,
        'emailVerified' : _Validator.validate_email_verified,
        'localId' : _Validator.validate_uid,
        'password' : _Validator.validate_password,
        'phoneNumber' : _Validator.validate_phone,
        'photoUrl' : _Validator.validate_photo_url,
        'validSince' : _Validator.validate_valid_since,
    }

    _CREATE_USER_FIELDS = {
        'uid' : 'localId',
        'display_name' : 'displayName',
        'email' : 'email',
        'email_verified' : 'emailVerified',
        'phone_number' : 'phoneNumber',
        'photo_url' : 'photoUrl',
        'password' : 'password',
        'disabled' : 'disabled',
    }

    _UPDATE_USER_FIELDS = {
        'display_name' : 'displayName',
        'email' : 'email',
        'email_verified' : 'emailVerified',
        'phone_number' : 'phoneNumber',
        'photo_url' : 'photoUrl',
        'password' : 'password',
        'disabled' : 'disableUser',
        'custom_claims' : 'customAttributes',
        'valid_since' : 'validSince',
    }

    _REMOVABLE_FIELDS = {
        'displayName' : 'DISPLAY_NAME',
        'photoUrl' : 'PHOTO_URL'
    }

    def __init__(self, app):
        g_credential = app.credential.get_credential()
        session = transport.requests.AuthorizedSession(g_credential)
        version_header = 'Python/Admin/{0}'.format(firebase_admin.__version__)
        session.headers.update({'X-Client-Version': version_header})
        self._session = session

    def get_user(self, **kwargs):
        """Gets the user data corresponding to the provided key."""
        if 'uid' in kwargs:
            key, key_type = kwargs.pop('uid'), 'user ID'
            _Validator.validate_uid(key)
            payload = {'localId' : [key]}
        elif 'email' in kwargs:
            key, key_type = kwargs.pop('email'), 'email'
            _Validator.validate_email(key)
            payload = {'email' : [key]}
        elif 'phone_number' in kwargs:
            key, key_type = kwargs.pop('phone_number'), 'phone number'
            _Validator.validate_phone(key)
            payload = {'phoneNumber' : [key]}
        else:
            raise ValueError('Unsupported keyword arguments: {0}.'.format(kwargs))

        try:
            response = self._request('post', 'getAccountInfo', json=payload)
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
            return self._request('post', 'downloadAccount', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(USER_DOWNLOAD_ERROR, 'Failed to download user accounts.', error)

    def create_user(self, **kwargs):
        """Creates a new user account with the specified properties."""
        payload = self._init_payload('create_user', UserManager._CREATE_USER_FIELDS, **kwargs)
        self._validate(payload, self._VALIDATORS, 'create user')
        try:
            response = self._request('post', 'signupNewUser', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(USER_CREATE_ERROR, 'Failed to create new user.', error)
        else:
            if not response or not response.get('localId'):
                raise ApiCallError(USER_CREATE_ERROR, 'Failed to create new user.')
            return response.get('localId')

    def update_user(self, uid, **kwargs):
        """Updates an existing user account with the specified properties"""
        _Validator.validate_uid(uid)
        payload = self._init_payload('update_user', UserManager._UPDATE_USER_FIELDS, **kwargs)
        payload['localId'] = uid

        remove = []
        for key, value in UserManager._REMOVABLE_FIELDS.items():
            if key in payload and payload[key] is None:
                remove.append(value)
                del payload[key]
        if remove:
            payload['deleteAttribute'] = sorted(remove)
        if 'phoneNumber' in payload and payload['phoneNumber'] is None:
            payload['deleteProvider'] = ['phone']
            del payload['phoneNumber']
        if 'customAttributes' in payload:
            custom_claims = payload['customAttributes']
            if custom_claims is None:
                custom_claims = {}
            if isinstance(custom_claims, dict):
                payload['customAttributes'] = json.dumps(custom_claims)

        self._validate(payload, self._VALIDATORS, 'update user')
        try:
            response = self._request('post', 'setAccountInfo', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(
                USER_UPDATE_ERROR, 'Failed to update user: {0}.'.format(uid), error)
        else:
            if not response or not response.get('localId'):
                raise ApiCallError(USER_UPDATE_ERROR, 'Failed to update user: {0}.'.format(uid))
            return response.get('localId')

    def delete_user(self, uid):
        """Deletes the user identified by the specified user ID."""
        _Validator.validate_uid(uid)
        try:
            response = self._request('post', 'deleteAccount', json={'localId' : uid})
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

    def _init_payload(self, operation, fields, **kwargs):
        payload = {}
        for key, value in fields.items():
            if key in kwargs:
                payload[value] = kwargs.pop(key)
        if kwargs:
            unexpected_keys = ', '.join(kwargs.keys())
            raise ValueError(
                'Unsupported arguments: "{0}" in call to {1}()'.format(unexpected_keys, operation))
        return payload

    def _validate(self, properties, validators, operation):
        for key, value in properties.items():
            validator = validators.get(key)
            if not validator:
                raise ValueError('Unsupported property: "{0}" in {1} call.'.format(key, operation))
            validator(value)

    def _request(self, method, urlpath, **kwargs):
        """Makes an HTTP call using the Python requests library.

        Refer to http://docs.python-requests.org/en/master/api/ for more information on supported
        options and features.

        Args:
          method: HTTP method name as a string (e.g. get, post).
          urlpath: URL path of the remote endpoint. This will be appended to the server's base URL.
          kwargs: An additional set of keyword arguments to be passed into requests API
              (e.g. json, params).

        Returns:
          dict: The parsed JSON response.
        """
        resp = self._session.request(method, ID_TOOLKIT_URL + urlpath, **kwargs)
        resp.raise_for_status()
        return resp.json()


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
