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

import base64
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
USER_IMPORT_ERROR = 'USER_IMPORT_ERROR'
USER_DOWNLOAD_ERROR = 'LIST_USERS_ERROR'

MAX_LIST_USERS_RESULTS = 1000
MAX_CLAIMS_PAYLOAD_SIZE = 1000
RESERVED_CLAIMS = set([
    'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash', 'exp', 'iat',
    'iss', 'jti', 'nbf', 'nonce', 'sub', 'firebase',
])


class _UnspecifiedSentinel(object):
    pass

_UNSPECIFIED = _UnspecifiedSentinel()


class _Validator(object):
    """A collection of data validation utilities."""

    @classmethod
    def validate_uid(cls, uid, required=True):
        if uid is _UNSPECIFIED and not required:
            return _UNSPECIFIED
        if not isinstance(uid, six.string_types) or not uid or len(uid) > 128:
            raise ValueError(
                'Invalid uid: "{0}". The uid must be a non-empty string with no more than 128 '
                'characters.'.format(uid))
        return uid

    @classmethod
    def validate_email(cls, email):
        if email is _UNSPECIFIED:
            return _UNSPECIFIED
        if not isinstance(email, six.string_types) or not email:
            raise ValueError(
                'Invalid email: "{0}". Email must be a non-empty string.'.format(email))
        parts = email.split('@')
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError('Malformed email address string: "{0}".'.format(email))
        return email

    @classmethod
    def validate_phone(cls, phone):
        """Validates the specified phone number.

        Phone number vlidation is very lax here. Backend will enforce E.164 spec compliance, and
        normalize accordingly. Here we check if the number starts with + sign, and contains at
        least one alphanumeric character.
        """
        if phone is _UNSPECIFIED:
            return _UNSPECIFIED
        if not isinstance(phone, six.string_types) or not phone:
            raise ValueError('Invalid phone number: "{0}". Phone number must be a non-empty '
                             'string.'.format(phone))
        if not phone.startswith('+') or not re.search('[a-zA-Z0-9]', phone):
            raise ValueError('Invalid phone number: "{0}". Phone number must be a valid, E.164 '
                             'compliant identifier.'.format(phone))
        return phone

    @classmethod
    def validate_password(cls, password):
        if password is _UNSPECIFIED:
            return _UNSPECIFIED
        if not isinstance(password, six.string_types) or len(password) < 6:
            raise ValueError(
                'Invalid password string. Password must be a string at least 6 characters long.')
        return password

    @classmethod
    def validate_bytes(cls, value, label):
        if value is _UNSPECIFIED:
            return _UNSPECIFIED
        if not isinstance(value, six.binary_type) or not value:
            raise ValueError('{0} must be a non-empty byte sequence.'.format(label))
        return value

    @classmethod
    def validate_boolean(cls, value, label):
        if value is _UNSPECIFIED:
            return _UNSPECIFIED
        if not isinstance(value, bool):
            raise ValueError('{0} must be boolean.'.format(label))
        return value

    @classmethod
    def validate_display_name(cls, display_name):
        if display_name is _UNSPECIFIED:
            return _UNSPECIFIED
        if not isinstance(display_name, six.string_types) or not display_name:
            raise ValueError(
                'Invalid display name: "{0}". Display name must be a non-empty '
                'string.'.format(display_name))
        return display_name

    @classmethod
    def validate_photo_url(cls, photo_url):
        if photo_url is _UNSPECIFIED:
            return _UNSPECIFIED
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
    def validate_timestamp(cls, timestamp, label):
        if timestamp is _UNSPECIFIED:
            return _UNSPECIFIED
        if timestamp is None or isinstance(timestamp, bool) or not isinstance(timestamp, int):
            raise ValueError(
                'Invalid timestamp. {0} must be an int'.format(label))
        if int(timestamp) <= 0:
            raise ValueError(
                'Invalid timestamp. {0} must be a positive interger.'.format(label))
        return timestamp


    @classmethod
    def validate_custom_claims(cls, custom_claims):
        """Validates the specified custom claims.

        Custom claims must be specified as a JSON string. The string must not exceed 1000
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
        return custom_claims


class ApiCallError(Exception):
    """Represents an Exception encountered while invoking the Firebase user management API."""

    def __init__(self, code, message, error=None):
        Exception.__init__(self, message)
        self.code = code
        self.detail = error


def _none_to_unspecified(value):
    if value is None:
        return _UNSPECIFIED
    else:
        return value


class UserMetadata(object):
    """Contains additional metadata associated with a user account."""

    def __init__(self, creation_timestamp=None, last_sign_in_timestamp=None):
        self._creation_timestamp = creation_timestamp
        self._last_sign_in_timestamp = last_sign_in_timestamp

    @property
    def creation_timestamp(self):
        """ Creation timestamp in milliseconds since the epoch.

        Returns:
          integer: The user creation timestamp in milliseconds since the epoch.
        """
        return self._creation_timestamp

    @property
    def last_sign_in_timestamp(self):
        """ Last sign in timestamp in milliseconds since the epoch.

        Returns:
          integer: The last sign in timestamp in milliseconds since the epoch.
        """
        return self._last_sign_in_timestamp


class UserProvider(object):

    def __init__(self, uid, provider_id, email=None, display_name=None, photo_url=None):
        self.uid = uid
        self.provider_id = provider_id
        self.email = _none_to_unspecified(email)
        self.display_name = _none_to_unspecified(display_name)
        self.photo_url = _none_to_unspecified(photo_url)


class UserImportRecord(object):

    def __init__(self, uid, email=None, email_verified=None, display_name=None, phone_number=None,
                 photo_url=None, disabled=None, metadata=None, provider_data=None,
                 custom_claims=None, password_hash=None, password_salt=None):
        self.uid = uid
        self.email = _none_to_unspecified(email)
        self.email_verified = _none_to_unspecified(email_verified)
        self.display_name = _none_to_unspecified(display_name)
        self.phone_number = _none_to_unspecified(phone_number)
        self.photo_url = _none_to_unspecified(photo_url)
        self.disabled = _none_to_unspecified(disabled)
        self.metadata = _none_to_unspecified(metadata)
        self.provider_data = _none_to_unspecified(provider_data)
        self.custom_claims = _none_to_unspecified(custom_claims)
        self.password_hash = _none_to_unspecified(password_hash)
        self.password_salt = _none_to_unspecified(password_salt)


class ErrorInfo(object):

    def __init__(self, error):
        self._index = error['index']
        self._reason = error['message']

    @property
    def index(self):
        return self._index

    @property
    def reason(self):
        return self._reason


class UserImportResult(object):

    def __init__(self, result, total):
        errors = result.get('error', [])
        self._success_count = total - len(errors)
        self._failure_count = len(errors)
        self._errors = [ErrorInfo(err) for err in errors]

    @property
    def success_count(self):
        return self._success_count

    @property
    def failure_count(self):
        return self._failure_count

    @property
    def errors(self):
        return self._errors


def encode_user_provider(provider):
    if not isinstance(provider, UserProvider):
        raise ValueError('Invalid user provider: {0}.'.format(provider))
    payload = {
        'rawId': _Validator.validate_uid(provider.uid),
        'providerId': _Validator.validate_uid(provider.provider_id),
        'displayName': _Validator.validate_display_name(provider.display_name),
        'email': _Validator.validate_email(provider.email),
        'photoUrl': _Validator.validate_photo_url(provider.photo_url),
    }
    return {k: v for k, v in payload.items() if v is not _UNSPECIFIED}

def encode_user_import_record(user):
    if not isinstance(user, UserImportRecord):
        raise ValueError('Invalid user import record: {0}.'.format(user))
    payload = {
        'localId': _Validator.validate_uid(user.uid),
        'email': _Validator.validate_email(user.email),
        'emailVerified': _Validator.validate_boolean(user.email_verified, 'email_verified'),
        'displayName': _Validator.validate_display_name(user.display_name),
        'phoneNumber': _Validator.validate_phone(user.phone_number),
        'photoUrl': _Validator.validate_photo_url(user.photo_url),
        'disabled': _Validator.validate_boolean(user.disabled, 'disabled'),
    }
    if user.password_hash is not _UNSPECIFIED:
        password_hash = _Validator.validate_bytes(user.password_hash, 'password_hash')
        payload['passwordHash'] = base64.urlsafe_b64encode(password_hash)
    if user.password_salt is not _UNSPECIFIED:
        password_salt = _Validator.validate_bytes(user.password_salt, 'password_salt')
        payload['salt'] = base64.urlsafe_b64encode(password_salt)
    if user.metadata is not _UNSPECIFIED:
        if not isinstance(user.metadata, UserMetadata):
            raise ValueError('Invalid user metadata instance: {0}.'.format(user.metadata))
        payload['createdAt'] = _Validator.validate_timestamp(_none_to_unspecified(
            user.metadata.creation_timestamp), 'creation_timestamp')
        payload['lastLoginAt'] = _Validator.validate_timestamp(_none_to_unspecified(
            user.metadata.last_sign_in_timestamp), 'last_sign_in_timestamp')
    if user.custom_claims is not _UNSPECIFIED:
        if isinstance(user.custom_claims, dict):
            custom_claims = json.dumps(user.custom_claims)
        else:
            custom_claims = user.custom_claimns
        payload['customAttributes'] = _Validator.validate_custom_claims(custom_claims)
    if user.provider_data is not _UNSPECIFIED:
        if not isinstance(user.provider_data, list):
            raise ValueError('Provider data must be a list.')
        payload['providerUserInfo'] = [encode_user_provider(p) for p in user.provider_data]
    return {k: v for k, v in payload.items() if v is not _UNSPECIFIED}


class UserManager(object):
    """Provides methods for interacting with the Google Identity Toolkit."""

    def __init__(self, client):
        self._client = client

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

    def create_user(self, **kwargs):
        """Creates a new user account with the specified properties."""
        payload = {
            'localId': _Validator.validate_uid(kwargs.pop('uid', _UNSPECIFIED), required=False),
            'displayName': _Validator.validate_display_name(kwargs.pop(
                'display_name', _UNSPECIFIED)),
            'email': _Validator.validate_email(kwargs.pop('email', _UNSPECIFIED)),
            'emailVerified': _Validator.validate_boolean(kwargs.pop(
                'email_verified', _UNSPECIFIED), 'email_verified'),
            'phoneNumber': _Validator.validate_phone(kwargs.pop('phone_number', _UNSPECIFIED)),
            'photoUrl': _Validator.validate_photo_url(kwargs.pop('photo_url', _UNSPECIFIED)),
            'password': _Validator.validate_password(kwargs.pop('password', _UNSPECIFIED)),
            'disabled': _Validator.validate_boolean(kwargs.pop(
                'disabled', _UNSPECIFIED), 'disabled'),
        }
        if kwargs:
            unexpected_keys = ', '.join(kwargs.keys())
            raise ValueError(
                'Unsupported arguments: "{0}" in call to create_user()'.format(unexpected_keys))
        payload = {k: v for k, v in payload.items() if v is not _UNSPECIFIED}
        try:
            response = self._client.request('post', 'signupNewUser', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(USER_CREATE_ERROR, 'Failed to create new user.', error)
        else:
            if not response or not response.get('localId'):
                raise ApiCallError(USER_CREATE_ERROR, 'Failed to create new user.')
            return response.get('localId')

    def update_user(self, uid, **kwargs):
        """Updates an existing user account with the specified properties"""
        payload = {
            'localId': _Validator.validate_uid(uid),
            'email': _Validator.validate_email(kwargs.pop('email', _UNSPECIFIED)),
            'emailVerified': _Validator.validate_boolean(kwargs.pop(
                'email_verified', _UNSPECIFIED), 'email_verified'),
            'password': _Validator.validate_password(kwargs.pop('password', _UNSPECIFIED)),
            'disableUser': _Validator.validate_boolean(kwargs.pop(
                'disabled', _UNSPECIFIED), 'disabled'),
            'validSince': _Validator.validate_timestamp(kwargs.pop(
                'valid_since', _UNSPECIFIED), 'valid_since'),
        }

        remove = []
        if 'display_name' in kwargs:
            display_name = kwargs.pop('display_name')
            if display_name is None:
                remove.append('DISPLAY_NAME')
            else:
                payload['displayName'] = _Validator.validate_display_name(display_name)

        if 'photo_url' in kwargs:
            photo_url = kwargs.pop('photo_url')
            if photo_url is None:
                remove.append('PHOTO_URL')
            else:
                payload['photoUrl'] = _Validator.validate_photo_url(photo_url)

        if remove:
            payload['deleteAttribute'] = remove
        if 'phone_number' in kwargs:
            phone_number = kwargs.pop('phone_number')
            if phone_number is None:
                payload['deleteProvider'] = ['phone']
            else:
                payload['phoneNumber'] = _Validator.validate_phone(phone_number)

        if 'custom_claims' in kwargs:
            custom_claims = kwargs.pop('custom_claims')
            if custom_claims is None:
                custom_claims = {}
            if isinstance(custom_claims, dict):
                custom_claims = json.dumps(custom_claims) # pylint: disable=redefined-variable-type
            payload['customAttributes'] = _Validator.validate_custom_claims(custom_claims)

        if kwargs:
            unexpected_keys = ', '.join(kwargs.keys())
            raise ValueError(
                'Unsupported arguments: "{0}" in call to update_user()'.format(unexpected_keys))
        payload = {k: v for k, v in payload.items() if v is not _UNSPECIFIED}

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
        _Validator.validate_uid(uid)
        try:
            response = self._client.request('post', 'deleteAccount', json={'localId' : uid})
        except requests.exceptions.RequestException as error:
            self._handle_http_error(
                USER_DELETE_ERROR, 'Failed to delete user: {0}.'.format(uid), error)
        else:
            if not response or not response.get('kind'):
                raise ApiCallError(USER_DELETE_ERROR, 'Failed to delete user: {0}.'.format(uid))

    def import_users(self, users, hash_alg=None):
        """Imports the given list of users to Firebase Auth."""
        if not isinstance(users, list) or not users:
            raise ValueError('Users must be a non-empty list.')
        if len(users) > 1000:
            raise ValueError('Users list must not have more than 1000 elements.')
        payload = {
            'users': [encode_user_import_record(u) for u in users]
        }
        if any(['passwordHash' in u for u in payload['users']]):
            if not hash_alg:
                raise ValueError('Hash is required when at least one user has a password.')
            payload.update(hash_alg.to_dict())
        try:
            response = self._client.request('post', 'uploadAccount', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(
                USER_IMPORT_ERROR, 'Failed to import users.', error)
        else:
            if not isinstance(response, dict):
                raise ApiCallError(USER_IMPORT_ERROR, 'Failed to import users.')
            return response

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
