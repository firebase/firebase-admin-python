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
MAX_IMPORT_USERS_SIZE = 1000
RESERVED_CLAIMS = set([
    'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash', 'exp', 'iat',
    'iss', 'jti', 'nbf', 'nonce', 'sub', 'firebase',
])


class _UnspecifiedSentinel(object):
    pass

_UNSPECIFIED = _UnspecifiedSentinel()


def _none_to_unspecified(value):
    if value is None:
        return _UNSPECIFIED
    else:
        return value

def _b64_encode(bytes_value):
    return base64.urlsafe_b64encode(bytes_value).decode()


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
    def validate_provider_id(cls, provider_id):
        if provider_id is _UNSPECIFIED:
            return _UNSPECIFIED
        if not isinstance(provider_id, six.string_types) or not provider_id:
            raise ValueError(
                'Invalid provider ID: "{0}". Provider ID must be a non-empty '
                'string.'.format(provider_id))
        return provider_id

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
                'Invalid timestamp. {0} must be an int.'.format(label))
        if int(timestamp) <= 0:
            raise ValueError(
                'Invalid timestamp. {0} must be a positive interger.'.format(label))
        return timestamp

    @classmethod
    def validate_int(cls, value, label, low=None, high=None):
        if value is None or isinstance(value, bool) or not isinstance(value, int):
            raise ValueError('{0} must be an int.'.format(value))
        if low is not None and value < low:
            raise ValueError('{0} must not be smaller than {1}.'.format(label, low))
        if high is not None and value > high:
            raise ValueError('{0} must not be larger than {1}.'.format(label, high))
        return value

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


class UserInfo(object):
    """A collection of standard profile information for a user.

    Used to expose profile information returned by an identity provider.
    """

    @property
    def uid(self):
        """Returns the user ID of this user."""
        raise NotImplementedError

    @property
    def display_name(self):
        """Returns the display name of this user."""
        raise NotImplementedError

    @property
    def email(self):
        """Returns the email address associated with this user."""
        raise NotImplementedError

    @property
    def phone_number(self):
        """Returns the phone number associated with this user."""
        raise NotImplementedError

    @property
    def photo_url(self):
        """Returns the photo URL of this user."""
        raise NotImplementedError

    @property
    def provider_id(self):
        """Returns the ID of the identity provider.

        This can be a short domain name (e.g. google.com), or the identity of an OpenID
        identity provider.
        """
        raise NotImplementedError


class UserRecord(UserInfo):
    """Contains metadata associated with a Firebase user account."""

    def __init__(self, data):
        super(UserRecord, self).__init__()
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument: {0}. Must be a dictionary.'.format(data))
        if not data.get('localId'):
            raise ValueError('User ID must not be None or empty.')
        self._data = data

    @property
    def uid(self):
        """Returns the user ID of this user.

        Returns:
          string: A user ID string. This value is never None or empty.
        """
        return self._data.get('localId')

    @property
    def display_name(self):
        """Returns the display name of this user.

        Returns:
          string: A display name string or None.
        """
        return self._data.get('displayName')

    @property
    def email(self):
        """Returns the email address associated with this user.

        Returns:
          string: An email address string or None.
        """
        return self._data.get('email')

    @property
    def phone_number(self):
        """Returns the phone number associated with this user.

        Returns:
          string: A phone number string or None.
        """
        return self._data.get('phoneNumber')

    @property
    def photo_url(self):
        """Returns the photo URL of this user.

        Returns:
          string: A URL string or None.
        """
        return self._data.get('photoUrl')

    @property
    def provider_id(self):
        """Returns the provider ID of this user.

        Returns:
          string: A constant provider ID value.
        """
        return 'firebase'

    @property
    def email_verified(self):
        """Returns whether the email address of this user has been verified.

        Returns:
          bool: True if the email has been verified, and False otherwise.
        """
        return bool(self._data.get('emailVerified'))

    @property
    def disabled(self):
        """Returns whether this user account is disabled.

        Returns:
          bool: True if the user account is disabled, and False otherwise.
        """
        return bool(self._data.get('disabled'))

    @property
    def tokens_valid_after_timestamp(self):
        """Returns the time, in milliseconds since the epoch, before which tokens are invalid.

        Note: this is truncated to 1 second accuracy.

        Returns:
            int: Timestamp in milliseconds since the epoch, truncated to the second.
                 All tokens issued before that time are considered revoked.
        """
        valid_since = self._data.get('validSince')
        if valid_since is not None:
            return 1000 * int(valid_since)
        return None

    @property
    def user_metadata(self):
        """Returns additional metadata associated with this user.

        Returns:
          UserMetadata: A UserMetadata instance. Does not return None.
        """
        def _int_or_none(key):
            if key in self._data:
                return int(self._data[key])
            return None
        return UserMetadata(_int_or_none('createdAt'), _int_or_none('lastLoginAt'))

    @property
    def provider_data(self):
        """Returns a list of UserInfo instances.

        Each object represents an identity from an identity provider that is linked to this user.

        Returns:
          list: A list of UserInfo objects, which may be empty.
        """
        providers = self._data.get('providerUserInfo', [])
        return [ProviderUserInfo(entry) for entry in providers]

    @property
    def custom_claims(self):
        """Returns any custom claims set on this user account.

        Returns:
          dict: A dictionary of claims or None.
        """
        claims = self._data.get('customAttributes')
        if claims:
            parsed = json.loads(claims)
            if parsed != {}:
                return parsed
        return None


class ExportedUserRecord(UserRecord):
    """Contains metadata associated with a user including password hash and salt."""

    def __init__(self, data):
        super(ExportedUserRecord, self).__init__(data)

    @property
    def password_hash(self):
        """The user's password hash as a base64-encoded string.

        If the Firebase Auth hashing algorithm (SCRYPT) was used to create the user account, this
        is the base64-encoded password hash of the user. If a different hashing algorithm was
        used to create this user, as is typical when migrating from another Auth system, this
        is an empty string. If no password is set, this is ``None``.
        """
        return self._data.get('passwordHash')

    @property
    def password_salt(self):
        """The user's password salt as a base64-encoded string.

        If the Firebase Auth hashing algorithm (SCRYPT) was used to create the user account, this
        is the base64-encoded password salt of the user. If a different hashing algorithm was
        used to create this user, as is typical when migrating from another Auth system, this is
        an empty string. If no password is set, this is ``None``.
        """
        return self._data.get('salt')


class ListUsersPage(object):
    """Represents a page of user records exported from a Firebase project.

    Provides methods for traversing the user accounts included in this page, as well as retrieving
    subsequent pages of users. The iterator returned by ``iterate_all()`` can be used to iterate
    through all users in the Firebase project starting from this page.
    """

    def __init__(self, download, page_token, max_results):
        self._download = download
        self._max_results = max_results
        self._current = download(page_token, max_results)

    @property
    def users(self):
        """A list of ``ExportedUserRecord`` instances available in this page."""
        return [ExportedUserRecord(user) for user in self._current.get('users', [])]

    @property
    def next_page_token(self):
        """Page token string for the next page (empty string indicates no more pages)."""
        return self._current.get('nextPageToken', '')

    @property
    def has_next_page(self):
        """A boolean indicating whether more pages are available."""
        return bool(self.next_page_token)

    def get_next_page(self):
        """Retrieves the next page of user accounts, if available.

        Returns:
            ListUsersPage: Next page of users, or None if this is the last page.
        """
        if self.has_next_page:
            return ListUsersPage(self._download, self.next_page_token, self._max_results)
        return None

    def iterate_all(self):
        """Retrieves an iterator for user accounts.

        Returned iterator will iterate through all the user accounts in the Firebase project
        starting from this page. The iterator will never buffer more than one page of users
        in memory at a time.

        Returns:
            iterator: An iterator of ExportedUserRecord instances.
        """
        return _UserIterator(self)


class ProviderUserInfo(UserInfo):
    """Contains metadata regarding how a user is known by a particular identity provider."""

    def __init__(self, data):
        super(ProviderUserInfo, self).__init__()
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument: {0}. Must be a dictionary.'.format(data))
        if not data.get('rawId'):
            raise ValueError('User ID must not be None or empty.')
        self._data = data

    @property
    def uid(self):
        return self._data.get('rawId')

    @property
    def display_name(self):
        return self._data.get('displayName')

    @property
    def email(self):
        return self._data.get('email')

    @property
    def phone_number(self):
        return self._data.get('phoneNumber')

    @property
    def photo_url(self):
        return self._data.get('photoUrl')

    @property
    def provider_id(self):
        return self._data.get('providerId')


class UserProvider(object):
    """Represents a user identity provider that can be associated with a Firebase user.

    One or more providers can be specified in a ``UserImportRecord`` when importing users via
    ``auth.import_users()``.

    Args:
        uid: User's unique ID assigned by the identity provider.
        provider_id: ID of the identity provider. This can be a short domain name or the identifier
            of an OpenID identity provider.
        email: User's email address (optional).
        display_name: User's display name (optional).
        photo_url: User's photo URL (optional).
    """

    def __init__(self, uid, provider_id, email=None, display_name=None, photo_url=None):
        self.uid = uid
        self.provider_id = provider_id
        self.email = _none_to_unspecified(email)
        self.display_name = _none_to_unspecified(display_name)
        self.photo_url = _none_to_unspecified(photo_url)


class UserImportRecord(object):
    """Represents a user account to be imported to Firebase Auth.

    Must specify the ``uid`` field at a minimum. A sequence of ``UserImportRecord`` objects can be
    passed to the ``auth.import_users()`` function, in order to import those users into Firebase
    Auth in bulk. If the ``password_hash`` is set on a user, a hash configuration must be
    specified when calling ``import_users()``.

    Args:
        uid: User's unique ID. Must be a non-empty string not longer than 128 characters.
        email: User's email address (optional).
        email_verified: A boolean indicating whether the user's email has been verified (optional).
        display_name: User's display name (optional).
        phone_number: User's phone number (optional).
        photo_url: User's photo URL (optional).
        disabled: A boolean indicating whether this user account has been disabled (optional).
        metadata: An ``auth.UserMetadata`` instance with additional user metadata (optional).
        provider_data: A list of ``auth.UserProvider`` instances (optional).
        custom_claims: A ``dict`` of custom claims to be set on the user account (optional).
        password_hash: User's password hash as a ``bytes`` sequence (optional).
        password_salt: User's password salt as a ``bytes`` sequence (optional).
    """

    def __init__(self, uid, email=None, email_verified=None, display_name=None, phone_number=None,
                 photo_url=None, disabled=None, metadata=None, provider_data=None,
                 custom_claims=None, password_hash=None, password_salt=None):
        self._uid = uid
        self._email = _none_to_unspecified(email)
        self._email_verified = _none_to_unspecified(email_verified)
        self._display_name = _none_to_unspecified(display_name)
        self._phone_number = _none_to_unspecified(phone_number)
        self._photo_url = _none_to_unspecified(photo_url)
        self._disabled = _none_to_unspecified(disabled)
        self._metadata = _none_to_unspecified(metadata)
        self._provider_data = _none_to_unspecified(provider_data)
        self._custom_claims = _none_to_unspecified(custom_claims)
        self._password_hash = _none_to_unspecified(password_hash)
        self._password_salt = _none_to_unspecified(password_salt)

    def to_dict(self):
        """Returns a dict representation of the user. For internal use only."""
        payload = {
            'localId': _Validator.validate_uid(self._uid),
            'email': _Validator.validate_email(self._email),
            'emailVerified': _Validator.validate_boolean(self._email_verified, 'email_verified'),
            'displayName': _Validator.validate_display_name(self._display_name),
            'phoneNumber': _Validator.validate_phone(self._phone_number),
            'photoUrl': _Validator.validate_photo_url(self._photo_url),
            'disabled': _Validator.validate_boolean(self._disabled, 'disabled'),
        }
        if self._password_hash is not _UNSPECIFIED:
            password_hash = _Validator.validate_bytes(self._password_hash, 'password_hash')
            payload['passwordHash'] = _b64_encode(password_hash)
        if self._password_salt is not _UNSPECIFIED:
            password_salt = _Validator.validate_bytes(self._password_salt, 'password_salt')
            payload['salt'] = _b64_encode(password_salt)
        if self._metadata is not _UNSPECIFIED:
            if not isinstance(self._metadata, UserMetadata):
                raise ValueError('Invalid user metadata instance: {0}.'.format(self._metadata))
            payload['createdAt'] = _Validator.validate_timestamp(_none_to_unspecified(
                self._metadata.creation_timestamp), 'creation_timestamp')
            payload['lastLoginAt'] = _Validator.validate_timestamp(_none_to_unspecified(
                self._metadata.last_sign_in_timestamp), 'last_sign_in_timestamp')
        if self._custom_claims is not _UNSPECIFIED:
            if isinstance(self._custom_claims, dict):
                custom_claims = json.dumps(self._custom_claims)
            else:
                custom_claims = self._custom_claims
            payload['customAttributes'] = _Validator.validate_custom_claims(custom_claims)
        if self._provider_data and self._provider_data is not _UNSPECIFIED:
            if not isinstance(self._provider_data, list):
                raise ValueError('Provider data must be a list.')
            payload['providerUserInfo'] = [encode_user_provider(p) for p in self._provider_data]
        return {k: v for k, v in payload.items() if v is not _UNSPECIFIED}


class UserImportHash(object):
    """Represents a hash algorithm used to hash user passwords.

    An instance of this class must be specified when importing users with passwords via the
    ``auth.import_users()`` API.
    """

    def __init__(self, name, data=None):
        self._name = name
        self._data = data

    def to_dict(self):
        payload = {'hashAlgorithm': self._name}
        if self._data:
            payload.update(self._data)
        return payload

    @classmethod
    def _hmac(cls, name, key):
        data = {
            'signerKey': _b64_encode(_Validator.validate_bytes(key, 'key'))
        }
        return UserImportHash(name, data)

    @classmethod
    def hmac_sha512(cls, key):
        return cls._hmac('HMAC_SHA512', key)

    @classmethod
    def hmac_sha256(cls, key):
        return cls._hmac('HMAC_SHA256', key)

    @classmethod
    def scrypt(cls, key, rounds, memory_cost, salt_separator=None):
        data = {
            'signerKey': _b64_encode(_Validator.validate_bytes(key, 'key')),
            'rounds': _Validator.validate_int(rounds, 'rounds', 1, 8),
            'memoryCost': _Validator.validate_int(memory_cost, 'memory_cost', 1, 14),
        }
        if salt_separator:
            data['saltSeparator'] = _b64_encode(_Validator.validate_bytes(
                salt_separator, 'salt_separator'))
        return UserImportHash('SCRYPT', data)


class ErrorInfo(object):
    """Represents an error encountered while importing a ``UserImportRecord``."""

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
    """Represents the result of a bulk user import operation.

    See ``auth.import_users()`` API for more details.
    """

    def __init__(self, result, total):
        errors = result.get('error', [])
        self._success_count = total - len(errors)
        self._failure_count = len(errors)
        self._errors = [ErrorInfo(err) for err in errors]

    @property
    def success_count(self):
        """Returns the number of users successfully imported."""
        return self._success_count

    @property
    def failure_count(self):
        """Returns the number of users that failed to be imported."""
        return self._failure_count

    @property
    def errors(self):
        """Returns a list of ``auth.ErrorInfo`` instances describing the errors encountered."""
        return self._errors


def encode_user_provider(provider):
    """Encodes a UserProvider into a dict."""
    if not isinstance(provider, UserProvider):
        raise ValueError('Invalid user provider: {0}.'.format(provider))
    payload = {
        'rawId': _Validator.validate_uid(provider.uid),
        'providerId': _Validator.validate_provider_id(provider.provider_id),
        'displayName': _Validator.validate_display_name(provider.display_name),
        'email': _Validator.validate_email(provider.email),
        'photoUrl': _Validator.validate_photo_url(provider.photo_url),
    }
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
        if len(users) > MAX_IMPORT_USERS_SIZE:
            raise ValueError(
                'Users list must not have more than {0} elements.'.format(MAX_IMPORT_USERS_SIZE))
        payload = {'users': [u.to_dict() for u in users]}
        if any(['passwordHash' in u for u in payload['users']]):
            if not hash_alg:
                raise ValueError('Hash is required when at least one user has a password.')
            if not isinstance(hash_alg, UserImportHash):
                raise ValueError('Hash must be an instance of UserImportHash.')
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


class _UserIterator(object):
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
