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

"""Firebase Authentication module.

This module contains functions for minting and verifying JWTs used for
authenticating against Firebase services. It also provides functions for
creating and managing user accounts in Firebase projects.
"""

import os
import re
import time

from google.auth import jwt
from google.auth import transport
import google.oauth2.id_token
import requests
import six
from six.moves import urllib

import firebase_admin
from firebase_admin import credentials
from firebase_admin import utils

# Provided for overriding during tests.
_request = transport.requests.Request()

_AUTH_ATTRIBUTE = '_auth'
GCLOUD_PROJECT_ENV_VAR = 'GCLOUD_PROJECT'


def _get_auth_service(app):
    """Returns an _AuthService instance for an App.

    If the App already has an _AuthService associated with it, simply returns
    it. Otherwise creates a new _AuthService, and adds it to the App before
    returning it.

    Args:
      app: A Firebase App instance (or None to use the default App).

    Returns:
      _AuthService: An _AuthService for the specified App instance.

    Raises:
      ValueError: If the app argument is invalid.
    """
    return utils.get_app_service(app, _AUTH_ATTRIBUTE, _AuthService)


def create_custom_token(uid, developer_claims=None, app=None):
    """Builds and signs a Firebase custom auth token.

    Args:
      uid: ID of the user for whom the token is created.
      developer_claims: A dictionary of claims to be included in the token
          (optional).
      app: An App instance (optional).

    Returns:
      string: A token minted from the input parameters.

    Raises:
      ValueError: If input parameters are invalid.
    """
    token_generator = _get_auth_service(app).token_generator
    return token_generator.create_custom_token(uid, developer_claims)


def verify_id_token(id_token, app=None):
    """Verifies the signature and data for the provided JWT.

    Accepts a signed token string, verifies that it is current, and issued
    to this project, and that it was correctly signed by Google.

    Args:
      id_token: A string of the encoded JWT.
      app: An App instance (optional).

    Returns:
      dict: A dictionary of key-value pairs parsed from the decoded JWT.

    Raises:
      ValueError: If the JWT was found to be invalid, or if the App was not
          initialized with a credentials.Certificate.
    """
    token_generator = _get_auth_service(app).token_generator
    return token_generator.verify_id_token(id_token)


def get_user(uid, app=None):
    """Gets the user data corresponding to the specified user ID.

    Args:
        uid: A user ID string.
        app: An App instance (optional).

    Returns:
        UserRecord: A UserRecord instance.

    Raises:
        ValueError: If the user ID is None, empty or malformed.
        AuthError: If an error occurs while retrieving the user or if the specified user ID
            does not exist.
    """
    user_manager = _get_auth_service(app).user_manager
    return user_manager.get_user(uid=uid)


def get_user_by_email(email, app=None):
    """Gets the user data corresponding to the specified user email.

    Args:
        email: A user email address string.
        app: An App instance (optional).

    Returns:
        UserRecord: A UserRecord instance.

    Raises:
        ValueError: If the email is None, empty or malformed.
        AuthError: If an error occurs while retrieving the user or no user exists by the specified
            email address.
    """
    user_manager = _get_auth_service(app).user_manager
    return user_manager.get_user(email=email)


def get_user_by_phone_number(phone_number, app=None):
    """Gets the user data corresponding to the specified phone number.

    Args:
        phone_number: A phone number string.
        app: An App instance (optional).

    Returns:
        UserRecord: A UserRecord instance.

    Raises:
        ValueError: If the phone number is None, empty or malformed.
        AuthError: If an error occurs while retrieving the user or no user exists by the specified
            phone number.
    """
    user_manager = _get_auth_service(app).user_manager
    return user_manager.get_user(phone_number=phone_number)


def create_user(**kwargs):
    """Creates a new user account with the specified properties.

    Keyword Args:
        uid: User ID to assign to the newly created user (optional).
        display_name: The user's display name (optional).
        email: The user's primary email (optional).
        email_verified: A boolean indicating whether or not the user's primary email is
            verified (optional).
        phone_number: The user's primary phone number (optional).
        photo_url: The user's photo URL (optional).
        password: The user's raw, unhashed password. (optional).
        disabled: A boolean indicating whether or not the user account is disabled (optional).
        app: An App instance (optional).

    Returns:
        UserRecord: A UserRecord instance for the newly created user.

    Raises:
        ValueError: If the specified user properties are invalid.
        AuthError: If an error occurs while creating the user account.
    """
    app = kwargs.pop('app', None)
    user_manager = _get_auth_service(app).user_manager
    uid = user_manager.create_user(**kwargs)
    return user_manager.get_user(uid=uid)


def update_user(uid, **kwargs): # pylint: disable=missing-param-doc
    """Updates an existing user account with the specified properties.

    Args:
        uid: A user ID string.

    Keyword Args:
        display_name: The user's display name (optional). Can be removed by explicitly passing
            None.
        email: The user's primary email (optional).
        email_verified: A boolean indicating whether or not the user's primary email is
            verified (optional).
        phone_number: The user's primary phone number (optional). Can be removed by explicitly
            passing None.
        photo_url: The user's photo URL (optional). Can be removed by explicitly passing None.
        password: The user's raw, unhashed password. (optional).
        disabled: A boolean indicating whether or not the user account is disabled (optional).
        app: An App instance (optional).

    Returns:
        UserRecord: An updated UserRecord instance for the user.

    Raises:
        ValueError: If the specified user ID or properties are invalid.
        AuthError: If an error occurs while updating the user account.
    """
    app = kwargs.pop('app', None)
    user_manager = _get_auth_service(app).user_manager
    user_manager.update_user(uid, **kwargs)
    return user_manager.get_user(uid=uid)


def delete_user(uid, app=None):
    """Deletes the user identified by the specified user ID.

    Args:
        uid: A user ID string.
        app: An App instance (optional).

    Raises:
        ValueError: If the user ID is None, empty or malformed.
        AuthError: If an error occurs while deleting the user account.
    """
    user_manager = _get_auth_service(app).user_manager
    user_manager.delete_user(uid)


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
    def user_metadata(self):
        """Returns additional metadata associated with this user.

        Returns:
          UserMetadata: A UserMetadata instance. Does not return None.
        """
        return UserMetadata(self._data)

    @property
    def provider_data(self):
        """Returns a list of UserInfo instances.

        Each object represents an identity from an identity provider that is linked to this user.

        Returns:
          list: A list of UserInfo objects, which may be empty.
        """
        providers = self._data.get('providerUserInfo', [])
        return [_ProviderUserInfo(entry) for entry in providers]


class UserMetadata(object):
    """Contains additional metadata associated with a user account."""

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument: {0}. Must be a dictionary.'.format(data))
        self._data = data

    @property
    def creation_timestamp(self):
        if 'createdAt' in self._data:
            return int(self._data['createdAt'])
        return None

    @property
    def last_sign_in_timestamp(self):
        if 'lastLoginAt' in self._data:
            return int(self._data['lastLoginAt'])
        return None


class _ProviderUserInfo(UserInfo):
    """Contains metadata regarding how a user is known by a particular identity provider."""

    def __init__(self, data):
        super(_ProviderUserInfo, self).__init__()
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


class AuthError(Exception):
    """Represents an Exception encountered while invoking the Firebase auth API."""

    def __init__(self, code, message, error=None):
        Exception.__init__(self, message)
        self.code = code
        self.detail = error


class _Validator(object):
    """A collectoin of data validation utilities.

    Method provided in this class raise ValueErrors if any validations fail. Normal returns
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


class _UserManager(object):
    """Provides methods for interacting with the Google Identity Toolkit."""

    _ID_TOOLKIT_URL = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/'

    _VALIDATORS = {
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
        'disabled' : 'disabled',
    }

    _REMOVABLE_FIELDS = {
        'displayName' : 'DISPLAY_NAME',
        'photoUrl' : 'PHOTO_URL'
    }

    _INTERNAL_ERROR = 'INTERNAL_ERROR'
    _USER_NOT_FOUND_ERROR = 'USER_NOT_FOUND_ERROR'
    _USER_CREATE_ERROR = 'USER_CREATE_ERROR'
    _USER_UPDATE_ERROR = 'USER_UPDATE_ERROR'
    _USER_DELETE_ERROR = 'USER_DELETE_ERROR'

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
            self._handle_http_error(_UserManager._INTERNAL_ERROR, msg, error)
        else:
            if not response or not response.get('users'):
                raise AuthError(
                    _UserManager._USER_NOT_FOUND_ERROR,
                    'No user record found for the provided {0}: {1}.'.format(key_type, key))
            return UserRecord(response['users'][0])

    def create_user(self, **kwargs):
        """Creates a new user account with the specified properties."""
        payload = self._init_payload('create_user', _UserManager._CREATE_USER_FIELDS, **kwargs)
        self._validate(payload, self._VALIDATORS, 'create user')
        try:
            response = self._request('post', 'signupNewUser', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(
                _UserManager._USER_CREATE_ERROR, 'Failed to create new user.', error)
        else:
            if not response or not response.get('localId'):
                raise AuthError(_UserManager._USER_CREATE_ERROR, 'Failed to create new user.')
            return response.get('localId')

    def update_user(self, uid, **kwargs):
        """Updates an existing user account with the specified properties"""
        _Validator.validate_uid(uid)
        payload = self._init_payload('update_user', _UserManager._UPDATE_USER_FIELDS, **kwargs)
        payload['localId'] = uid

        remove = []
        for key, value in _UserManager._REMOVABLE_FIELDS.items():
            if key in payload and payload[key] is None:
                remove.append(value)
                del payload[key]
        if remove:
            payload['deleteAttribute'] = sorted(remove)
        if 'phoneNumber' in payload and payload['phoneNumber'] is None:
            payload['deleteProvider'] = ['phone']
            del payload['phoneNumber']
        if 'disabled' in payload:
            payload['disableUser'] = payload['disabled']
            del payload['disabled']

        self._validate(payload, self._VALIDATORS, 'update user')
        try:
            response = self._request('post', 'setAccountInfo', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(
                _UserManager._USER_UPDATE_ERROR, 'Failed to update user: {0}.'.format(uid), error)
        else:
            if not response or not response.get('localId'):
                raise AuthError(
                    _UserManager._USER_UPDATE_ERROR, 'Failed to update user: {0}.'.format(uid))

    def delete_user(self, uid):
        """Deletes the user identified by the specified user ID."""
        _Validator.validate_uid(uid)
        try:
            response = self._request('post', 'deleteAccount', json={'localId' : [uid]})
        except requests.exceptions.RequestException as error:
            self._handle_http_error(
                _UserManager._USER_DELETE_ERROR, 'Failed to delete user: {0}.'.format(uid), error)
        else:
            if not response or not response.get('kind'):
                raise AuthError(
                    _UserManager._USER_DELETE_ERROR, 'Failed to delete user: {0}.'.format(uid))

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

    def _handle_http_error(self, code, msg, error):
        if error.response is not None:
            msg += '\nServer response: {0}'.format(error.response.content.decode())
        else:
            msg += '\nReason: {0}'.format(error)
        raise AuthError(code, msg, error)

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
        resp = self._session.request(method, _UserManager._ID_TOOLKIT_URL + urlpath, **kwargs)
        resp.raise_for_status()
        return resp.json()


class _TokenGenerator(object):
    """Generates custom tokens, and validates ID tokens."""

    FIREBASE_CERT_URI = ('https://www.googleapis.com/robot/v1/metadata/x509/'
                         'securetoken@system.gserviceaccount.com')

    ISSUER_PREFIX = 'https://securetoken.google.com/'

    MAX_TOKEN_LIFETIME_SECONDS = 3600  # One Hour, in Seconds
    FIREBASE_AUDIENCE = ('https://identitytoolkit.googleapis.com/google.'
                         'identity.identitytoolkit.v1.IdentityToolkit')

    # Key names we don't allow to appear in the developer_claims.
    _RESERVED_CLAIMS_ = set([
        'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash',
        'exp', 'firebase', 'iat', 'iss', 'jti', 'nbf', 'nonce', 'sub'
    ])


    def __init__(self, app):
        """Initializes FirebaseAuth from a FirebaseApp instance.

        Args:
          app: A FirebaseApp instance.
        """
        self._app = app

    def create_custom_token(self, uid, developer_claims=None):
        """Builds and signs a FirebaseCustomAuthToken.

        Args:
          uid: ID of the user for whom the token is created.
          developer_claims: A dictionary of claims to be included in the token.

        Returns:
          string: A token minted from the input parameters as a byte string.

        Raises:
          ValueError: If input parameters are invalid.
        """
        if not isinstance(self._app.credential, credentials.Certificate):
            raise ValueError(
                'Must initialize Firebase App with a certificate credential '
                'to call create_custom_token().')

        if developer_claims is not None:
            if not isinstance(developer_claims, dict):
                raise ValueError('developer_claims must be a dictionary')

            disallowed_keys = set(developer_claims.keys()
                                 ) & self._RESERVED_CLAIMS_
            if disallowed_keys:
                if len(disallowed_keys) > 1:
                    error_message = ('Developer claims {0} are reserved and '
                                     'cannot be specified.'.format(
                                         ', '.join(disallowed_keys)))
                else:
                    error_message = ('Developer claim {0} is reserved and '
                                     'cannot be specified.'.format(
                                         ', '.join(disallowed_keys)))
                raise ValueError(error_message)

        if not uid or not isinstance(uid, six.string_types) or len(uid) > 128:
            raise ValueError('uid must be a string between 1 and 128 characters.')

        now = int(time.time())
        payload = {
            'iss': self._app.credential.service_account_email,
            'sub': self._app.credential.service_account_email,
            'aud': self.FIREBASE_AUDIENCE,
            'uid': uid,
            'iat': now,
            'exp': now + self.MAX_TOKEN_LIFETIME_SECONDS,
        }

        if developer_claims is not None:
            payload['claims'] = developer_claims

        return jwt.encode(self._app.credential.signer, payload)

    def verify_id_token(self, id_token):
        """Verifies the signature and data for the provided JWT.

        Accepts a signed token string, verifies that is the current, and issued
        to this project, and that it was correctly signed by Google.

        Args:
          id_token: A string of the encoded JWT.

        Returns:
          dict: A dictionary of key-value pairs parsed from the decoded JWT.

        Raises:
          ValueError: The JWT was found to be invalid, or the app was not initialized with a
              credentials.Certificate instance.
        """
        if not id_token:
            raise ValueError('Illegal ID token provided: {0}. ID token must be a non-empty '
                             'string.'.format(id_token))

        if isinstance(id_token, six.text_type):
            id_token = id_token.encode('ascii')
        if not isinstance(id_token, six.binary_type):
            raise ValueError('Illegal ID token provided: {0}. ID token must be a non-empty '
                             'string.'.format(id_token))

        try:
            project_id = self._app.credential.project_id
            if project_id is None:
                project_id = os.environ.get(GCLOUD_PROJECT_ENV_VAR)
        except AttributeError:
            project_id = os.environ.get(GCLOUD_PROJECT_ENV_VAR)

        if not project_id:
            raise ValueError('Failed to ascertain project ID from the credential or the '
                             'environment. Must initialize app with a credentials.Certificate or '
                             'set your Firebase project ID as the GCLOUD_PROJECT environment '
                             'variable to call verify_id_token().')

        header = jwt.decode_header(id_token)
        payload = jwt.decode(id_token, verify=False)
        issuer = payload.get('iss')
        audience = payload.get('aud')
        subject = payload.get('sub')
        expected_issuer = self.ISSUER_PREFIX + project_id

        project_id_match_msg = ('Make sure the ID token comes from the same'
                                ' Firebase project as the service account used'
                                ' to authenticate this SDK.')
        verify_id_token_msg = (
            'See https://firebase.google.com/docs/auth/admin/verify-id-tokens'
            ' for details on how to retrieve an ID token.')
        error_message = None
        if not header.get('kid'):
            if audience == self.FIREBASE_AUDIENCE:
                error_message = ('verify_id_token() expects an ID token, but '
                                 'was given a custom token.')
            elif header.get('alg') == 'HS256' and payload.get(
                    'v') is 0 and 'uid' in payload.get('d', {}):
                error_message = ('verify_id_token() expects an ID token, but '
                                 'was given a legacy custom token.')
            else:
                error_message = 'Firebase ID token has no "kid" claim.'
        elif header.get('alg') != 'RS256':
            error_message = ('Firebase ID token has incorrect algorithm. '
                             'Expected "RS256" but got "{0}". {1}'.format(
                                 header.get('alg'), verify_id_token_msg))
        elif audience != project_id:
            error_message = (
                'Firebase ID token has incorrect "aud" (audience) claim. '
                'Expected "{0}" but got "{1}". {2} {3}'.format(
                    project_id, audience, project_id_match_msg,
                    verify_id_token_msg))
        elif issuer != expected_issuer:
            error_message = ('Firebase ID token has incorrect "iss" (issuer) '
                             'claim. Expected "{0}" but got "{1}". {2} {3}'
                             .format(expected_issuer, issuer,
                                     project_id_match_msg,
                                     verify_id_token_msg))
        elif subject is None or not isinstance(subject, six.string_types):
            error_message = ('Firebase ID token has no "sub" (subject) '
                             'claim. ') + verify_id_token_msg
        elif not subject:
            error_message = ('Firebase ID token has an empty string "sub" '
                             '(subject) claim. ') + verify_id_token_msg
        elif len(subject) > 128:
            error_message = ('Firebase ID token has a "sub" (subject) '
                             'claim longer than 128 '
                             'characters. ') + verify_id_token_msg

        if error_message:
            raise ValueError(error_message)

        verified_claims = google.oauth2.id_token.verify_firebase_token(
            id_token,
            request=_request,
            audience=project_id)
        verified_claims['uid'] = verified_claims['sub']
        return verified_claims


class _AuthService(object):

    def __init__(self, app):
        self._token_generator = _TokenGenerator(app)
        self._user_manager = _UserManager(app)

    @property
    def token_generator(self):
        return self._token_generator

    @property
    def user_manager(self):
        return self._user_manager
