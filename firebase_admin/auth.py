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

This module contains helper methods and utilities for minting and verifying
JWTs used for authenticating against Firebase services.
"""

import os
import re
import threading
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

_auth_lock = threading.Lock()

"""Provided for overriding during tests."""
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
    """Get the user data corresponding to the specified user ID.

    Args:
        uid: A user ID string.
        app: An App instance (optional).

    Returns:
        UserRecord: A UserRecord instance.

    Raises:
        ValueError: If the user ID string is not a non-empty string.
        FirebaseAuthError: If an error occurs while retrieving the user or if the specified
            user ID does not exist.
    """
    user_manager = _get_auth_service(app).user_manager
    return user_manager.get_user(uid)


def create_user(properties=None, app=None):
    """Creates a new user account with the specified properties.

    Args:
        properties: A dictionary containing user attributes (optional).
        app: An App instance (optional).

    Returns:
        UserRecord: A UserRecord instance for the newly created user.

    Raises:
        ValueError: If the specified user properties are invalid.
        FirebaseAuthError: If an error occurs while creating the user account.
    """
    user_manager = _get_auth_service(app).user_manager
    uid = user_manager.create_user(properties)
    return get_user(uid)


class UserInfo(object):
    """A collection of standard profile information for a user.

    Used to expose profile information returned by an identity provider.
    """

    @property
    def uid(self):
        raise NotImplementedError

    @property
    def display_name(self):
        raise NotImplementedError

    @property
    def email(self):
        raise NotImplementedError

    @property
    def photo_url(self):
        raise NotImplementedError

    @property
    def provider_id(self):
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
        return self._data.get('localId')

    @property
    def display_name(self):
        return self._data.get('displayName')

    @property
    def email(self):
        return self._data.get('email')

    @property
    def photo_url(self):
        return self._data.get('photoUrl')

    @property
    def provider_id(self):
        return 'firebase'

    @property
    def email_verified(self):
        return bool(self._data.get('emailVerified'))

    @property
    def disabled(self):
        return bool(self._data.get('disabled'))

    @property
    def user_metadata(self):
        return UserMetadata(self._data)

    @property
    def provider_data(self):
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
    def photo_url(self):
        return self._data.get('photoUrl')

    @property
    def provider_id(self):
        return self._data.get('providerId')


class FirebaseAuthError(Exception):
    """Represents an Exception encountered while invoking the Firebase auth API."""

    def __init__(self, code, message, error=None):
        Exception.__init__(self, message)
        self.code = code
        self.detail = error


class _Validator(object):
    """A collectoin of data validation utilities."""

    EMAIL_PATTERN = re.compile('^[^@]+@[^@]+$')

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
        elif not cls.EMAIL_PATTERN.match(email):
            raise ValueError('Malformed email address string: "{0}".'.format(email))

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


class _UserManager(object):
    """Provides methods for interacting with the Google Identity Toolkit."""

    _ID_TOOLKIT_URL = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/'

    _CREATE_USER_ATTRIBUTES = {
        'disabled' : _Validator.validate_disabled,
        'displayName' : _Validator.validate_display_name,
        'email' : _Validator.validate_email,
        'emailVerified' : _Validator.validate_email_verified,
        'localId' : _Validator.validate_uid,
        'photoUrl' : _Validator.validate_photo_url,
        'password' : _Validator.validate_password,
    }

    _INTERNAL_ERROR = 'INTERNAL_ERROR'
    _USER_NOT_FOUND_ERROR = 'USER_NOT_FOUND_ERROR'
    _USER_CREATE_ERROR = 'USER_CREATE_ERROR'


    def __init__(self, app):
        g_credential = app.credential.get_credential()
        session = transport.requests.AuthorizedSession(g_credential)
        version_header = 'Python/Admin/{0}'.format(firebase_admin.__version__)
        session.headers.update({'X-Client-Version': version_header})
        self._session = session

    def get_user(self, uid):
        if not isinstance(uid, six.string_types) or not uid:
            raise ValueError(
                'Invalid user ID: "{0}". User ID must be a non-empty string.'.format(uid))

        payload = {'localId' : [uid]}
        try:
            response = self._request('post', 'getAccountInfo', json=payload)
            if not response or not response.get('users'):
                msg = 'No user record found for the provided user ID: {0}'.format(uid)
                raise FirebaseAuthError(_UserManager._USER_NOT_FOUND_ERROR, msg)
            return UserRecord(response['users'][0])
        except requests.exceptions.RequestException as error:
            msg = 'Error while retrieving user with ID: {0}'.format(uid)
            raise FirebaseAuthError(_UserManager._INTERNAL_ERROR, msg, error)

    def create_user(self, properties=None):
        """Creates a new user account with the specified properties."""
        if properties is not None and not isinstance(properties, dict):
            raise ValueError(
                'Invalid user properties: "{0}". Properties must be a dictionary or None.')
        if properties is None:
            properties = {}

        payload = dict(properties)
        if 'uid' in payload:
            payload['localId'] = payload['uid']
            del payload['uid']
        self._validate(payload, self._CREATE_USER_ATTRIBUTES, 'create user')
        try:
            response = self._request('post', 'signupNewUser', json=payload)
            if not response or not response.get('localId'):
                raise FirebaseAuthError(
                    _UserManager._USER_CREATE_ERROR, 'Failed to create new user')
            return response.get('localId')
        except requests.exceptions.RequestException as error:
            raise FirebaseAuthError(
                _UserManager._USER_CREATE_ERROR, 'Failed to create new user', error)

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
          string: A token string minted from the input parameters.

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
