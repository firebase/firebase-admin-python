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

import json
import time

from google.auth import transport

import firebase_admin
from firebase_admin import _token_gen
from firebase_admin import _user_mgt
from firebase_admin import _utils


_AUTH_ATTRIBUTE = '_auth'
_ID_TOKEN_REVOKED = 'ID_TOKEN_REVOKED'
_SESSION_COOKIE_REVOKED = 'SESSION_COOKIE_REVOKED'


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
    return _utils.get_app_service(app, _AUTH_ATTRIBUTE, _AuthService)


def create_custom_token(uid, developer_claims=None, app=None):
    """Builds and signs a Firebase custom auth token.

    Args:
        uid: ID of the user for whom the token is created.
        developer_claims: A dictionary of claims to be included in the token
            (optional).
        app: An App instance (optional).

    Returns:
        bytes: A token minted from the input parameters.

    Raises:
        ValueError: If input parameters are invalid.
    """
    token_generator = _get_auth_service(app).token_generator
    return token_generator.create_custom_token(uid, developer_claims)


def verify_id_token(id_token, app=None, check_revoked=False):
    """Verifies the signature and data for the provided JWT.

    Accepts a signed token string, verifies that it is current, and issued
    to this project, and that it was correctly signed by Google.

    Args:
        id_token: A string of the encoded JWT.
        app: An App instance (optional).
        check_revoked: Boolean, If true, checks whether the token has been revoked (optional).

    Returns:
        dict: A dictionary of key-value pairs parsed from the decoded JWT.

    Raises:
        ValueError: If the JWT was found to be invalid, or if the App's project ID cannot
            be determined.
        AuthError: If check_revoked is requested and the token was revoked.
    """
    if not isinstance(check_revoked, bool):
        # guard against accidental wrong assignment.
        raise ValueError('Illegal check_revoked argument. Argument must be of type '
                         ' bool, but given "{0}".'.format(type(app)))
    token_verifier = _get_auth_service(app).token_verifier
    verified_claims = token_verifier.verify_id_token(id_token)
    if check_revoked:
        _check_jwt_revoked(verified_claims, _ID_TOKEN_REVOKED, 'ID token', app)
    return verified_claims

def create_session_cookie(id_token, expires_in, app=None):
    """Creates a new Firebase session cookie from the given ID token and options.

    The returned JWT can be set as a server-side session cookie with a custom cookie policy.

    Args:
        id_token: The Firebase ID token to exchange for a session cookie.
        expires_in: Duration until the cookie is expired. This can be specified
            as a numeric seconds value or a ``datetime.timedelta`` instance.
        app: An App instance (optional).

    Returns:
        bytes: A session cookie generated from the input parameters.

    Raises:
        ValueError: If input parameters are invalid.
        AuthError: If an error occurs while creating the cookie.
    """
    token_generator = _get_auth_service(app).token_generator
    try:
        return token_generator.create_session_cookie(id_token, expires_in)
    except _token_gen.ApiCallError as error:
        raise AuthError(error.code, str(error), error.detail)

def verify_session_cookie(session_cookie, check_revoked=False, app=None):
    """Verifies a Firebase session cookie.

    Accepts a session cookie string, verifies that it is current, and issued
    to this project, and that it was correctly signed by Google.

    Args:
        session_cookie: A session cookie string to verify.
        check_revoked: Boolean, if true, checks whether the cookie has been revoked (optional).
        app: An App instance (optional).

    Returns:
        dict: A dictionary of key-value pairs parsed from the decoded JWT.

    Raises:
        ValueError: If the cookie was found to be invalid, or if the App's project ID cannot
            be determined.
        AuthError: If check_revoked is requested and the cookie was revoked.
    """
    token_verifier = _get_auth_service(app).token_verifier
    verified_claims = token_verifier.verify_session_cookie(session_cookie)
    if check_revoked:
        _check_jwt_revoked(verified_claims, _SESSION_COOKIE_REVOKED, 'session cookie', app)
    return verified_claims

def revoke_refresh_tokens(uid, app=None):
    """Revokes all refresh tokens for an existing user.

    revoke_refresh_tokens updates the user's tokens_valid_after_timestamp to the current UTC
    in seconds since the epoch. It is important that the server on which this is called has its
    clock set correctly and synchronized.

    While this revokes all sessions for a specified user and disables any new ID tokens for
    existing sessions from getting minted, existing ID tokens may remain active until their
    natural expiration (one hour). To verify that ID tokens are revoked, use
    ``verify_id_token(idToken, check_revoked=True)``.
    """
    user_manager = _get_auth_service(app).user_manager
    user_manager.update_user(uid, valid_since=int(time.time()))

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
    try:
        response = user_manager.get_user(uid=uid)
        return UserRecord(response)
    except _user_mgt.ApiCallError as error:
        raise AuthError(error.code, str(error), error.detail)

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
    try:
        response = user_manager.get_user(email=email)
        return UserRecord(response)
    except _user_mgt.ApiCallError as error:
        raise AuthError(error.code, str(error), error.detail)


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
    try:
        response = user_manager.get_user(phone_number=phone_number)
        return UserRecord(response)
    except _user_mgt.ApiCallError as error:
        raise AuthError(error.code, str(error), error.detail)

def list_users(page_token=None, max_results=_user_mgt.MAX_LIST_USERS_RESULTS, app=None):
    """Retrieves a page of user accounts from a Firebase project.

    The ``page_token`` argument governs the starting point of the page. The ``max_results``
    argument governs the maximum number of user accounts that may be included in the returned page.
    This function never returns None. If there are no user accounts in the Firebase project, this
    returns an empty page.

    Args:
        page_token: A non-empty page token string, which indicates the starting point of the page
            (optional). Defaults to ``None``, which will retrieve the first page of users.
        max_results: A positive integer indicating the maximum number of users to include in the
            returned page (optional). Defaults to 1000, which is also the maximum number allowed.
        app: An App instance (optional).

    Returns:
        ListUsersPage: A ListUsersPage instance.

    Raises:
        ValueError: If max_results or page_token are invalid.
        AuthError: If an error occurs while retrieving the user accounts.
    """
    user_manager = _get_auth_service(app).user_manager
    def download(page_token, max_results):
        try:
            return user_manager.list_users(page_token, max_results)
        except _user_mgt.ApiCallError as error:
            raise AuthError(error.code, str(error), error.detail)
    return ListUsersPage(download, page_token, max_results)


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
    try:
        uid = user_manager.create_user(**kwargs)
        return UserRecord(user_manager.get_user(uid=uid))
    except _user_mgt.ApiCallError as error:
        raise AuthError(error.code, str(error), error.detail)


def update_user(uid, **kwargs):
    """Updates an existing user account with the specified properties.

    Args:
        uid: A user ID string.
        kwargs: A series of keyword arguments (optional).

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
        custom_claims: A dictionary or a JSON string contining the custom claims to be set on the
            user account (optional).
        valid_since: An integer signifying the seconds since the epoch. This field is set by
            ``revoke_refresh_tokens`` and it is discouraged to set this field directly.

    Returns:
        UserRecord: An updated UserRecord instance for the user.

    Raises:
        ValueError: If the specified user ID or properties are invalid.
        AuthError: If an error occurs while updating the user account.
    """
    app = kwargs.pop('app', None)
    user_manager = _get_auth_service(app).user_manager
    try:
        user_manager.update_user(uid, **kwargs)
        return UserRecord(user_manager.get_user(uid=uid))
    except _user_mgt.ApiCallError as error:
        raise AuthError(error.code, str(error), error.detail)

def set_custom_user_claims(uid, custom_claims, app=None):
    """Sets additional claims on an existing user account.

    Custom claims set via this function can be used to define user roles and privilege levels.
    These claims propagate to all the devices where the user is already signed in (after token
    expiration or when token refresh is forced), and next time the user signs in. The claims
    can be accessed via the user's ID token JWT. If a reserved OIDC claim is specified (sub, iat,
    iss, etc), an error is thrown. Claims payload must also not be larger then 1000 characters
    when serialized into a JSON string.

    Args:
        uid: A user ID string.
        custom_claims: A dictionary or a JSON string of custom claims. Pass None to unset any
            claims set previously.
        app: An App instance (optional).

    Raises:
        ValueError: If the specified user ID or the custom claims are invalid.
        AuthError: If an error occurs while updating the user account.
    """
    user_manager = _get_auth_service(app).user_manager
    try:
        user_manager.update_user(uid, custom_claims=custom_claims)
    except _user_mgt.ApiCallError as error:
        raise AuthError(error.code, str(error), error.detail)

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
    try:
        user_manager.delete_user(uid)
    except _user_mgt.ApiCallError as error:
        raise AuthError(error.code, str(error), error.detail)

def _check_jwt_revoked(verified_claims, error_code, label, app):
    user = get_user(verified_claims.get('uid'), app=app)
    if verified_claims.get('iat') * 1000 < user.tokens_valid_after_timestamp:
        raise AuthError(error_code, 'The Firebase {0} has been revoked.'.format(label))


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


class UserMetadata(object):
    """Contains additional metadata associated with a user account."""

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument: {0}. Must be a dictionary.'.format(data))
        self._data = data

    @property
    def creation_timestamp(self):
        """ Creation timestamp in milliseconds since the epoch.

        Returns:
          integer: The user creation timestamp in milliseconds since the epoch.
        """
        if 'createdAt' in self._data:
            return int(self._data['createdAt'])
        return None

    @property
    def last_sign_in_timestamp(self):
        """ Last sign in timestamp in milliseconds since the epoch.

        Returns:
          integer: The last sign in timestamp in milliseconds since the epoch.
        """
        if 'lastLoginAt' in self._data:
            return int(self._data['lastLoginAt'])
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
        return _user_mgt.UserIterator(self)


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


class _AuthService(object):
    """Firebase Authentication service."""

    def __init__(self, app):
        client = _AuthHTTPClient(app)
        self._token_generator = _token_gen.TokenGenerator(app, client)
        self._token_verifier = _token_gen.TokenVerifier(app)
        self._user_manager = _user_mgt.UserManager(client)

    @property
    def token_generator(self):
        return self._token_generator

    @property
    def token_verifier(self):
        return self._token_verifier

    @property
    def user_manager(self):
        return self._user_manager


class _AuthHTTPClient(object):
    """An HTTP client for making REST calls to the identity toolkit service."""

    ID_TOOLKIT_URL = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/'

    def __init__(self, app):
        g_credential = app.credential.get_credential()
        session = transport.requests.AuthorizedSession(g_credential)
        version_header = 'Python/Admin/{0}'.format(firebase_admin.__version__)
        session.headers.update({'X-Client-Version': version_header})
        self.session = session

    def request(self, method, urlpath, **kwargs):
        """Makes an HTTP call using the Python requests library.

        Args:
            method: HTTP method name as a string (e.g. get, post).
            urlpath: URL path of the endpoint. This will be appended to the server's base URL.
            kwargs: An additional set of keyword arguments to be passed into requests API
              (e.g. json, params).

        Returns:
            dict: The parsed JSON response.
        """
        resp = self.session.request(method, self.ID_TOOLKIT_URL + urlpath, **kwargs)
        resp.raise_for_status()
        return resp.json()
