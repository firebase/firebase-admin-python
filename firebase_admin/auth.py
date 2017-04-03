"""Firebase Authentication module.

This module contains helper methods and utilities for minting and verifying
JWTs used for authenticating against Firebase services.
"""

import os
import threading
import time

from oauth2client import crypt
import six

import firebase_admin
from firebase_admin import credentials
from firebase_admin import jwt

_auth_lock = threading.Lock()

"""Provided for overriding during tests. (OAuth2 client uses a caching-enabled
   HTTP client internally if none provided)
"""
_http = None

_AUTH_ATTRIBUTE = '_auth'
GCLOUD_PROJECT_ENV_VAR = 'GCLOUD_PROJECT'


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


def _get_token_generator(app):
    """Returns a _TokenGenerator instance for an App.

    If the App already has a _TokenGenerator associated with it, simply returns
    it. Otherwise creates a new _TokenGenerator, and adds it to the App before
    returning it.

    Args:
      app: A Firebase App instance (or None to use the default App).

    Returns:
      _TokenGenerator: A _TokenGenerator for the specified App instance.

    Raises:
      ValueError: If the app argument is invalid.
    """
    app = _get_initialized_app(app)
    with _auth_lock:
        if not hasattr(app, _AUTH_ATTRIBUTE):
            setattr(app, _AUTH_ATTRIBUTE, _TokenGenerator(app))
        return getattr(app, _AUTH_ATTRIBUTE)


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
    token_generator = _get_token_generator(app)
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
      ValueError: If the input parameters are invalid, or if the App was not
          initialized with a credentials.Certificate.
      AppIdenityError: The JWT was found to be invalid, the message will contain details.
    """
    token_generator = _get_token_generator(app)
    return token_generator.verify_id_token(id_token)


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

        return jwt.encode(payload, self._app.credential.signer)

    def verify_id_token(self, id_token):
        """Verifies the signature and data for the provided JWT.

        Accepts a signed token string, verifies that is the current, and issued
        to this project, and that it was correctly signed by Google.

        Args:
          id_token: A string of the encoded JWT.

        Returns:
          dict: A dictionary of key-value pairs parsed from the decoded JWT.

        Raises:
          ValueError: The app was not initialized with a credentials.Certificate instance.
          AppIdenityError: The JWT was found to be invalid, the message will contain details.
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
        except AttributeError:
            project_id = os.environ.get(GCLOUD_PROJECT_ENV_VAR)

        if not project_id:
            raise ValueError('Must initialize app with a credentials.Certificate '
                             'or set your Firebase project ID as the '
                             'GCLOUD_PROJECT environment variable to call '
                             'verify_id_token().')

        header, payload = jwt.decode(id_token)
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
            raise crypt.AppIdentityError(error_message)

        verified_claims = jwt.verify_id_token(
            id_token,
            self.FIREBASE_CERT_URI,
            audience=project_id,
            kid=header.get('kid'),
            http=_http)
        verified_claims['uid'] = verified_claims['sub']
        return verified_claims
