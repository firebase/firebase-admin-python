"""Firebase token minting and validation sub module."""
import datetime
import time

import requests
import six
from google.auth import jwt
from google.auth import transport
import google.oauth2.id_token

from firebase_admin import credentials

# Provided for overriding during tests.
_request = transport.requests.Request()


ID_TOOLKIT_URL = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/'
FIREBASE_ID_TOKEN_CERT_URI = ('https://www.googleapis.com/robot/v1/metadata/x509/'
                              'securetoken@system.gserviceaccount.com')
FIREBASE_COOKIE_CERT_URI = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys'
ISSUER_PREFIX = 'https://securetoken.google.com/'

MAX_TOKEN_LIFETIME_SECONDS = datetime.timedelta(hours=1).total_seconds()
FIREBASE_AUDIENCE = ('https://identitytoolkit.googleapis.com/google.'
                     'identity.identitytoolkit.v1.IdentityToolkit')

# Key names we don't allow to appear in the developer_claims.
RESERVED_CLAIMS = set([
    'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash',
    'exp', 'firebase', 'iat', 'iss', 'jti', 'nbf', 'nonce', 'sub'
])

MIN_SESSION_COOKIE_DURATION_SECONDS = datetime.timedelta(minutes=5).total_seconds()
MAX_SESSION_COOKIE_DURATION_SECONDS = datetime.timedelta(days=14).total_seconds()

COOKIE_CREATE_ERROR = 'COOKIE_CREATE_ERROR'


class ApiCallError(Exception):
    """Represents an Exception encountered while invoking the ID toolkit API."""

    def __init__(self, code, message, error=None):
        Exception.__init__(self, message)
        self.code = code
        self.detail = error


class TokenGenerator(object):
    """Generates custom tokens, and validates ID tokens."""

    def __init__(self, app, client):
        self._app = app
        self._client = client
        self._id_token_verifier = JWTVerifier(
            project_id=app.project_id, short_name='ID token',
            operation='verify_id_token()',
            doc_url='https://firebase.google.com/docs/auth/admin/verify-id-tokens',
            cert_url=FIREBASE_ID_TOKEN_CERT_URI)
        self._cookie_verifier = JWTVerifier(
            project_id=app.project_id, short_name='session cookie',
            operation='verify_session_cookie()',
            doc_url='https://firebase.google.com/docs/auth/admin/verify-id-tokens',
            cert_url=FIREBASE_COOKIE_CERT_URI)

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

            disallowed_keys = set(developer_claims.keys()) & RESERVED_CLAIMS
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
            'aud': FIREBASE_AUDIENCE,
            'uid': uid,
            'iat': now,
            'exp': now + MAX_TOKEN_LIFETIME_SECONDS,
        }

        if developer_claims is not None:
            payload['claims'] = developer_claims
        return jwt.encode(self._app.credential.signer, payload)

    def verify_id_token(self, id_token):
        return self._id_token_verifier.verify(id_token)

    def verify_session_cookie(self, cookie):
        return self._cookie_verifier.verify(cookie)

    def create_session_cookie(self, id_token, expires_in):
        if not id_token:
            raise ValueError('Illegal ID token provided: {0}. ID token must be a non-empty '
                             'string.'.format(id_token))
        if isinstance(id_token, six.text_type):
            id_token = id_token.encode('ascii')
        if not isinstance(id_token, six.binary_type):
            raise ValueError('Illegal ID token provided: {0}. ID token must be a non-empty '
                             'string.'.format(id_token))

        if isinstance(expires_in, datetime.timedelta):
            expires_in = expires_in.total_seconds()
        if isinstance(expires_in, bool) or not isinstance(expires_in, int):
            raise ValueError('Illegal expiry duration: {0}.'.format(expires_in))
        if expires_in < MIN_SESSION_COOKIE_DURATION_SECONDS:
            raise ValueError('Illegal expiry duration: {0}. Duration must be at least {1} '
                             'seconds.'.format(expires_in, MIN_SESSION_COOKIE_DURATION_SECONDS))
        if expires_in > MAX_SESSION_COOKIE_DURATION_SECONDS:
            raise ValueError('Illegal expiry duration: {0}. Duration must be at most {1} '
                             'seconds.'.format(expires_in, MAX_SESSION_COOKIE_DURATION_SECONDS))

        payload = {
            'idToken': id_token,
            'validDuration': expires_in,
        }
        try:
            response = self._client.request('post', 'createSessionCookie', json=payload)
        except requests.exceptions.RequestException as error:
            self._handle_http_error(COOKIE_CREATE_ERROR, 'Failed to create session cookie', error)
        else:
            if not response or not response.get('sessionCookie'):
                raise ApiCallError(COOKIE_CREATE_ERROR, 'Failed to create session cookie.')
            return response.get('sessionCookie')

    def _handle_http_error(self, code, msg, error):
        if error.response is not None:
            msg += '\nServer response: {0}'.format(error.response.content.decode())
        else:
            msg += '\nReason: {0}'.format(error)
        raise ApiCallError(code, msg, error)


class JWTVerifier(object):

    def __init__(self, **kwargs):
        self.project_id = kwargs.pop('project_id')
        self.short_name = kwargs.pop('short_name')
        self.operation = kwargs.pop('operation')
        self.url = kwargs.pop('doc_url')
        self.cert_url = kwargs.pop('cert_url')

    def verify(self, token):
        """Verifies the signature and data for the provided JWT.

        Accepts a signed token string, verifies that is the current, and issued
        to this project, and that it was correctly signed by Google.

        Args:
          token: A string of the encoded JWT.

        Returns:
          dict: A dictionary of key-value pairs parsed from the decoded JWT.

        Raises:
          ValueError: The JWT was found to be invalid, or the app was not initialized with a
              credentials.Certificate instance.
        """
        if not token:
            raise ValueError(
                'Illegal {0} provided: {1}. {0} must be a non-empty '
                'string.'.format(self.short_name, token))
        if isinstance(token, six.text_type):
            token = token.encode('ascii')
        if not isinstance(token, six.binary_type):
            raise ValueError(
                'Illegal {0} provided: {1}. {0} must be a non-empty '
                'string.'.format(self.short_name, token))

        if not self.project_id:
            raise ValueError(
                'Failed to ascertain project ID from the credential or the environment. Project '
                'ID is required to call {0}. Initialize the app with a credentials.Certificate '
                'or set your Firebase project ID as an app option. Alternatively set the '
                'GCLOUD_PROJECT environment variable.'.format(self.operation))

        header = jwt.decode_header(token)
        payload = jwt.decode(token, verify=False)
        issuer = payload.get('iss')
        audience = payload.get('aud')
        subject = payload.get('sub')
        expected_issuer = ISSUER_PREFIX + self.project_id

        project_id_match_msg = (
            'Make sure the {0} comes from the same Firebase project as the service account used '
            'to authenticate this SDK.'.format(self.short_name))
        verify_id_token_msg = (
            'See {0} for details on how to retrieve an {1}.'.format(self.url, self.short_name))

        error_message = None
        if not header.get('kid'):
            if audience == FIREBASE_AUDIENCE:
                error_message = (
                    '{0} expects an ID token, but was given a custom token.'.format(self.operation))
            elif header.get('alg') == 'HS256' and payload.get(
                    'v') is 0 and 'uid' in payload.get('d', {}):
                error_message = (
                    '{0} expects an ID token, but was given a legacy custom '
                    'token.'.format(self.operation))
            else:
                error_message = 'Firebase {0} has no "kid" claim.'.format(self.short_name)
        elif header.get('alg') != 'RS256':
            error_message = (
                'Firebase {0} has incorrect algorithm. Expected "RS256" but got '
                '"{1}". {2}'.format(self.short_name, header.get('alg'), verify_id_token_msg))
        elif audience != self.project_id:
            error_message = (
                'Firebase {0} has incorrect "aud" (audience) claim. Expected "{1}" but '
                'got "{2}". {3} {4}'.format(self.short_name, self.project_id, audience,
                                            project_id_match_msg, verify_id_token_msg))
        elif issuer != expected_issuer:
            error_message = (
                'Firebase {0} has incorrect "iss" (issuer) claim. Expected "{1}" but '
                'got "{2}". {3} {4}'.format(self.short_name, expected_issuer, issuer,
                                            project_id_match_msg, verify_id_token_msg))
        elif subject is None or not isinstance(subject, six.string_types):
            error_message = (
                'Firebase {0} has no "sub" (subject) claim. '
                '{1}'.format(self.short_name, verify_id_token_msg))
        elif not subject:
            error_message = (
                'Firebase {0} has an empty string "sub" (subject) claim. '
                '{1}'.format(self.short_name, verify_id_token_msg))
        elif len(subject) > 128:
            error_message = (
                'Firebase {0} has a "sub" (subject) claim longer than 128 characters. '
                '{1}'.format(self.short_name, verify_id_token_msg))

        if error_message:
            raise ValueError(error_message)

        verified_claims = google.oauth2.id_token.verify_token(
            token,
            request=_request,
            audience=self.project_id,
            certs_url=self.cert_url)
        verified_claims['uid'] = verified_claims['sub']
        return verified_claims
