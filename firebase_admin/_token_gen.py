"""Firebase token minting and validation sub module."""
import time

import six
from google.auth import jwt
from google.auth import transport
import google.oauth2.id_token

from firebase_admin import credentials

# Provided for overriding during tests.
_request = transport.requests.Request()


class TokenGenerator(object):
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

        project_id = self._app.project_id
        if not project_id:
            raise ValueError('Failed to ascertain project ID from the credential or the '
                             'environment. Project ID is required to call verify_id_token(). '
                             'Initialize the app with a credentials.Certificate or set '
                             'your Firebase project ID as an app option. Alternatively '
                             'set the GCLOUD_PROJECT environment variable.')

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