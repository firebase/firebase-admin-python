# Copyright 2026 Google Inc.
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

"""Firebase Phone Number Verification (FPNV) module."""
from typing import Any, Dict

import jwt
from jwt import PyJWKClient, InvalidTokenError, DecodeError, InvalidSignatureError, \
    InvalidAudienceError, InvalidIssuerError, ExpiredSignatureError

from firebase_admin import _utils
from firebase_admin.exceptions import InvalidArgumentError

_FPNV_ATTRIBUTE = '_fpnv'
_FPNV_JWKS_URL = 'https://fpnv.googleapis.com/v1beta/jwks'
_FPNV_ISSUER = 'https://fpnv.googleapis.com/projects/'
_ALGORITHM_ES256 = 'ES256'


def client(app=None):
    """Returns an instance of the FPNV service for the specified app.

    Args:
        app: An App instance (optional).

    Returns:
        FpnvClient: A FpnvClient instance.

    Raises:
        ValueError: If the app is not a valid App instance.
    """
    return _utils.get_app_service(app, _FPNV_ATTRIBUTE, FpnvClient)


class FpnvToken(dict):
    """Represents a verified FPNV token.

    This class behaves like a dictionary, allowing access to the decoded claims.
    It also provides convenience properties for common claims.
    """

    def __init__(self, claims):
        super(FpnvToken, self).__init__(claims)

    @property
    def phone_number(self):
        """Returns the phone number associated with the token."""
        return self.get('sub')

    @property
    def issuer(self):
        """Returns the issuer of the token."""
        return self.get('iss')

    @property
    def audience(self):
        """Returns the audience of the token."""
        return self.get('aud')

    @property
    def sub(self):
        """Returns the sub (subject) of the token, which is the phone number."""
        return self.get('sub')

    # TODO: ADD ALL


class FpnvClient:
    """The client for the Firebase Phone Number Verification service."""
    _project_id = None

    def __init__(self, app):
        """Initializes the FpnvClient.

        Args:
            app: A firebase_admin.App instance.

        Raises:
            ValueError: If the app is invalid or lacks a project ID.
        """
        self._project_id = app.project_id

        if not self._project_id:
            cred = app.credential.get_credential()
            if hasattr(cred, 'project_id'):
                self._project_id = cred.project_id

        if not self._project_id:
            raise ValueError(
                'Project ID is required for FPNV. Please ensure the app is '
                'initialized with a credential that contains a project ID.'
            )

        self._verifier = _FpnvTokenVerifier(self._project_id)

    def verify_token(self, token) -> FpnvToken:
        """Verifies the given FPNV token.

        Verifies the signature, expiration, and claims of the token.

        Args:
            token: A string containing the FPNV JWT.

        Returns:
            FpnvToken: The verified token claims.

        Raises:
            ValueError: If the token is invalid or malformed.
            firebase_admin.exceptions.InvalidArgumentError: If verification fails.
        """
        try:
            claims = self._verifier.verify(token)
            return FpnvToken(claims)
        except Exception as error:
            raise InvalidArgumentError(
                'Failed to verify token: {0}'.format(error)
            )


class _FpnvTokenVerifier:
    """Internal class for verifying FPNV JWTs signed with ES256."""
    _jwks_client = None
    _project_id = None

    def __init__(self, project_id):
        self._project_id = project_id
        self._jwks_client = PyJWKClient(_FPNV_JWKS_URL, lifespan=21600)

    def verify(self, token) -> Dict[str, Any]:
        _Validators.check_string("FPNV check token", token)
        try:
            self._validate_headers(jwt.get_unverified_header(token))
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = self._validate_payload(token, signing_key.key)
        except (InvalidTokenError, DecodeError) as exception:
            raise ValueError(
                f'Verifying FPNV token failed. Error: {exception}'
            ) from exception

        return claims

    def _validate_headers(self, headers: Any) -> None:
        if headers.get('kid') is None:
            raise ValueError("FPNV has no 'kid' claim.")

        if headers.get('typ') != 'JWT':
            raise ValueError("The provided FPNV token has an incorrect type header")

        algorithm = headers.get('alg')
        if algorithm != _ALGORITHM_ES256:
            raise ValueError(
                'The provided FPNV token has an incorrect alg header. '
                f'Expected {_ALGORITHM_ES256} but got {algorithm}.'
            )

    def _validate_payload(self, token: str, signing_key: str) -> Dict[str, Any]:
        """Decodes and verifies the token."""
        _issuer = None
        payload = {}
        try:
            unsafe_payload = jwt.decode(token, options={"verify_signature": False})
            _issuer = unsafe_payload.get('iss')

            if _issuer is None:
                raise ValueError('The provided FPNV token has no issuer.')
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=[_ALGORITHM_ES256],
                audience=_issuer
            )
        except InvalidSignatureError as exception:
            raise ValueError(
                'The provided FPNV token has an invalid signature.'
            ) from exception
        except InvalidAudienceError as exception:
            raise ValueError(
                'The provided FPNV token has an incorrect "aud" (audience) claim. '
                f'Expected payload to include {_issuer}.'
            ) from exception
        except InvalidIssuerError as exception:
            raise ValueError(
                'The provided FPNV token has an incorrect "iss" (issuer) claim. '
                f'Expected claim to include {_issuer}'
            ) from exception
        except ExpiredSignatureError as exception:
            raise ValueError(
                'The provided FPNV token has expired.'
            ) from exception
        except InvalidTokenError as exception:
            raise ValueError(
                f'Decoding FPNV token failed. Error: {exception}'
            ) from exception

        if not payload.get('iss').startswith(_FPNV_ISSUER):
            raise ValueError('Token does not contain the correct "iss" (issuer).')
        _Validators.check_string(
            'The provided FPNV token "sub" (subject) claim',
            payload.get('sub'))

        return payload


class _Validators:
    """A collection of data validation utilities.

    Methods provided in this class raise ``ValueErrors`` if any validations fail.
    """

    @classmethod
    def check_string(cls, label: str, value: Any):
        """Checks if the given value is a string."""
        if value is None:
            raise ValueError(f'{label} "{value}" must be a non-empty string.')
        if not isinstance(value, str):
            raise ValueError(f'{label} "{value}" must be a string.')
