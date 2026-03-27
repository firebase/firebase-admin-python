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

"""Firebase Phone Number Verification module.

This module contains functions for verifying JWTs related to the Firebase
Phone Number Verification service.
"""
from __future__ import annotations
from typing import Any, Dict, Optional

import jwt
from jwt import (
    PyJWKClient, InvalidSignatureError,
    PyJWKClientError, InvalidAudienceError, InvalidIssuerError, ExpiredSignatureError
)

from firebase_admin import App, _utils, exceptions

_FPNV_ATTRIBUTE = '_phone_number_verification'
_FPNV_JWKS_URL = 'https://fpnv.googleapis.com/v1beta/jwks'
_FPNV_ISSUER = 'https://fpnv.googleapis.com/projects/'
_ALGORITHM_ES256 = 'ES256'


def _get_fpnv_service(app):
    return _utils.get_app_service(app, _FPNV_ATTRIBUTE, _FpnvService)

def verify_token(token: str, app: Optional[App] = None) -> PhoneNumberVerificationToken:
    """Verifies a Firebase Phone Number Verification token.

    Args:
        token: A string containing the Firebase Phone Number Verification JWT.
        app: An App instance (optional).

    Returns:
        PhoneNumberVerificationToken: The verified token claims.

    Raises:
        ValueError: If the token is not a string or is empty.
        InvalidTokenError: If the token is invalid or malformed.
        ExpiredTokenError: If the token has expired.
    """
    return _get_fpnv_service(app).verify_token(token)


class PhoneNumberVerificationToken(dict):
    """Represents a verified Firebase Phone Number Verification token.

    This class behaves like a dictionary, allowing access to the decoded claims.
    It also provides convenience properties for common claims.
    """

    def __init__(self, claims):
        super().__init__(claims)
        self['phone_number'] = claims.get('sub')

    @property
    def phone_number(self) -> str:
        """Returns the phone number of the user.
        This corresponds to the 'sub' claim in the JWT.
        """
        return self.get('sub')

    @property
    def issuer(self) -> str:
        """Returns the issuer identifier for the issuer of the response."""
        return self.get('iss')

    @property
    def audience(self) -> str:
        """Returns the audience for which this token is intended."""
        return self.get('aud')

    @property
    def exp(self) -> int:
        """Returns the expiration time since the Unix epoch."""
        return self.get('exp')

    @property
    def iat(self) -> int:
        """Returns the issued-at time since the Unix epoch."""
        return self.get('iat')

    @property
    def sub(self) -> str:
        """Returns the sub (subject) of the token, which is the phone number."""
        return self.get('sub')

    @property
    def claims(self):
        """Returns the entire map of claims."""
        return self


class _FpnvService:
    """Service class that implements Firebase Phone Number Verification functionality."""
    _project_id = None

    def __init__(self, app):
        self._project_id = app.project_id
        if not self._project_id:
            raise ValueError(
                'Project ID is required for Firebase Phone Number Verification. Please ensure the '
                'app is initialized with a credential that contains a project ID.'
            )

        self._verifier = _FpnvTokenVerifier(self._project_id)

    def verify_token(self, token) -> PhoneNumberVerificationToken:
        """Verifies a Firebase Phone Number Verification token.

        Verifies the signature, expiration, and claims of the token.

        Args:
            token: A string containing the Firebase Phone Number Verification JWT.

        Returns:
            PhoneNumberVerificationToken: The verified token claims.

        Raises:
            ValueError: If the token is not a string or is empty.
            InvalidTokenError: If the token is invalid or malformed.
            ExpiredTokenError: If the token has expired.
        """
        return PhoneNumberVerificationToken(self._verifier.verify(token))


class _FpnvTokenVerifier:
    """Internal class for verifying Firebase Phone Number Verification JWTs signed with ES256."""
    _jwks_client = None
    _project_id = None

    def __init__(self, project_id):
        self._project_id = project_id
        self._jwks_client = PyJWKClient(_FPNV_JWKS_URL, lifespan=21600)

    def verify(self, token) -> Dict[str, Any]:
        """Verifies the given Firebase Phone Number Verification token."""
        _Validators.check_string("Firebase Phone Number Verification check token", token)
        try:
            self._validate_headers(jwt.get_unverified_header(token))
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = self._decode_and_verify(token, signing_key.key)
        except (jwt.InvalidTokenError, PyJWKClientError) as exception:
            raise InvalidTokenError(
                'Verifying phone number verification token failed.',
                cause=exception,
                http_response=getattr(exception, 'http_response', None)
            ) from exception

        return claims

    def _validate_headers(self, headers: Any) -> None:
        """Validates the headers."""
        if headers.get('kid') is None:
            raise InvalidTokenError("Token has no 'kid' claim.")

        if headers.get('typ') != 'JWT':
            raise InvalidTokenError(
                'The provided token has an incorrect type header. ' \
                f"Expected 'JWT' but got {headers.get('typ')!r}."
            )

        algorithm = headers.get('alg')
        if algorithm != _ALGORITHM_ES256:
            raise InvalidTokenError(
                'The provided token has an incorrect alg header. '
                f'Expected {_ALGORITHM_ES256} but got {algorithm}.'
            )

    def _decode_and_verify(self, token, signing_key) -> Dict[str, Any]:
        """Decodes and verifies the token."""
        expected_issuer = f'{_FPNV_ISSUER}{self._project_id}'
        try:
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=[_ALGORITHM_ES256],
                audience=expected_issuer,
                issuer=expected_issuer
            )
        except InvalidSignatureError as exception:
            raise InvalidTokenError(
                'The provided token has an invalid signature.'
            ) from exception
        except InvalidAudienceError as exception:
            raise InvalidTokenError(
                'The provided token has an incorrect "aud" (audience) claim. '
                f'Expected {expected_issuer}.'
            ) from exception
        except InvalidIssuerError as exception:
            raise InvalidTokenError(
                'The provided token has an incorrect "iss" (issuer) claim. '
                f'Expected {expected_issuer}.'
            ) from exception
        except ExpiredSignatureError as exception:
            raise ExpiredTokenError(
                'The provided token has expired.'
            ) from exception
        except jwt.InvalidTokenError as exception:
            raise InvalidTokenError(
                f'Decoding token failed. Error: {exception}'
            ) from exception

        sub_claim = payload.get('sub')
        if not isinstance(sub_claim, str) or not sub_claim:
            raise InvalidTokenError(
                'The provided token has an incorrect "sub" (subject) claim. '
                'Expected a non-empty string.'
            )

        return payload


class _Validators:
    """A collection of data validation utilities.

    Methods provided in this class raise ``ValueErrors`` if any validations fail.
    """

    @classmethod
    def check_string(cls, label: str, value: Any):
        """Checks if the given value is a string."""
        if not isinstance(value, str) or not value:
            raise ValueError(f'{label} must be a non-empty string.')

# Firebase Phone Number Verification Errors
class InvalidTokenError(exceptions.InvalidArgumentError):
    """Raised when a Firebase Phone Number Verification token is invalid."""

    def __init__(self, message, cause=None, http_response=None):
        exceptions.InvalidArgumentError.__init__(self, message, cause, http_response)

class ExpiredTokenError(InvalidTokenError):
    """Raised when a Firebase Phone Number Verification token is expired."""

    def __init__(self, message, cause=None, http_response=None):
        InvalidTokenError.__init__(self, message, cause, http_response)
