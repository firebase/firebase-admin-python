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

This module provides functions for verifying JWTs issued by the Firebase
Phone Number Verification service.
"""

from typing import Any, Dict

import jwt
from jwt import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    PyJWKClient,
)

from firebase_admin import _utils

_PHONE_NUMBER_VERIFICATION_ATTRIBUTE = '_phone_number_verification'
_JWKS_URL = 'https://fpnv.googleapis.com/v1beta/jwks'
_ISSUER_PREFIX = 'https://fpnv.googleapis.com/projects/'
_ALGORITHM = 'ES256'


def _get_phone_number_verification_service(app) -> Any:
    """Returns the _PhoneNumberVerificationService for the given app."""
    return _utils.get_app_service(
        app,
        _PHONE_NUMBER_VERIFICATION_ATTRIBUTE,
        _PhoneNumberVerificationService,
    )


def verify_token(token: str, app=None) -> 'PhoneNumberVerificationToken':
    """Verifies a Firebase Phone Number Verification token.

    Args:
        token: A JWT string issued by the Phone Number Verification service.
        app: An App instance (optional).

    Returns:
        PhoneNumberVerificationToken: The decoded and verified token claims.

    Raises:
        ValueError: If the app's ``project_id`` is invalid or unspecified,
            or if the token's headers or payload are invalid.
        PyJWKClientError: If the JWKS client fails to fetch a valid signing key.
    """
    return _get_phone_number_verification_service(app).verify_token(token)


class PhoneNumberVerificationToken(dict):
    """Represents a decoded and verified Phone Number Verification token.

    Behaves as a read-only dictionary of decoded JWT claims, with additional
    convenience properties for the most common claims.
    """

    @property
    def phone_number(self):
        """Returns the verified phone number from the ``sub`` claim."""
        return self.get('sub')

    @property
    def issuer(self):
        """Returns the token issuer from the ``iss`` claim."""
        return self.get('iss')

    @property
    def audience(self):
        """Returns the token audience from the ``aud`` claim."""
        return self.get('aud')

    @property
    def exp(self):
        """Returns the token expiration time (seconds since the Unix epoch)."""
        return self.get('exp')

    @property
    def iat(self):
        """Returns the token issued-at time (seconds since the Unix epoch)."""
        return self.get('iat')


class _PhoneNumberVerificationService:
    """Service class implementing Firebase Phone Number Verification token verification."""

    _project_id = None
    _expected_issuer = None
    _jwks_client = None

    def __init__(self, app):
        """Initializes the service with the provided App instance.

        Args:
            app: A firebase_admin.App instance.

        Raises:
            ValueError: If the app does not have a project ID.
        """
        self._project_id = app.project_id
        if not self._project_id:
            raise ValueError(
                'A project ID must be specified to access the Phone Number Verification '
                'service. Either set the projectId option, use service account credentials, '
                'or set the GOOGLE_CLOUD_PROJECT environment variable.')
        self._expected_issuer = _ISSUER_PREFIX + self._project_id
        # Cache JWKS for up to 6 hours (21600 seconds) to reduce network overhead.
        self._jwks_client = PyJWKClient(_JWKS_URL, lifespan=21600)

    def verify_token(self, token: str) -> PhoneNumberVerificationToken:
        """Verifies a Phone Number Verification JWT string.

        Validates the token string, fetches the appropriate public key from the
        JWKS endpoint, then verifies the signature and all standard claims.

        Args:
            token: The JWT string to verify.

        Returns:
            PhoneNumberVerificationToken: The decoded and verified token claims.

        Raises:
            ValueError: If the token is not a valid non-empty string, has invalid
                headers, or contains invalid claims.
            PyJWKClientError: If the JWKS client fails to fetch a valid signing key.
        """
        _Validators.check_string('phone number verification token', token)
        try:
            self._has_valid_token_headers(jwt.get_unverified_header(token))
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            verified_claims = self._decode_and_verify(token, signing_key.key)
        except (InvalidTokenError, DecodeError) as exception:
            raise ValueError(
                f'Verifying Phone Number Verification token failed. Error: {exception}'
            ) from exception
        return PhoneNumberVerificationToken(verified_claims)

    def _has_valid_token_headers(self, headers: Any) -> None:
        """Validates the JWT headers for a Phone Number Verification token.

        Args:
            headers: The decoded JWT headers dict.

        Raises:
            ValueError: If a required header is missing or has an unexpected value.
        """
        if headers.get('kid') is None:
            raise ValueError(
                'The provided Phone Number Verification token has no "kid" claim.')
        if headers.get('typ') != 'JWT':
            raise ValueError(
                'The provided Phone Number Verification token has an incorrect type header.')
        algorithm = headers.get('alg')
        if algorithm != _ALGORITHM:
            raise ValueError(
                'The provided Phone Number Verification token has an incorrect alg header. '
                f'Expected {_ALGORITHM} but got {algorithm}.')

    def _decode_and_verify(self, token: str, signing_key) -> Dict[str, Any]:
        """Decodes and verifies the claims of a Phone Number Verification token.

        Args:
            token: The JWT string to decode.
            signing_key: The public key used for signature verification.

        Returns:
            dict: The verified token payload.

        Raises:
            ValueError: If any token claim is invalid.
        """
        try:
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=[_ALGORITHM],
                audience=self._expected_issuer,
                issuer=self._expected_issuer,
            )
        except InvalidSignatureError as exception:
            raise ValueError(
                'The provided Phone Number Verification token has an invalid signature.'
            ) from exception
        except InvalidAudienceError as exception:
            raise ValueError(
                'The provided Phone Number Verification token has an incorrect "aud" '
                f'(audience) claim. Expected payload to include {self._expected_issuer}.'
            ) from exception
        except InvalidIssuerError as exception:
            raise ValueError(
                'The provided Phone Number Verification token has an incorrect "iss" '
                f'(issuer) claim. Expected claim to include {self._expected_issuer}.'
            ) from exception
        except ExpiredSignatureError as exception:
            raise ValueError(
                'The provided Phone Number Verification token has expired.'
            ) from exception
        except InvalidTokenError as exception:
            raise ValueError(
                f'Decoding Phone Number Verification token failed. Error: {exception}'
            ) from exception

        _Validators.check_string(
            'The provided Phone Number Verification token "sub" (subject) claim',
            payload.get('sub'))

        return payload


class _Validators:
    """A collection of data validation utilities.

    Methods provided in this class raise ``ValueErrors`` if any validations fail.
    """

    @classmethod
    def check_string(cls, label: str, value: Any):
        """Checks if the given value is a non-empty string.

        Args:
            label: A descriptive label for the value (used in error messages).
            value: The value to validate.

        Raises:
            ValueError: If the value is ``None``, not a string, or an empty string.
        """
        if value is None:
            raise ValueError(f'{label} "{value}" must be a non-empty string.')
        if not isinstance(value, str):
            raise ValueError(f'{label} "{value}" must be a string.')
        if not value:
            raise ValueError(f'{label} must be a non-empty string.')
