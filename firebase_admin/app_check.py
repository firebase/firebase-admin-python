# Copyright 2022 Google Inc.
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

"""Firebase App Check module."""

from typing import Any, Dict, List
import jwt
from jwt import PyJWKClient, DecodeError, InvalidKeyError
from firebase_admin import _utils

_APP_CHECK_ATTRIBUTE = '_app_check'

def _get_app_check_service(app) -> Any:
    return _utils.get_app_service(app, _APP_CHECK_ATTRIBUTE, _AppCheckService)

def verify_token(token: str, app=None) -> Dict[str, Any]:
    """Verifies a Firebase App Check token.

    Args:
        token: A token from App Check.
        app: An App instance (optional).

    Returns:
        Dict[str, Any]: A token's decoded claims
        if the App Check token is valid; otherwise, a rejected promise.
    """
    return _get_app_check_service(app).verify_token(token)

class _AppCheckService:
    """Service class that implements Firebase App Check functionality."""

    _APP_CHECK_ISSUER = 'https://firebaseappcheck.googleapis.com/'
    _JWKS_URL = 'https://firebaseappcheck.googleapis.com/v1/jwks'
    _project_id = None

    def __init__(self, app):
        # Validate and store the project_id to validate the JWT claims
        self._project_id = app.project_id
        if not self._project_id:
            raise ValueError(
                'Project ID is required to access App Check service. Either set the '
                'projectId option, or use service account credentials. Alternatively, set the '
                'GOOGLE_CLOUD_PROJECT environment variable.')

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verifies a Firebase App Check token."""
        _Validators.check_string("app check token", token)

        # Obtain the Firebase App Check Public Keys
        # Note: It is not recommended to hard code these keys as they rotate,
        # but you should cache them for up to 6 hours.
        # TODO(dwyfrequency): update cache lifespan
        jwks_client = PyJWKClient(self._JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        self._has_valid_token_headers(jwt.get_unverified_header(token))
        verified_claims = self._decode_and_verify(token, signing_key.get('key'))

        # The token's subject will be the app ID, you may optionally filter against
        # an allow list
        verified_claims['app_id'] = verified_claims.get('sub')
        return verified_claims

    def _has_valid_token_headers(self, headers: Any) -> None:
        """Checks whether the token has valid headers for App Check."""
        # Ensure the token's header has type JWT
        if headers.get('typ') != 'JWT':
            raise ValueError("The provided App Check token has an incorrect type header")
        # Ensure the token's header uses the algorithm RS256
        algorithm = headers.get('alg')
        if algorithm != 'RS256':
            raise ValueError(
                'The provided App Check token has an incorrect algorithm. '
                f'Expected RS256 but got {algorithm}.'
                )

    def _decode_token(self, token: str, signing_key: str, algorithms: List[str]) -> Dict[str, Any]:
        """Decodes the JWT received from App Check."""
        payload = {}
        try:
            payload = jwt.decode(
                token,
                signing_key,
                algorithms
            )
        except (DecodeError, InvalidKeyError):
            ValueError(
                'Decoding App Check token failed. Make sure you passed the entire string JWT '
                'which represents the Firebase App Check token.'
                )
        return payload

    def _decode_and_verify(self, token: str, signing_key: str):
        """Decodes and verifies the token from App Check."""
        payload = self._decode_token(
            token,
            signing_key,
            algorithms=["RS256"]
        )

        scoped_project_id = 'projects/' + self._project_id
        audience = payload.get('aud')
        if not isinstance(audience, list) and scoped_project_id not in audience:
            raise ValueError('Firebase App Check token has incorrect "aud" (audience) claim.')
        if not payload.get('iss').startswith(self._APP_CHECK_ISSUER):
            raise ValueError('Token does not contain the correct Issuer.')

        return payload

class _Validators:
    """A collection of data validation utilities.

    Methods provided in this class raise ``ValueErrors`` if any validations fail.
    """

    @classmethod
    def check_string(cls, label: str, value: Any):
        """Checks if the given value is a string."""
        if value is None:
            raise ValueError('{0} "{1}" must be a non-empty string.'.format(label, value))
        if not isinstance(value, str):
            raise ValueError('{0} "{1}" must be a string.'.format(label, value))
