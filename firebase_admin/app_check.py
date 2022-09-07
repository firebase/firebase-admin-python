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

# See as an example from firebase_admin/messaging.py
# def _get_messaging_service(app):
#     return _utils.get_app_service(app, _MESSAGING_ATTRIBUTE, _MessagingService)

"""Firebase App Check module."""

# ASK(lahiru) Do I need to add these imports to the requirements file?
from typing import Any, Dict, List
import jwt
from jwt import PyJWKClient
from firebase_admin import _utils

_APP_CHECK_ATTRIBUTE = '_app_check'

def _get_app_check_service(app) -> Any:
    return _utils.get_app_service(app, _APP_CHECK_ATTRIBUTE, _AppCheckService)

# should i accept an app (design doc doesn't have one) or just always make it none
def verify_token(token: str, app=None) -> Dict[str, Any]:
    return _get_app_check_service(app).verify_token(token)

class _AppCheckService:
    """Service class that implements Firebase App Check functionality."""
  
    _APP_CHECK_GCP_API_URL = "https://firebaseappcheck.googleapis.com"
    _APP_CHECK_BETA_JWKS_RESOURCE = "/v1beta/jwks"

    def __init__(self, app):
        # the verification method should go in the service
        project_id = app.project_id
        if not project_id:
            raise ValueError(
                'Project ID is required to access App Check service. Either set the '
                'projectId option, or use service account credentials. Alternatively, set the '
                'GOOGLE_CLOUD_PROJECT environment variable.')
        # Unsure what I should include in this constructor, or even if I should include one
    
    @classmethod
    def verify_token(self, token: str) -> Dict[str, Any]:
        if token is None:
            return None

        # Obtain the Firebase App Check Public Keys
        # Note: It is not recommended to hard code these keys as they rotate,
        # but you should cache them for up to 6 hours.
        url = f'{self._APP_CHECK_GCP_API_URL}{self._APP_CHECK_BETA_JWKS_RESOURCE}'

        jwks_client = PyJWKClient(url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        header = jwt.get_unverified_header(token)
        self._has_valid_token_headers(header)
        
        # I don't see any method or property to just get key
        # from signing_key /*/lib/python3.10/site-packages/jwt/api_jwk.py
        payload = self._decode_and_verify(token, signing_key.key, "project_number")

        # The token's subject will be the app ID, you may optionally filter against
        # an allow list
        return payload.get('sub')

    def _has_valid_token_headers(self, header: Any) -> None:
        # Ensure the token's header has type JWT
        if header.get('typ') != 'JWT':
            raise ValueError("The token received is not a JWT")
        # Ensure the token's header uses the algorithm RS256
        if header.get('alg') != 'RS256':
            raise ValueError("JWT's algorithm does not have valid token headers")

    def _decode_token(self, token: str, signing_key: str, algorithms: List[str]) -> Dict[str, Any]:
        payload = {}
        try:
            payload = jwt.decode(
                token,
                signing_key,
                algorithms
            )
        except:
            ValueError('Unable to decode the token')
        return payload

    def _decode_and_verify(self, token: str, signing_key: str):
        payload = {}
        payload = self._decode_token(
            token,
            signing_key,
            algorithms=["RS256"]
        )

        # within the aud property, there will be an array of project id & number
        if len(payload.aud) <= 1:
            raise ValueError('Project ID and Project Number are required to access App Check.') 
        if self._APP_CHECK_GCP_API_URL not in payload.issuer:
            raise ValueError('Token does not contain the correct Issuer.')

        return payload
