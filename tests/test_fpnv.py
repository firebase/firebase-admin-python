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

"""Test cases for the firebase_admin.fpnv module."""

from unittest import mock

import jwt
import pytest

import firebase_admin
from firebase_admin import fpnv
from tests import testutils

# Mock Data
_PROJECT_ID = 'mock-project-id'
_FPNV_TOKEN = 'fpnv_token_string'
_EXP_TIMESTAMP = 2000000000
_ISSUER = f'https://fpnv.googleapis.com/projects/{_PROJECT_ID}'
_JWKS_URL = 'https://fpnv.googleapis.com/v1beta/jwks'
_PHONE_NUMBER = '+1234567890'
_ISSUER_PREFIX = 'https://fpnv.googleapis.com/projects/'
_PRIVATE_KEY = 'test-private-key'  # In real tests, use a real RSA/EC private key
_PUBLIC_KEY = 'test-public-key'  # In real tests, use the corresponding public key

_MOCK_PAYLOAD = {
    'iss': _ISSUER,
    'sub': '+1234567890',
    'aud': [_ISSUER],
    'exp': _EXP_TIMESTAMP,
    'iat': _EXP_TIMESTAMP - 3600,
    "other": 'other'
}


@pytest.fixture
def app():
    cred = testutils.MockCredential()
    return firebase_admin.initialize_app(cred, {'projectId': _PROJECT_ID})


@pytest.fixture
def client(app):
    return fpnv.client(app)


class TestCommon:
    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()


class TestFpnvToken(TestCommon):
    def test_properties(self):
        token = fpnv.FpnvToken(_MOCK_PAYLOAD)

        assert token.phone_number == _PHONE_NUMBER
        assert token.sub == _PHONE_NUMBER
        assert token.issuer == _ISSUER
        assert token.audience == [_ISSUER]
        assert token.exp == _MOCK_PAYLOAD['exp']
        assert token.iat == _MOCK_PAYLOAD['iat']
        assert token.claims == _MOCK_PAYLOAD
        assert token['other'] == _MOCK_PAYLOAD['other']


class TestFpnvClient(TestCommon):

    def test_client_no_app(self):
        with mock.patch('firebase_admin._utils.get_app_service') as mock_get_service:
            fpnv.client()
            mock_get_service.assert_called_once()
        with pytest.raises(ValueError):
            fpnv.client()

    def test_client(self, app):
        client = fpnv.client(app)
        assert isinstance(client, fpnv.FpnvClient)
        assert client._project_id == _PROJECT_ID

    def test_requires_project_id(self):
        cred = testutils.MockCredential()
        # Create app without project ID
        app = firebase_admin.initialize_app(cred, name='no_project_id')
        # Mock credential to not have project_id
        app.credential.get_credential().project_id = None

        with pytest.raises(ValueError, match='Project ID is required'):
            fpnv.client(app)

    def test_client_default_app(self):
        client = fpnv.client()
        assert isinstance(client, fpnv.FpnvClient)

    def test_client_explicit_app(self):
        cred = testutils.MockCredential()
        app = firebase_admin.initialize_app(cred, {'projectId': _PROJECT_ID}, name='custom')
        client = fpnv.client(app)
        assert isinstance(client, fpnv.FpnvClient)


class TestVerifyToken:

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.decode')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_success(self, mock_header, mock_decode, mock_jwks_cls, client):
        token_str = 'valid.token.string'
        # Mock Header
        mock_header.return_value = {'kid': 'key1', 'typ': 'JWT', 'alg': 'ES256'}

        # Mock Signing Key
        mock_jwks_instance = mock_jwks_cls.return_value
        mock_signing_key = mock.Mock()
        mock_signing_key.key = _PUBLIC_KEY
        mock_jwks_instance.get_signing_key_from_jwt.return_value = mock_signing_key

        mock_decode.return_value = _MOCK_PAYLOAD

        # Execute
        token = client.verify_token(token_str)

        # Verify
        assert isinstance(token, fpnv.FpnvToken)
        assert token.phone_number == _PHONE_NUMBER

        mock_header.assert_called_with(token_str)
        mock_jwks_instance.get_signing_key_from_jwt.assert_called_with(token_str)
        mock_decode.assert_called_with(
            token_str,
            _PUBLIC_KEY,
            algorithms=['ES256'],
            audience=_ISSUER,
            issuer=_ISSUER
        )

    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_no_kid(self, mock_header, client):
        mock_header.return_value = {'typ': 'JWT', 'alg': 'ES256'}  # Missing kid
        with pytest.raises(ValueError, match="no 'kid' claim"):
            client.verify_token('token')

    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_wrong_alg(self, mock_header, client):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'RS256'}  # Wrong alg
        with pytest.raises(ValueError, match="incorrect alg"):
            client.verify_token('token')

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_jwk_error(self, mock_header, mock_jwks_cls, client):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}
        mock_jwks_instance = mock_jwks_cls.return_value
        # Simulate Key not found or other PyJWKClient error
        mock_jwks_instance.get_signing_key_from_jwt.side_effect = jwt.PyJWKClientError(
            "Key not found")

        with pytest.raises(ValueError, match="Verifying FPNV token failed"):
            client.verify_token('token')

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.decode')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_expired(self, mock_header, mock_decode, mock_jwks_cls, client):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}
        mock_jwks_instance = mock_jwks_cls.return_value
        mock_jwks_instance.get_signing_key_from_jwt.return_value.key = _PUBLIC_KEY

        # Simulate ExpiredSignatureError
        mock_decode.side_effect = jwt.ExpiredSignatureError("Expired")

        with pytest.raises(ValueError, match="token has expired"):
            client.verify_token('token')

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.decode')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_invalid_audience(self, mock_header, mock_decode, mock_jwks_cls, client):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}
        mock_jwks_instance = mock_jwks_cls.return_value
        mock_jwks_instance.get_signing_key_from_jwt.return_value.key = _PUBLIC_KEY

        # Simulate InvalidAudienceError
        mock_decode.side_effect = jwt.InvalidAudienceError("Wrong Aud")

        with pytest.raises(ValueError, match="incorrect \"aud\""):
            client.verify_token('token')

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.decode')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_invalid_issuer(self, mock_header, mock_decode, mock_jwks_cls, client):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}
        mock_jwks_instance = mock_jwks_cls.return_value
        mock_jwks_instance.get_signing_key_from_jwt.return_value.key = _PUBLIC_KEY

        # Simulate InvalidIssuerError
        mock_decode.side_effect = jwt.InvalidIssuerError("Wrong Iss")

        with pytest.raises(ValueError, match="incorrect \"iss\""):
            client.verify_token('token')
