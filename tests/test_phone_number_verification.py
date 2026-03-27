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

import base64
import time
from unittest import mock
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import firebase_admin
from firebase_admin import phone_number_verification as fpnv
from tests import testutils

# Mock Data
_PROJECT_ID = 'mock-project-id'
_EXP_TIMESTAMP = 2000000000
_ISSUER = f'https://fpnv.googleapis.com/projects/{_PROJECT_ID}'
_PHONE_NUMBER = '+1234567890'
_PUBLIC_KEY = 'test-public-key'  # In real tests, use the corresponding public key
_ALGORITHM = 'ES256'
_KEY_ID = 'test-key-id'
_TYPE = 'JWT'

_MOCK_PAYLOAD = {
    'iss': _ISSUER,
    'sub': _PHONE_NUMBER,
    'aud': [_ISSUER],
    'exp': _EXP_TIMESTAMP,
    'iat': _EXP_TIMESTAMP - 3600,
    "other": 'other'
}




class TestCommon:
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': _PROJECT_ID})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()


class TestFpnvToken:
    def test_properties(self):
        token = fpnv.PhoneNumberVerificationToken(_MOCK_PAYLOAD)

        assert token.phone_number == _PHONE_NUMBER
        assert token.sub == _PHONE_NUMBER
        assert token.issuer == _ISSUER
        assert token.audience == [_ISSUER]
        expected_claims = _MOCK_PAYLOAD.copy()
        expected_claims['phone_number'] = _PHONE_NUMBER
        assert token.claims == expected_claims
        assert token['other'] == _MOCK_PAYLOAD['other']


class TestVerifyToken(TestCommon):

    def test_no_project_id(self):
        app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
        app.credential.get_credential().project_id = None
        with pytest.raises(
            ValueError,
            match='Project ID is required for Firebase Phone Number Verification'
        ):
            fpnv.verify_token('token', app=app)

    def test_verify_token_with_real_crypto(self):
        """Verifies a token signed with a real ES256 key pair.

        Mocking only the JWKS endpoint.
        This ensures the cryptographic verification logic is functioning correctly.
        """
        # Generate a real ES256 key pair
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Create the JWK representation of the public key (for the mock endpoint)
        # Note: Retrieving numbers from the key involves cryptography primitives
        public_numbers = public_key.public_numbers()

        def to_b64url(b_data):
            return base64.urlsafe_b64encode(b_data).rstrip(b'=').decode('utf-8')

        jwk = {
            "kty": "EC",
            "use": "sig",
            "alg": _ALGORITHM,
            "kid": _KEY_ID,
            "crv": "P-256",
            "x": to_b64url(public_numbers.x.to_bytes(32, 'big')),
            "y": to_b64url(public_numbers.y.to_bytes(32, 'big')),
        }
        now = int(time.time())
        payload = {
            'iss': _ISSUER,
            'aud': [_ISSUER],
            'iat': now,
            'exp': now + 3600,
            'sub': _PHONE_NUMBER
        }

        # Sign using the private key object directly (PyJWT supports this)
        token = jwt.encode(
            payload,
            private_key,
            algorithm=_ALGORITHM,
            headers={'alg': _ALGORITHM, 'typ': _TYPE, 'kid': _KEY_ID},
        )

        # Mock PyJWKClient fetch_data
        with patch('jwt.PyJWKClient.fetch_data') as mock_fetch:
            mock_fetch.return_value = {'keys': [jwk]}

            app = firebase_admin.get_app()
            decoded_token = fpnv.verify_token(token, app)

            assert decoded_token['sub'] == _PHONE_NUMBER
            assert _ISSUER in decoded_token['aud']
            assert decoded_token.phone_number == decoded_token['sub']
            # Test convenience dictionary lookup
            assert decoded_token['phone_number'] == _PHONE_NUMBER

    def test_verify_token_module_level_delegation(self):
        """Verifies module-level verify_token delegates correctly."""
        with patch(
            'firebase_admin.phone_number_verification._FpnvService.verify_token'
        ) as mock_verify:
            mock_verify.return_value = 'mock-result'
            res = fpnv.verify_token('some-token')
            assert res == 'mock-result'
            mock_verify.assert_called_once_with('some-token')

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.decode')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_success(self, mock_header, mock_decode, mock_jwks_cls):
        token_str = 'valid.token.string'
        # Mock Header
        mock_header.return_value = {'kid': 'key1', 'typ': 'JWT', 'alg': 'ES256'}

        # Mock Signing Key
        mock_jwks_instance = mock_jwks_cls.return_value
        mock_signing_key = mock.Mock()
        mock_signing_key.key = _PUBLIC_KEY
        mock_jwks_instance.get_signing_key_from_jwt.return_value = mock_signing_key
        service = fpnv._get_fpnv_service(firebase_admin.get_app())
        service._verifier._jwks_client = mock_jwks_instance

        mock_decode.return_value = _MOCK_PAYLOAD

        # Execute
        token = fpnv.verify_token(token_str)

        # Verify
        assert isinstance(token, fpnv.PhoneNumberVerificationToken)
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
    def test_verify_token_no_name(self, mock_header):
        app = firebase_admin.get_app()
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}
        with pytest.raises(ValueError, match="must be a non-empty string"):
            fpnv.verify_token('', app=app)

    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_no_kid(self, mock_header):
        app = firebase_admin.get_app()
        mock_header.return_value = {'typ': 'JWT', 'alg': 'ES256'}  # Missing kid
        with pytest.raises(fpnv.InvalidTokenError, match="Token has no 'kid' claim."):
            fpnv.verify_token('token', app=app)

    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_wrong_alg(self, mock_header):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'RS256'}  # Wrong alg
        with pytest.raises(fpnv.InvalidTokenError, match="incorrect alg"):
            fpnv.verify_token('token')

    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_wrong_typ(self, mock_header):
        mock_header.return_value = {'kid': 'k', 'typ': 'WRONG', 'alg': 'ES256'} # wrong typ
        with pytest.raises(fpnv.InvalidTokenError, match="incorrect type header"):
            fpnv.verify_token('token')

    def test_verify_token_jwk_error(self):
        service = fpnv._get_fpnv_service(firebase_admin.get_app())
        jwks_client = service._verifier._jwks_client

        # Mock the method on the existing instance
        with mock.patch.object(jwks_client, 'get_signing_key_from_jwt') as mock_method:
            mock_method.side_effect = jwt.PyJWKClientError("Key not found")

            # Mock header is still needed if _get_signing_key calls it before the client
            with mock.patch('jwt.get_unverified_header') as mock_header:
                mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}

                with pytest.raises(
                    fpnv.InvalidTokenError,
                    match="Verifying phone number verification token failed"
                ):
                    fpnv.verify_token('token')

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.decode')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_expired(self, mock_header, mock_decode, mock_jwks_cls):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}
        mock_jwks_instance = mock_jwks_cls.return_value
        mock_jwks_instance.get_signing_key_from_jwt.return_value.key = _PUBLIC_KEY
        service = fpnv._get_fpnv_service(firebase_admin.get_app())
        service._verifier._jwks_client = mock_jwks_instance

        # Simulate ExpiredSignatureError
        mock_decode.side_effect = jwt.ExpiredSignatureError("Expired")

        with pytest.raises(fpnv.ExpiredTokenError, match="token has expired"):
            fpnv.verify_token('token')

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.decode')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_invalid_signature(self, mock_header, mock_decode, mock_jwks_cls):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}
        mock_jwks_instance = mock_jwks_cls.return_value
        mock_jwks_instance.get_signing_key_from_jwt.return_value.key = _PUBLIC_KEY
        service = fpnv._get_fpnv_service(firebase_admin.get_app())
        service._verifier._jwks_client = mock_jwks_instance

        # Simulate InvalidSignatureError
        mock_decode.side_effect = jwt.InvalidSignatureError("Wrong Signature")

        with pytest.raises(fpnv.InvalidTokenError, match="invalid signature"):
            fpnv.verify_token('token')

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.decode')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_invalid_audience(self, mock_header, mock_decode, mock_jwks_cls):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}
        mock_jwks_instance = mock_jwks_cls.return_value
        mock_jwks_instance.get_signing_key_from_jwt.return_value.key = _PUBLIC_KEY
        service = fpnv._get_fpnv_service(firebase_admin.get_app())
        service._verifier._jwks_client = mock_jwks_instance

        # Simulate InvalidAudienceError
        mock_decode.side_effect = jwt.InvalidAudienceError("Wrong Aud")

        with pytest.raises(fpnv.InvalidTokenError, match="incorrect \"aud\""):
            fpnv.verify_token('token')

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.decode')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_invalid_issuer(self, mock_header, mock_decode, mock_jwks_cls):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}
        mock_jwks_instance = mock_jwks_cls.return_value
        mock_jwks_instance.get_signing_key_from_jwt.return_value.key = _PUBLIC_KEY
        service = fpnv._get_fpnv_service(firebase_admin.get_app())
        service._verifier._jwks_client = mock_jwks_instance

        # Simulate InvalidIssuerError
        mock_decode.side_effect = jwt.InvalidIssuerError("Wrong Iss")

        with pytest.raises(fpnv.InvalidTokenError, match="incorrect \"iss\""):
            fpnv.verify_token('token')

    @mock.patch('jwt.PyJWKClient')
    @mock.patch('jwt.decode')
    @mock.patch('jwt.get_unverified_header')
    def test_verify_token_invalid_token(self, mock_header, mock_decode, mock_jwks_cls):
        mock_header.return_value = {'kid': 'k', 'typ': 'JWT', 'alg': 'ES256'}
        mock_jwks_instance = mock_jwks_cls.return_value
        mock_jwks_instance.get_signing_key_from_jwt.return_value.key = _PUBLIC_KEY
        service = fpnv._get_fpnv_service(firebase_admin.get_app())
        service._verifier._jwks_client = mock_jwks_instance

        # Simulate InvalidTokenError
        mock_decode.side_effect = jwt.InvalidTokenError("Decoding FPNV token failed")

        with pytest.raises(fpnv.InvalidTokenError, match="Decoding FPNV token failed"):
            fpnv.verify_token('token')
