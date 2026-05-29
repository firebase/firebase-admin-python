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

"""Test cases for the firebase_admin.phone_number_verification module."""

import base64
import time
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt import ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError
from jwt import InvalidSignatureError, PyJWK

import firebase_admin
from firebase_admin import phone_number_verification
from tests import testutils

PROJECT_ID = 'mock-project-id'
ISSUER = f'https://fpnv.googleapis.com/projects/{PROJECT_ID}'
PHONE_NUMBER = '+12025551234'
KEY_ID = 'test-key-id'
ALGORITHM = 'ES256'

NON_STRING_ARGS = [[], tuple(), {}, True, False, 1, 0]

# A minimal symmetric key used only to satisfy PyJWK when mocking jwt.decode.
_SECRET_KEY = 'test-secret-key-for-mocking'
_SIGNING_KEY = {
    'kty': 'oct',
    'alg': 'HS256',
    'k': base64.urlsafe_b64encode(_SECRET_KEY.encode()),
}

# A representative decoded JWT payload (mirrors a real FPNV token structure).
JWT_PAYLOAD_SAMPLE = {
    'iss': ISSUER,
    'sub': PHONE_NUMBER,
    'aud': [ISSUER],
    'exp': 9_999_999_999,
    'iat': 9_999_999_999 - 3600,
}

# The header dict returned by jwt.get_unverified_header for a valid FPNV token.
JWT_HEADERS_SAMPLE = {
    'alg': ALGORITHM,
    'typ': 'JWT',
    'kid': KEY_ID,
}


class TestCommon:
    """Base class that initialises a default Firebase app for the test class."""

    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()


class TestPhoneNumberVerificationToken:
    """Unit tests for the PhoneNumberVerificationToken wrapper class."""

    def test_token_properties(self):
        token = phone_number_verification.PhoneNumberVerificationToken(JWT_PAYLOAD_SAMPLE)

        assert token.phone_number == PHONE_NUMBER
        assert token.issuer == ISSUER
        assert token.audience == [ISSUER]
        assert token.exp == JWT_PAYLOAD_SAMPLE['exp']
        assert token.iat == JWT_PAYLOAD_SAMPLE['iat']
        # Dict-style access must also work.
        assert token['sub'] == PHONE_NUMBER

    def test_token_behaves_as_dict(self):
        extra = {'custom_claim': 'value', **JWT_PAYLOAD_SAMPLE}
        token = phone_number_verification.PhoneNumberVerificationToken(extra)
        assert token['custom_claim'] == 'value'
        assert set(token.keys()) == set(extra.keys())

    def test_token_missing_claims_return_none(self):
        token = phone_number_verification.PhoneNumberVerificationToken({})
        assert token.phone_number is None
        assert token.issuer is None
        assert token.audience is None
        assert token.exp is None
        assert token.iat is None


class TestPhoneNumberVerificationService(TestCommon):
    """Tests for _PhoneNumberVerificationService and the module-level verify_token()."""

    # ------------------------------------------------------------------
    # Initialisation / project-ID validation
    # ------------------------------------------------------------------

    def test_no_project_id_raises_error(self):
        def evaluate():
            app = firebase_admin.initialize_app(
                testutils.MockCredential(), name='no_project_id')
            with pytest.raises(ValueError, match='A project ID must be specified'):
                phone_number_verification.verify_token(token='test_token', app=app)
        testutils.run_without_project_id(evaluate)

    # ------------------------------------------------------------------
    # Token string validation
    # ------------------------------------------------------------------

    @pytest.mark.parametrize('token', NON_STRING_ARGS)
    def test_verify_token_with_non_string_raises_error(self, token):
        with pytest.raises(ValueError) as excinfo:
            phone_number_verification.verify_token(token)
        expected = f'phone number verification token "{token}" must be a string.'
        assert str(excinfo.value) == expected

    def test_verify_token_with_none_raises_error(self):
        with pytest.raises(ValueError) as excinfo:
            phone_number_verification.verify_token(None)
        assert 'must be a non-empty string' in str(excinfo.value)

    def test_verify_token_with_empty_string_raises_error(self):
        with pytest.raises(ValueError) as excinfo:
            phone_number_verification.verify_token('')
        assert 'must be a non-empty string' in str(excinfo.value)

    # ------------------------------------------------------------------
    # Header validation
    # ------------------------------------------------------------------

    def test_has_valid_token_headers_succeeds(self):
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        assert service._has_valid_token_headers(JWT_HEADERS_SAMPLE) is None

    def test_has_valid_token_headers_missing_kid_raises_error(self):
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        headers = {'alg': ALGORITHM, 'typ': 'JWT'}  # no kid
        with pytest.raises(ValueError) as excinfo:
            service._has_valid_token_headers(headers)
        assert 'no "kid" claim' in str(excinfo.value)

    def test_has_valid_token_headers_incorrect_type_raises_error(self):
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        headers = {'alg': ALGORITHM, 'typ': 'WRONG', 'kid': KEY_ID}
        with pytest.raises(ValueError) as excinfo:
            service._has_valid_token_headers(headers)
        expected = (
            'The provided Phone Number Verification token has an incorrect type header.')
        assert str(excinfo.value) == expected

    def test_has_valid_token_headers_incorrect_algorithm_raises_error(self):
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        headers = {'alg': 'RS256', 'typ': 'JWT', 'kid': KEY_ID}
        with pytest.raises(ValueError) as excinfo:
            service._has_valid_token_headers(headers)
        expected = (
            'The provided Phone Number Verification token has an incorrect alg header. '
            'Expected ES256 but got RS256.')
        assert str(excinfo.value) == expected

    # ------------------------------------------------------------------
    # Payload decoding and claim verification
    # ------------------------------------------------------------------

    def test_decode_and_verify_calls_jwt_decode_correctly(self, mocker):
        jwt_decode_mock = mocker.patch('jwt.decode', return_value=JWT_PAYLOAD_SAMPLE)
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)

        payload = service._decode_and_verify(token=None, signing_key='test-key')

        jwt_decode_mock.assert_called_once_with(
            None, 'test-key',
            algorithms=[ALGORITHM],
            audience=ISSUER,
            issuer=ISSUER)
        assert payload == JWT_PAYLOAD_SAMPLE

    def test_decode_and_verify_with_incorrect_token_raises_error(self):
        """Ensure a structurally invalid JWT string produces a descriptive ValueError."""
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        with pytest.raises(ValueError) as excinfo:
            service._decode_and_verify(token='not.a.real.jwt', signing_key=_SIGNING_KEY)
        assert 'Decoding Phone Number Verification token failed' in str(excinfo.value)

    def test_decode_and_verify_with_expired_token_raises_error(self, mocker):
        mocker.patch('jwt.decode', side_effect=ExpiredSignatureError)
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        with pytest.raises(ValueError) as excinfo:
            service._decode_and_verify(token='token', signing_key=_SIGNING_KEY)
        expected = 'The provided Phone Number Verification token has expired.'
        assert str(excinfo.value) == expected

    def test_decode_and_verify_with_invalid_signature_raises_error(self, mocker):
        mocker.patch('jwt.decode', side_effect=InvalidSignatureError)
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        with pytest.raises(ValueError) as excinfo:
            service._decode_and_verify(token='token', signing_key=_SIGNING_KEY)
        expected = 'The provided Phone Number Verification token has an invalid signature.'
        assert str(excinfo.value) == expected

    def test_decode_and_verify_with_invalid_audience_raises_error(self, mocker):
        mocker.patch('jwt.decode', side_effect=InvalidAudienceError)
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        with pytest.raises(ValueError) as excinfo:
            service._decode_and_verify(token='token', signing_key=_SIGNING_KEY)
        expected = (
            'The provided Phone Number Verification token has an incorrect "aud" '
            f'(audience) claim. Expected payload to include {ISSUER}.')
        assert str(excinfo.value) == expected

    def test_decode_and_verify_with_invalid_issuer_raises_error(self, mocker):
        mocker.patch('jwt.decode', side_effect=InvalidIssuerError)
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        with pytest.raises(ValueError) as excinfo:
            service._decode_and_verify(token='token', signing_key=_SIGNING_KEY)
        expected = (
            'The provided Phone Number Verification token has an incorrect "iss" '
            f'(issuer) claim. Expected claim to include {ISSUER}.')
        assert str(excinfo.value) == expected

    def test_decode_and_verify_with_none_sub_raises_error(self, mocker):
        payload_no_sub = {**JWT_PAYLOAD_SAMPLE, 'sub': None}
        mocker.patch('jwt.decode', return_value=payload_no_sub)
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        with pytest.raises(ValueError) as excinfo:
            service._decode_and_verify(token='token', signing_key=_SIGNING_KEY)
        expected = (
            'The provided Phone Number Verification token "sub" (subject) claim '
            f'"{None}" must be a non-empty string.')
        assert str(excinfo.value) == expected

    def test_decode_and_verify_with_non_string_sub_raises_error(self, mocker):
        sub_number = 12025551234
        payload_bad_sub = {**JWT_PAYLOAD_SAMPLE, 'sub': sub_number}
        mocker.patch('jwt.decode', return_value=payload_bad_sub)
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        with pytest.raises(ValueError) as excinfo:
            service._decode_and_verify(token='token', signing_key=_SIGNING_KEY)
        expected = (
            'The provided Phone Number Verification token "sub" (subject) claim '
            f'"{sub_number}" must be a string.')
        assert str(excinfo.value) == expected

    def test_decode_and_verify_with_empty_sub_raises_error(self, mocker):
        payload_empty_sub = {**JWT_PAYLOAD_SAMPLE, 'sub': ''}
        mocker.patch('jwt.decode', return_value=payload_empty_sub)
        app = firebase_admin.get_app()
        service = phone_number_verification._get_phone_number_verification_service(app)
        with pytest.raises(ValueError) as excinfo:
            service._decode_and_verify(token='token', signing_key=_SIGNING_KEY)
        assert 'must be a non-empty string' in str(excinfo.value)

    # ------------------------------------------------------------------
    # Module-level verify_token() integration tests (mocked JWKS)
    # ------------------------------------------------------------------

    def test_verify_token_returns_phone_number_verification_token(self, mocker):
        mocker.patch('jwt.decode', return_value=JWT_PAYLOAD_SAMPLE)
        mocker.patch(
            'jwt.PyJWKClient.get_signing_key_from_jwt',
            return_value=PyJWK(_SIGNING_KEY))
        mocker.patch('jwt.get_unverified_header', return_value=JWT_HEADERS_SAMPLE)
        app = firebase_admin.get_app()

        result = phone_number_verification.verify_token('encoded.token.here', app)

        assert isinstance(result, phone_number_verification.PhoneNumberVerificationToken)
        assert result.phone_number == PHONE_NUMBER
        assert result == JWT_PAYLOAD_SAMPLE

    def test_verify_token_malformed_jwt_raises_error(self):
        """A token that cannot be header-decoded should raise a descriptive ValueError."""
        app = firebase_admin.get_app()
        with pytest.raises(ValueError, match='Verifying Phone Number Verification token failed'):
            phone_number_verification.verify_token('not-a-jwt', app)

    def test_verify_token_wrong_header_alg_raises_error(self, mocker):
        mocker.patch(
            'jwt.get_unverified_header',
            return_value={**JWT_HEADERS_SAMPLE, 'alg': 'RS256'})
        app = firebase_admin.get_app()
        with pytest.raises(ValueError, match='incorrect alg header'):
            phone_number_verification.verify_token('valid.jwt.structure', app)

    def test_verify_token_wrong_header_typ_raises_error(self, mocker):
        mocker.patch(
            'jwt.get_unverified_header',
            return_value={**JWT_HEADERS_SAMPLE, 'typ': 'JWX'})
        app = firebase_admin.get_app()
        with pytest.raises(ValueError, match='incorrect type header'):
            phone_number_verification.verify_token('valid.jwt.structure', app)

    def test_verify_token_missing_kid_raises_error(self, mocker):
        headers_no_kid = {k: v for k, v in JWT_HEADERS_SAMPLE.items() if k != 'kid'}
        mocker.patch('jwt.get_unverified_header', return_value=headers_no_kid)
        app = firebase_admin.get_app()
        with pytest.raises(ValueError, match='no "kid" claim'):
            phone_number_verification.verify_token('valid.jwt.structure', app)

    # ------------------------------------------------------------------
    # End-to-end test using a real EC key pair
    # ------------------------------------------------------------------

    def test_verify_token_with_real_ec_key_pair(self):
        """Verifies a token signed with a real ES256 private key, mocking only JWKS fetch.

        This test validates that the cryptographic verification path works correctly
        without mocking the jwt library itself.
        """
        # Generate a real P-256 key pair.
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        def _to_b64url(num_bytes: bytes) -> str:
            return base64.urlsafe_b64encode(num_bytes).rstrip(b'=').decode('utf-8')

        jwk = {
            'kty': 'EC',
            'use': 'sig',
            'alg': ALGORITHM,
            'kid': KEY_ID,
            'crv': 'P-256',
            'x': _to_b64url(public_numbers.x.to_bytes(32, 'big')),
            'y': _to_b64url(public_numbers.y.to_bytes(32, 'big')),
        }

        now = int(time.time())
        payload = {
            'iss': ISSUER,
            'aud': [ISSUER],
            'iat': now,
            'exp': now + 3600,
            'sub': PHONE_NUMBER,
        }

        token = jwt.encode(
            payload,
            private_key,
            algorithm=ALGORITHM,
            headers={'alg': ALGORITHM, 'typ': 'JWT', 'kid': KEY_ID},
        )

        with patch('jwt.PyJWKClient.fetch_data') as mock_fetch:
            mock_fetch.return_value = {'keys': [jwk]}
            app = firebase_admin.get_app()
            result = phone_number_verification.verify_token(token, app)

        assert isinstance(result, phone_number_verification.PhoneNumberVerificationToken)
        assert result.phone_number == PHONE_NUMBER
        assert ISSUER in result.audience
        assert result.issuer == ISSUER
