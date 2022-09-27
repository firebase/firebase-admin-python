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

"""Test cases for the firebase_admin.app_check module."""
import base64
import pytest

from jwt import PyJWK
import firebase_admin
from firebase_admin import app_check
from tests import testutils

NON_STRING_ARGS = [list(), tuple(), dict(), True, False, 1, 0]

APP_ID = "1234567890"
PROJECT_ID = "1334"
SCOPED_PROJECT_ID = f"projects/{PROJECT_ID}"
JWT_PAYLOAD_SAMPLE = {
    "headers": {
        "alg": "RS256",
        "typ": "JWT"
    },
    "sub": APP_ID,
    "name": "John Doe",
    "iss": "https://firebaseappcheck.googleapis.com/",
    "aud": [SCOPED_PROJECT_ID]
}

secret_key = "secret"
signing_key = {
    "kty": "oct",
    # Using HS256 for simplicity, production key will use RS256
    "alg": "HS256",
    "k": base64.urlsafe_b64encode(secret_key.encode())
}

EXPIRED_TOKEN = "eyJraWQiOiJsWUJXVmciLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxOjM4ODE4ODY2Njk2MzphbmRyb2lkOjYyZWNhZWEzOTYzMWIxZGM3NDFhYTYiLCJhdWQiOlsicHJvamVjdHNcLzM4ODE4ODY2Njk2MyIsInByb2plY3RzXC9hZG1pbi1qYXZhLWludGVncmF0aW9uIl0sImlzcyI6Imh0dHBzOlwvXC9maXJlYmFzZWFwcGNoZWNrLmdvb2dsZWFwaXMuY29tXC8zODgxODg2NjY5NjMiLCJleHAiOjE2NjM3OTUxNDcsImlhdCI6MTY2Mzc5MTU0N30.oQWIQFwUlWp1wXhZ-rQvrw7ud2fmPj7kagWWPlqvXrRKASjtMka09Anm25mRaOymm7jeu7r0JMOYTSJJM6Iz89qCndO92nC6Wuvlug1zVYSJDgUWAv6msGOK_qANMMbYYXjx912nCHT0A7CyeTSCKK3xxq8lD0YI6c2E9g6U1E23mbHn-ekI8K_fV3DjZ9staCYmymlhbdZwf6FMeBZzSgjfXaHzNwe37Ndj9C_HxdZwYS4Yt7JS_SWNXtgGM6kj-Ie5MWLGuzR-qkMglaS7KqTK3K-iYG1pMzKst4akDbhsr7CO3K4Z1q-iT-yBkTuwMvE40ztVXBm_v5zQQqE7IGWu79Fr-3yjmyf7MrvgP-WgAGc4MLozuXvasgRUnaf2XiXlMlmAk3BfiOB4maUhVktjexlzF1lD7MnDQ0mxpVz_Q2gzAus8ugbySGS0XvvDDTX3qlPIeVFsXRehwzwvUKc6li2hIdzG3nvOMWNBBGQzSs99-EbfGVm4caGmVoc3"

INVALID_SIGNATURE_TOKEN = "eyJraWQiOiJsWUJXVmciLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxOjM4ODE4ODY2Njk2MzphbmRyb2lkOjYyZWNhZWEzOTYzMWIxZGM3NDFhYTYiLCJhdWQiOlsicHJvamVjdHNcLzM4ODE4ODY2Njk2MyIsInByb2plY3RzXC9hZG1pbi1qYXZhLWludGVncmF0aW9uIl0sImlzcyI6Imh0dHBzOlwvXC9maXJlYmFzZWFwcGNoZWNrLmdvb2dsZWFwaXMuY29tXC8zODgxODg2NjY5NjMiLCJleHAiOjE2NjM3OTUxNDcsImlhdCI6MTY2Mzc5MTU0N30.oQWIQFwUlWp1wXhZ-rQvrw7ud2fmPj7kagWWPlqvXrRKASjtMka09Anm25mRaOymm7jeuOYTSJJM6Iz89qCndO92nC6Wuvlug1zVYSJDgUWAv6msGOK_qANMMbYYXjx912nCHT0A7CyeTSCKK3xxq8lD0YI6c2E9g6U1E23mbHn-ekI8K_fV3DjZ9staCYmymlhbdZwf6FMeBZzSgjfXaHzNwe37Ndj9C_HxdZwYS4Yt7JS_SWNXtgGM6kj-Ie5MWLGuzR-qkMglaS7KqTK3K-iYG1pMzKst4akDbhsr7CO3K4Z1q-iT-yBkTuwMvE40ztVXBm_v5zQQqE7IGWu79Fr-3yjmyf7MrvgP-WgAGc4MLozuXvasgRUnaf2XiXlMlmAk3BfiOB4maUhVktjexlzF1lD7MnDQ0mxpVz_Q2gzAus8ugbySGS0XvvDDTX3qlPIeVFsXRehwzwvUKc6li2hIdzG3nvOMWNBBGQzSs99-EbfGVm4caGmVoc3"

class TestBatch:

    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

class TestVerifyToken(TestBatch):

    def test_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
            with pytest.raises(ValueError):
                app_check.verify_token(token="app_check_token", app=app)
        testutils.run_without_project_id(evaluate)

    @pytest.mark.parametrize('token', NON_STRING_ARGS)
    def test_verify_token_with_non_string_raises_error(self, token):
        with pytest.raises(ValueError) as excinfo:
            app_check.verify_token(token)
        expected = 'app check token "{0}" must be a string.'.format(token)
        assert str(excinfo.value) == expected

    def test_has_valid_token_headers(self):
        app = firebase_admin.get_app()
        app_check_service = app_check._get_app_check_service(app)

        headers = {"alg": "RS256", 'typ': "JWT"}
        assert app_check_service._has_valid_token_headers(headers=headers) is None

    def test_has_valid_token_headers_with_incorrect_type_raises_error(self):
        app = firebase_admin.get_app()
        app_check_service = app_check._get_app_check_service(app)
        headers = {"alg": "RS256", 'typ': "WRONG"}
        with pytest.raises(ValueError) as excinfo:
            app_check_service._has_valid_token_headers(headers=headers)

        expected = 'The provided App Check token has an incorrect type header'
        assert str(excinfo.value) == expected

    def test_has_valid_token_headers_with_incorrect_algorithm_raises_error(self):
        app = firebase_admin.get_app()
        app_check_service = app_check._get_app_check_service(app)
        headers = {"alg": "HS256", 'typ': "JWT"}
        with pytest.raises(ValueError) as excinfo:
            app_check_service._has_valid_token_headers(headers=headers)

        expected = ('The provided App Check token has an incorrect algorithm. '
                    'Expected RS256 but got HS256.')
        assert str(excinfo.value) == expected

    def test_decode_and_verify(self, mocker):
        jwt_decode_mock = mocker.patch("jwt.decode", return_value=JWT_PAYLOAD_SAMPLE)
        app = firebase_admin.get_app()
        app_check_service = app_check._get_app_check_service(app)
        payload = app_check_service._decode_and_verify(
            token=None,
            signing_key="1234",
        )

        jwt_decode_mock.assert_called_once_with(
            None, "1234", algorithms=["RS256"], audience=SCOPED_PROJECT_ID)
        assert payload == JWT_PAYLOAD_SAMPLE.copy()

    def test_decode_and_verify_with_incorrect_token_and_key(self):
        app = firebase_admin.get_app()
        app_check_service = app_check._get_app_check_service(app)
        with pytest.raises(ValueError) as excinfo:
            app_check_service._decode_and_verify(
                token="1232132",
                signing_key=signing_key,
            )

        expected = (
            'Decoding App Check token failed. Error: Not enough segments')
        assert str(excinfo.value) == expected

    def test_decode_and_verify_with_expired_token(self):
        app = firebase_admin.get_app()
        app_check._get_app_check_service(app)
        with pytest.raises(ValueError) as excinfo:
            app_check.verify_token(EXPIRED_TOKEN, app)

        expected = (
            'The provided App Check token signature has expired.')
        assert str(excinfo.value) == expected

    def test_decode_and_verify_with_invalid_signature(self):
        app = firebase_admin.get_app()
        app_check._get_app_check_service(app)
        with pytest.raises(ValueError) as excinfo:
            app_check.verify_token(INVALID_SIGNATURE_TOKEN, app)

        expected = (
            'The provided App Check token signature cannot be verified.')
        assert str(excinfo.value) == expected

    def test_verify_token(self, mocker):
        mocker.patch("jwt.decode", return_value=JWT_PAYLOAD_SAMPLE)
        mocker.patch("jwt.PyJWKClient.get_signing_key_from_jwt", return_value=PyJWK(signing_key))
        mocker.patch("jwt.get_unverified_header", return_value=JWT_PAYLOAD_SAMPLE.get("headers"))
        app = firebase_admin.get_app()

        payload = app_check.verify_token("encoded", app)
        expected = JWT_PAYLOAD_SAMPLE.copy()
        expected['app_id'] = APP_ID
        assert payload == expected

    def test_verify_token_with_non_list_audience_raises_error(self, mocker):
        jwt_with_non_list_audience = JWT_PAYLOAD_SAMPLE.copy()
        jwt_with_non_list_audience["aud"] = '1234'
        mocker.patch("jwt.decode", return_value=jwt_with_non_list_audience)
        mocker.patch("jwt.PyJWKClient.get_signing_key_from_jwt", return_value=PyJWK(signing_key))
        mocker.patch("jwt.get_unverified_header", return_value=JWT_PAYLOAD_SAMPLE.get("headers"))
        app = firebase_admin.get_app()

        with pytest.raises(ValueError) as excinfo:
            app_check.verify_token("encoded", app)

        expected = 'Firebase App Check token has incorrect "aud" (audience) claim.'
        assert str(excinfo.value) == expected

    def test_verify_token_with_empty_list_audience_raises_error(self, mocker):
        jwt_with_empty_list_audience = JWT_PAYLOAD_SAMPLE.copy()
        jwt_with_empty_list_audience["aud"] = []
        mocker.patch("jwt.decode", return_value=jwt_with_empty_list_audience)
        mocker.patch("jwt.PyJWKClient.get_signing_key_from_jwt", return_value=PyJWK(signing_key))
        mocker.patch("jwt.get_unverified_header", return_value=JWT_PAYLOAD_SAMPLE.get("headers"))
        app = firebase_admin.get_app()

        with pytest.raises(ValueError) as excinfo:
            app_check.verify_token("encoded", app)

        expected = 'Firebase App Check token has incorrect "aud" (audience) claim.'
        assert str(excinfo.value) == expected

    def test_verify_token_with_incorrect_issuer_raises_error(self, mocker):
        jwt_with_non_incorrect_issuer = JWT_PAYLOAD_SAMPLE.copy()
        jwt_with_non_incorrect_issuer["iss"] = "https://dwyfrequency.googleapis.com/"
        mocker.patch("jwt.decode", return_value=jwt_with_non_incorrect_issuer)
        mocker.patch("jwt.PyJWKClient.get_signing_key_from_jwt", return_value=PyJWK(signing_key))
        mocker.patch("jwt.get_unverified_header", return_value=JWT_PAYLOAD_SAMPLE.get("headers"))
        app = firebase_admin.get_app()

        with pytest.raises(ValueError) as excinfo:
            app_check.verify_token("encoded", app)

        expected = 'Token does not contain the correct "iss" (issuer).'
        assert str(excinfo.value) == expected
