# Copyright 2017 Google Inc.
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

"""Test cases for the firebase_admin._token_gen module."""

import base64
import datetime
import json
import os
import time

from google.auth import crypt
from google.auth import jwt
import google.auth.exceptions
import google.oauth2.id_token
import pytest
from pytest_localserver import plugin

import firebase_admin
from firebase_admin import auth
from firebase_admin import credentials
from firebase_admin import exceptions
from firebase_admin import _token_gen
from tests import testutils


MOCK_UID = 'user1'
MOCK_CREDENTIAL = credentials.Certificate(
    testutils.resource_filename('service_account.json'))
MOCK_PUBLIC_CERTS = testutils.resource('public_certs.json')
MOCK_PRIVATE_KEY = testutils.resource('private_key.pem')
MOCK_SERVICE_ACCOUNT_EMAIL = MOCK_CREDENTIAL.service_account_email
MOCK_REQUEST = testutils.MockRequest(200, MOCK_PUBLIC_CERTS)

INVALID_STRINGS = [None, '', 0, 1, True, False, list(), tuple(), dict()]
INVALID_BOOLS = [None, '', 'foo', 0, 1, list(), tuple(), dict()]
INVALID_JWT_ARGS = {
    'NoneToken': None,
    'EmptyToken': '',
    'BoolToken': True,
    'IntToken': 1,
    'ListToken': [],
    'EmptyDictToken': {},
    'NonEmptyDictToken': {'a': 1},
}

# Fixture for mocking a HTTP server
httpserver = plugin.httpserver


def _merge_jwt_claims(defaults, overrides):
    defaults.update(overrides)
    for key, value in overrides.items():
        if value is None:
            del defaults[key]
    return defaults

def verify_custom_token(custom_token, expected_claims, tenant_id=None):
    assert isinstance(custom_token, bytes)
    token = google.oauth2.id_token.verify_token(
        custom_token,
        testutils.MockRequest(200, MOCK_PUBLIC_CERTS),
        _token_gen.FIREBASE_AUDIENCE)
    assert token['uid'] == MOCK_UID
    assert token['iss'] == MOCK_SERVICE_ACCOUNT_EMAIL
    assert token['sub'] == MOCK_SERVICE_ACCOUNT_EMAIL
    if tenant_id is None:
        assert 'tenant_id' not in token
    else:
        assert token['tenant_id'] == tenant_id

    header = jwt.decode_header(custom_token)
    assert header.get('typ') == 'JWT'
    assert header.get('alg') == 'RS256'
    if expected_claims:
        for key, value in expected_claims.items():
            assert value == token['claims'][key]

def _get_id_token(payload_overrides=None, header_overrides=None):
    signer = crypt.RSASigner.from_string(MOCK_PRIVATE_KEY)
    headers = {
        'kid': 'mock-key-id-1'
    }
    payload = {
        'aud': MOCK_CREDENTIAL.project_id,
        'iss': 'https://securetoken.google.com/' + MOCK_CREDENTIAL.project_id,
        'iat': int(time.time()) - 100,
        'exp': int(time.time()) + 3600,
        'sub': '1234567890',
        'admin': True,
        'firebase': {
            'sign_in_provider': 'provider',
        },
    }
    if header_overrides:
        headers = _merge_jwt_claims(headers, header_overrides)
    if payload_overrides:
        payload = _merge_jwt_claims(payload, payload_overrides)
    return jwt.encode(signer, payload, header=headers)

def _get_session_cookie(payload_overrides=None, header_overrides=None):
    payload_overrides = payload_overrides or {}
    if 'iss' not in payload_overrides:
        payload_overrides['iss'] = 'https://session.firebase.google.com/{0}'.format(
            MOCK_CREDENTIAL.project_id)
    return _get_id_token(payload_overrides, header_overrides)

def _instrument_user_manager(app, status, payload):
    client = auth._get_client(app)
    user_manager = client._user_manager
    recorder = []
    user_manager.http_client.session.mount(
        _token_gen.TokenGenerator.ID_TOOLKIT_URL,
        testutils.MockAdapter(payload, status, recorder))
    return user_manager, recorder

def _overwrite_cert_request(app, request):
    client = auth._get_client(app)
    client._token_verifier.request = request

def _overwrite_iam_request(app, request):
    client = auth._get_client(app)
    client._token_generator.request = request

@pytest.fixture(scope='module')
def auth_app():
    """Returns an App initialized with a mock service account credential.

    This can be used in any scenario where the private key is required. Use user_mgt_app
    for everything else.
    """
    app = firebase_admin.initialize_app(MOCK_CREDENTIAL, name='tokenGen')
    yield app
    firebase_admin.delete_app(app)

@pytest.fixture(scope='module')
def user_mgt_app():
    app = firebase_admin.initialize_app(testutils.MockCredential(), name='userMgt',
                                        options={'projectId': 'mock-project-id'})
    yield app
    firebase_admin.delete_app(app)

@pytest.fixture
def env_var_app(request):
    """Returns an App instance initialized with the given set of environment variables.

    The lines of code following the yield statement are guaranteed to run after each test case
    that depends on this fixture. This ensures that the environment is left intact after the
    tests.
    """
    environ = os.environ
    os.environ = request.param
    app = firebase_admin.initialize_app(testutils.MockCredential(), name='env-var-app')
    yield app
    os.environ = environ
    firebase_admin.delete_app(app)

@pytest.fixture(scope='module')
def revoked_tokens():
    mock_user = json.loads(testutils.resource('get_user.json'))
    mock_user['users'][0]['validSince'] = str(int(time.time())+100)
    return json.dumps(mock_user)


class TestCreateCustomToken:

    valid_args = {
        'Basic': (MOCK_UID, {'one': 2, 'three': 'four'}),
        'NoDevClaims': (MOCK_UID, None),
        'EmptyDevClaims': (MOCK_UID, {}),
    }

    invalid_args = {
        'NoUid': (None, None, ValueError),
        'EmptyUid': ('', None, ValueError),
        'LongUid': ('x'*129, None, ValueError),
        'BoolUid': (True, None, ValueError),
        'IntUid': (1, None, ValueError),
        'ListUid': ([], None, ValueError),
        'EmptyDictUid': ({}, None, ValueError),
        'NonEmptyDictUid': ({'a':1}, None, ValueError),
        'BoolClaims': (MOCK_UID, True, ValueError),
        'IntClaims': (MOCK_UID, 1, ValueError),
        'StrClaims': (MOCK_UID, 'foo', ValueError),
        'ListClaims': (MOCK_UID, [], ValueError),
        'TupleClaims': (MOCK_UID, (1, 2), ValueError),
        'SingleReservedClaim': (MOCK_UID, {'sub':'1234'}, ValueError),
        'MultipleReservedClaims': (MOCK_UID, {'sub':'1234', 'aud':'foo'}, ValueError),
    }

    @pytest.mark.parametrize('values', valid_args.values(), ids=list(valid_args))
    def test_valid_params(self, auth_app, values):
        user, claims = values
        custom_token = auth.create_custom_token(user, claims, app=auth_app)
        verify_custom_token(custom_token, claims)

    @pytest.mark.parametrize('values', invalid_args.values(), ids=list(invalid_args))
    def test_invalid_params(self, auth_app, values):
        user, claims, error = values
        with pytest.raises(error):
            auth.create_custom_token(user, claims, app=auth_app)

    def test_noncert_credential(self, user_mgt_app):
        with pytest.raises(ValueError):
            auth.create_custom_token(MOCK_UID, app=user_mgt_app)

    def test_sign_with_iam(self):
        options = {'serviceAccountId': 'test-service-account', 'projectId': 'mock-project-id'}
        app = firebase_admin.initialize_app(
            testutils.MockCredential(), name='iam-signer-app', options=options)
        try:
            signature = base64.b64encode(b'test').decode()
            iam_resp = '{{"signature": "{0}"}}'.format(signature)
            _overwrite_iam_request(app, testutils.MockRequest(200, iam_resp))
            custom_token = auth.create_custom_token(MOCK_UID, app=app).decode()
            assert custom_token.endswith('.' + signature.rstrip('='))
            self._verify_signer(custom_token, 'test-service-account')
        finally:
            firebase_admin.delete_app(app)

    def test_sign_with_iam_error(self):
        options = {'serviceAccountId': 'test-service-account', 'projectId': 'mock-project-id'}
        app = firebase_admin.initialize_app(
            testutils.MockCredential(), name='iam-signer-app', options=options)
        try:
            iam_resp = '{"error": {"code": 403, "message": "test error"}}'
            _overwrite_iam_request(app, testutils.MockRequest(403, iam_resp))
            with pytest.raises(auth.TokenSignError) as excinfo:
                auth.create_custom_token(MOCK_UID, app=app)
            error = excinfo.value
            assert error.code == exceptions.UNKNOWN
            assert iam_resp in str(error)
            assert isinstance(error.cause, google.auth.exceptions.TransportError)
        finally:
            firebase_admin.delete_app(app)

    def test_sign_with_discovered_service_account(self):
        request = testutils.MockRequest(200, 'discovered-service-account')
        options = {'projectId': 'mock-project-id'}
        app = firebase_admin.initialize_app(testutils.MockCredential(), name='iam-signer-app',
                                            options=options)
        try:
            _overwrite_iam_request(app, request)
            # Force initialization of the signing provider. This will invoke the Metadata service.
            client = auth._get_client(app)
            assert client._token_generator.signing_provider is not None

            # Now invoke the IAM signer.
            signature = base64.b64encode(b'test').decode()
            request.response = testutils.MockResponse(
                200, '{{"signature": "{0}"}}'.format(signature))
            custom_token = auth.create_custom_token(MOCK_UID, app=app).decode()
            assert custom_token.endswith('.' + signature.rstrip('='))
            self._verify_signer(custom_token, 'discovered-service-account')
            assert len(request.log) == 2
            assert request.log[0][1]['headers'] == {'Metadata-Flavor': 'Google'}
        finally:
            firebase_admin.delete_app(app)

    def test_sign_with_discovery_failure(self):
        request = testutils.MockFailedRequest(Exception('test error'))
        options = {'projectId': 'mock-project-id'}
        app = firebase_admin.initialize_app(testutils.MockCredential(), name='iam-signer-app',
                                            options=options)
        try:
            _overwrite_iam_request(app, request)
            with pytest.raises(ValueError) as excinfo:
                auth.create_custom_token(MOCK_UID, app=app)
            assert str(excinfo.value).startswith('Failed to determine service account: test error')
            assert len(request.log) == 1
            assert request.log[0][1]['headers'] == {'Metadata-Flavor': 'Google'}
        finally:
            firebase_admin.delete_app(app)

    def _verify_signer(self, token, signer):
        segments = token.split('.')
        assert len(segments) == 3
        body = json.loads(base64.b64decode(segments[1]).decode())
        assert body['iss'] == signer
        assert body['sub'] == signer


class TestCreateSessionCookie:

    @pytest.mark.parametrize('id_token', [None, '', 0, 1, True, False, list(), dict(), tuple()])
    def test_invalid_id_token(self, user_mgt_app, id_token):
        with pytest.raises(ValueError):
            auth.create_session_cookie(id_token, expires_in=3600, app=user_mgt_app)

    @pytest.mark.parametrize('expires_in', [
        None, '', True, False, list(), dict(), tuple(),
        _token_gen.MIN_SESSION_COOKIE_DURATION_SECONDS - 1,
        _token_gen.MAX_SESSION_COOKIE_DURATION_SECONDS + 1,
    ])
    def test_invalid_expires_in(self, user_mgt_app, expires_in):
        with pytest.raises(ValueError):
            auth.create_session_cookie('id_token', expires_in=expires_in, app=user_mgt_app)

    @pytest.mark.parametrize('expires_in', [
        3600, datetime.timedelta(hours=1), datetime.timedelta(milliseconds=3600500)
    ])
    def test_valid_args(self, user_mgt_app, expires_in):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"sessionCookie": "cookie"}')
        cookie = auth.create_session_cookie('id_token', expires_in=expires_in, app=user_mgt_app)
        assert cookie == 'cookie'
        request = json.loads(recorder[0].body.decode())
        assert request == {'idToken' : 'id_token', 'validDuration': 3600}

    def test_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":{"message": "INVALID_ID_TOKEN"}}')
        with pytest.raises(auth.InvalidIdTokenError) as excinfo:
            auth.create_session_cookie('id_token', expires_in=3600, app=user_mgt_app)
        assert excinfo.value.code == exceptions.INVALID_ARGUMENT
        assert str(excinfo.value) == 'The provided ID token is invalid (INVALID_ID_TOKEN).'

    def test_error_with_details(self, user_mgt_app):
        _instrument_user_manager(
            user_mgt_app, 500, '{"error":{"message": "INVALID_ID_TOKEN: More details."}}')
        with pytest.raises(auth.InvalidIdTokenError) as excinfo:
            auth.create_session_cookie('id_token', expires_in=3600, app=user_mgt_app)
        assert excinfo.value.code == exceptions.INVALID_ARGUMENT
        expected = 'The provided ID token is invalid (INVALID_ID_TOKEN). More details.'
        assert str(excinfo.value) == expected

    def test_unexpected_error_code(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":{"message": "SOMETHING_UNUSUAL"}}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.create_session_cookie('id_token', expires_in=3600, app=user_mgt_app)
        assert str(excinfo.value) == 'Error while calling Auth service (SOMETHING_UNUSUAL).'

    def test_unexpected_error_response(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.create_session_cookie('id_token', expires_in=3600, app=user_mgt_app)
        assert str(excinfo.value) == 'Unexpected error response: {}'

    def test_unexpected_response(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{}')
        with pytest.raises(auth.UnexpectedResponseError) as excinfo:
            auth.create_session_cookie('id_token', expires_in=3600, app=user_mgt_app)
        assert excinfo.value.code == exceptions.UNKNOWN
        assert 'Failed to create session cookie' in str(excinfo.value)


MOCK_GET_USER_RESPONSE = testutils.resource('get_user.json')
TEST_ID_TOKEN = _get_id_token()
TEST_ID_TOKEN_WITH_TENANT = _get_id_token({
    'firebase': {
        'tenant': 'test-tenant',
    }
})
TEST_SESSION_COOKIE = _get_session_cookie()


class TestVerifyIdToken:

    valid_tokens = {
        'BinaryToken': TEST_ID_TOKEN,
        'TextToken': TEST_ID_TOKEN.decode('utf-8'),
    }

    invalid_tokens = {
        'NoKid': _get_id_token(header_overrides={'kid': None}),
        'WrongKid': _get_id_token(header_overrides={'kid': 'foo'}),
        'BadAudience': _get_id_token({'aud': 'bad-audience'}),
        'BadIssuer': _get_id_token({
            'iss': 'https://securetoken.google.com/wrong-issuer'
        }),
        'EmptySubject': _get_id_token({'sub': ''}),
        'IntSubject': _get_id_token({'sub': 10}),
        'LongStrSubject': _get_id_token({'sub': 'a' * 129}),
        'FutureToken': _get_id_token({'iat': int(time.time()) + 1000}),
        'ExpiredToken': _get_id_token({
            'iat': int(time.time()) - 10000,
            'exp': int(time.time()) - 3600
        }),
        'BadFormatToken': 'foobar'
    }

    @pytest.mark.parametrize('id_token', valid_tokens.values(), ids=list(valid_tokens))
    def test_valid_token(self, user_mgt_app, id_token):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        claims = auth.verify_id_token(id_token, app=user_mgt_app)
        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']
        assert claims['firebase']['sign_in_provider'] == 'provider'

    def test_valid_token_with_tenant(self, user_mgt_app):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        claims = auth.verify_id_token(TEST_ID_TOKEN_WITH_TENANT, app=user_mgt_app)
        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']
        assert claims['firebase']['tenant'] == 'test-tenant'

    @pytest.mark.parametrize('id_token', valid_tokens.values(), ids=list(valid_tokens))
    def test_valid_token_check_revoked(self, user_mgt_app, id_token):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_RESPONSE)
        claims = auth.verify_id_token(id_token, app=user_mgt_app, check_revoked=True)
        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']

    @pytest.mark.parametrize('id_token', valid_tokens.values(), ids=list(valid_tokens))
    def test_revoked_token_check_revoked(self, user_mgt_app, revoked_tokens, id_token):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        _instrument_user_manager(user_mgt_app, 200, revoked_tokens)
        with pytest.raises(auth.RevokedIdTokenError) as excinfo:
            auth.verify_id_token(id_token, app=user_mgt_app, check_revoked=True)
        assert str(excinfo.value) == 'The Firebase ID token has been revoked.'

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_check_revoked(self, user_mgt_app, arg):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        with pytest.raises(ValueError):
            auth.verify_id_token('id_token', check_revoked=arg, app=user_mgt_app)

    @pytest.mark.parametrize('id_token', valid_tokens.values(), ids=list(valid_tokens))
    def test_revoked_token_do_not_check_revoked(self, user_mgt_app, revoked_tokens, id_token):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        _instrument_user_manager(user_mgt_app, 200, revoked_tokens)
        claims = auth.verify_id_token(id_token, app=user_mgt_app, check_revoked=False)
        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']

    @pytest.mark.parametrize('id_token', INVALID_JWT_ARGS.values(), ids=list(INVALID_JWT_ARGS))
    def test_invalid_arg(self, user_mgt_app, id_token):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        with pytest.raises(ValueError) as excinfo:
            auth.verify_id_token(id_token, app=user_mgt_app)
        assert 'Illegal ID token provided' in str(excinfo.value)

    @pytest.mark.parametrize('id_token', invalid_tokens.values(), ids=list(invalid_tokens))
    def test_invalid_token(self, user_mgt_app, id_token):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        with pytest.raises(auth.InvalidIdTokenError) as excinfo:
            auth.verify_id_token(id_token, app=user_mgt_app)
        assert isinstance(excinfo.value, exceptions.InvalidArgumentError)
        assert excinfo.value.http_response is None

    def test_expired_token(self, user_mgt_app):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        id_token = self.invalid_tokens['ExpiredToken']
        with pytest.raises(auth.ExpiredIdTokenError) as excinfo:
            auth.verify_id_token(id_token, app=user_mgt_app)
        assert isinstance(excinfo.value, auth.InvalidIdTokenError)
        assert 'Token expired' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is None

    def test_project_id_option(self):
        app = firebase_admin.initialize_app(
            testutils.MockCredential(), options={'projectId': 'mock-project-id'}, name='myApp')
        _overwrite_cert_request(app, MOCK_REQUEST)
        try:
            claims = auth.verify_id_token(TEST_ID_TOKEN, app)
            assert claims['admin'] is True
            assert claims['uid'] == claims['sub']
        finally:
            firebase_admin.delete_app(app)

    @pytest.mark.parametrize('env_var_app', [
        {'GCLOUD_PROJECT': 'mock-project-id'},
        {'GOOGLE_CLOUD_PROJECT': 'mock-project-id'}
    ], indirect=True)
    def test_project_id_env_var(self, env_var_app):
        _overwrite_cert_request(env_var_app, MOCK_REQUEST)
        claims = auth.verify_id_token(TEST_ID_TOKEN, env_var_app)
        assert claims['admin'] is True

    def test_custom_token(self, auth_app):
        id_token = auth.create_custom_token(MOCK_UID, app=auth_app)
        _overwrite_cert_request(auth_app, MOCK_REQUEST)
        with pytest.raises(auth.InvalidIdTokenError) as excinfo:
            auth.verify_id_token(id_token, app=auth_app)
        message = 'verify_id_token() expects an ID token, but was given a custom token.'
        assert str(excinfo.value) == message

    def test_certificate_request_failure(self, user_mgt_app):
        _overwrite_cert_request(user_mgt_app, testutils.MockRequest(404, 'not found'))
        with pytest.raises(auth.CertificateFetchError) as excinfo:
            auth.verify_id_token(TEST_ID_TOKEN, app=user_mgt_app)
        assert 'Could not fetch certificates' in str(excinfo.value)
        assert isinstance(excinfo.value, exceptions.UnknownError)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is None


class TestVerifySessionCookie:

    valid_cookies = {
        'BinaryCookie': TEST_SESSION_COOKIE,
        'TextCookie': TEST_SESSION_COOKIE.decode('utf-8'),
    }

    invalid_cookies = {
        'NoKid': _get_session_cookie(header_overrides={'kid': None}),
        'WrongKid': _get_session_cookie(header_overrides={'kid': 'foo'}),
        'BadAudience': _get_session_cookie({'aud': 'bad-audience'}),
        'BadIssuer': _get_session_cookie({
            'iss': 'https://session.firebase.google.com/wrong-issuer'
        }),
        'EmptySubject': _get_session_cookie({'sub': ''}),
        'IntSubject': _get_session_cookie({'sub': 10}),
        'LongStrSubject': _get_session_cookie({'sub': 'a' * 129}),
        'FutureCookie': _get_session_cookie({'iat': int(time.time()) + 1000}),
        'ExpiredCookie': _get_session_cookie({
            'iat': int(time.time()) - 10000,
            'exp': int(time.time()) - 3600
        }),
        'BadFormatCookie': 'foobar',
        'IDToken': TEST_ID_TOKEN,
    }

    @pytest.mark.parametrize('cookie', valid_cookies.values(), ids=list(valid_cookies))
    def test_valid_cookie(self, user_mgt_app, cookie):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        claims = auth.verify_session_cookie(cookie, app=user_mgt_app)
        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']

    @pytest.mark.parametrize('cookie', valid_cookies.values(), ids=list(valid_cookies))
    def test_valid_cookie_check_revoked(self, user_mgt_app, cookie):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_RESPONSE)
        claims = auth.verify_session_cookie(cookie, app=user_mgt_app, check_revoked=True)
        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']

    @pytest.mark.parametrize('cookie', valid_cookies.values(), ids=list(valid_cookies))
    def test_revoked_cookie_check_revoked(self, user_mgt_app, revoked_tokens, cookie):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        _instrument_user_manager(user_mgt_app, 200, revoked_tokens)
        with pytest.raises(auth.RevokedSessionCookieError) as excinfo:
            auth.verify_session_cookie(cookie, app=user_mgt_app, check_revoked=True)
        assert str(excinfo.value) == 'The Firebase session cookie has been revoked.'

    @pytest.mark.parametrize('cookie', valid_cookies.values(), ids=list(valid_cookies))
    def test_revoked_cookie_does_not_check_revoked(self, user_mgt_app, revoked_tokens, cookie):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        _instrument_user_manager(user_mgt_app, 200, revoked_tokens)
        claims = auth.verify_session_cookie(cookie, app=user_mgt_app, check_revoked=False)
        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']

    @pytest.mark.parametrize('cookie', INVALID_JWT_ARGS.values(), ids=list(INVALID_JWT_ARGS))
    def test_invalid_args(self, user_mgt_app, cookie):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        with pytest.raises(ValueError) as excinfo:
            auth.verify_session_cookie(cookie, app=user_mgt_app)
        assert 'Illegal session cookie provided' in str(excinfo.value)

    @pytest.mark.parametrize('cookie', invalid_cookies.values(), ids=list(invalid_cookies))
    def test_invalid_cookie(self, user_mgt_app, cookie):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        with pytest.raises(auth.InvalidSessionCookieError) as excinfo:
            auth.verify_session_cookie(cookie, app=user_mgt_app)
        assert isinstance(excinfo.value, exceptions.InvalidArgumentError)
        assert excinfo.value.http_response is None

    def test_expired_cookie(self, user_mgt_app):
        _overwrite_cert_request(user_mgt_app, MOCK_REQUEST)
        cookie = self.invalid_cookies['ExpiredCookie']
        with pytest.raises(auth.ExpiredSessionCookieError) as excinfo:
            auth.verify_session_cookie(cookie, app=user_mgt_app)
        assert isinstance(excinfo.value, auth.InvalidSessionCookieError)
        assert 'Token expired' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is None

    def test_project_id_option(self):
        app = firebase_admin.initialize_app(
            testutils.MockCredential(), options={'projectId': 'mock-project-id'}, name='myApp')
        _overwrite_cert_request(app, MOCK_REQUEST)
        try:
            claims = auth.verify_session_cookie(TEST_SESSION_COOKIE, app=app)
            assert claims['admin'] is True
            assert claims['uid'] == claims['sub']
        finally:
            firebase_admin.delete_app(app)

    @pytest.mark.parametrize('env_var_app', [{'GCLOUD_PROJECT': 'mock-project-id'}], indirect=True)
    def test_project_id_env_var(self, env_var_app):
        _overwrite_cert_request(env_var_app, MOCK_REQUEST)
        claims = auth.verify_session_cookie(TEST_SESSION_COOKIE, app=env_var_app)
        assert claims['admin'] is True

    def test_custom_token(self, auth_app):
        custom_token = auth.create_custom_token(MOCK_UID, app=auth_app)
        _overwrite_cert_request(auth_app, MOCK_REQUEST)
        with pytest.raises(auth.InvalidSessionCookieError):
            auth.verify_session_cookie(custom_token, app=auth_app)

    def test_certificate_request_failure(self, user_mgt_app):
        _overwrite_cert_request(user_mgt_app, testutils.MockRequest(404, 'not found'))
        with pytest.raises(auth.CertificateFetchError) as excinfo:
            auth.verify_session_cookie(TEST_SESSION_COOKIE, app=user_mgt_app)
        assert 'Could not fetch certificates' in str(excinfo.value)
        assert isinstance(excinfo.value, exceptions.UnknownError)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is None


class TestCertificateCaching:

    def test_certificate_caching(self, user_mgt_app, httpserver):
        httpserver.serve_content(MOCK_PUBLIC_CERTS, 200, headers={'Cache-Control': 'max-age=3600'})
        verifier = _token_gen.TokenVerifier(user_mgt_app)
        verifier.cookie_verifier.cert_url = httpserver.url
        verifier.id_token_verifier.cert_url = httpserver.url
        verifier.verify_session_cookie(TEST_SESSION_COOKIE)
        assert len(httpserver.requests) == 1
        # Subsequent requests should not fetch certs from the server
        verifier.verify_session_cookie(TEST_SESSION_COOKIE)
        assert len(httpserver.requests) == 1
        verifier.verify_id_token(TEST_ID_TOKEN)
        assert len(httpserver.requests) == 1
