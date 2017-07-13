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

"""Test cases for firebase_admin.auth module."""
import os
import time

from google.auth import crypt
from google.auth import exceptions
from google.auth import jwt
import google.oauth2.id_token
import pytest
import six

import firebase_admin
from firebase_admin import auth
from firebase_admin import credentials
from tests import testutils


FIREBASE_AUDIENCE = ('https://identitytoolkit.googleapis.com/'
                     'google.identity.identitytoolkit.v1.IdentityToolkit')

MOCK_UID = 'user1'
MOCK_CREDENTIAL = credentials.Certificate(
    testutils.resource_filename('service_account.json'))
MOCK_PUBLIC_CERTS = testutils.resource('public_certs.json')
MOCK_PRIVATE_KEY = testutils.resource('private_key.pem')
MOCK_SERVICE_ACCOUNT_EMAIL = MOCK_CREDENTIAL.service_account_email


class AuthFixture(object):
    def __init__(self, name=None):
        if name:
            self.app = firebase_admin.get_app(name)
        else:
            self.app = None

    def create_custom_token(self, *args):
        if self.app:
            return auth.create_custom_token(*args, app=self.app)
        else:
            return auth.create_custom_token(*args)

    def verify_id_token(self, *args):
        if self.app:
            return auth.verify_id_token(*args, app=self.app)
        else:
            return auth.verify_id_token(*args)

def setup_module():
    firebase_admin.initialize_app(MOCK_CREDENTIAL)
    firebase_admin.initialize_app(MOCK_CREDENTIAL, name='testApp')

def teardown_module():
    firebase_admin.delete_app(firebase_admin.get_app())
    firebase_admin.delete_app(firebase_admin.get_app('testApp'))

@pytest.fixture(params=[None, 'testApp'], ids=['DefaultApp', 'CustomApp'])
def authtest(request):
    """Returns an AuthFixture instance.

    Instances returned by this fixture are parameterized to use either the defult App instance,
    or a custom App instance named 'testApp'. Due to this parameterization, each test case that
    depends on this fixture will get executed twice (as two test cases); once with the default
    App, and once with the custom App.
    """
    return AuthFixture(request.param)

@pytest.fixture
def non_cert_app():
    """Returns an App instance initialized with a mock non-cert credential.

    The lines of code following the yield statement are guaranteed to run after each test case
    that depends on this fixture. This ensures the proper cleanup of the App instance after
    tests.
    """
    app = firebase_admin.initialize_app(testutils.MockCredential(), name='non-cert-app')
    yield app
    firebase_admin.delete_app(app)

def verify_custom_token(custom_token, expected_claims):
    assert isinstance(custom_token, six.binary_type)
    token = google.oauth2.id_token.verify_token(
        custom_token,
        testutils.MockRequest(200, MOCK_PUBLIC_CERTS),
        FIREBASE_AUDIENCE)
    assert token['uid'] == MOCK_UID
    assert token['iss'] == MOCK_SERVICE_ACCOUNT_EMAIL
    assert token['sub'] == MOCK_SERVICE_ACCOUNT_EMAIL
    header = jwt.decode_header(custom_token)
    assert header.get('typ') == 'JWT'
    assert header.get('alg') == 'RS256'
    if expected_claims:
        for key, value in expected_claims.items():
            assert value == token['claims'][key]

def _merge_jwt_claims(defaults, overrides):
    defaults.update(overrides)
    for key, value in overrides.items():
        if value is None:
            del defaults[key]
    return defaults

def get_id_token(payload_overrides=None, header_overrides=None):
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
    }
    if header_overrides:
        headers = _merge_jwt_claims(headers, header_overrides)
    if payload_overrides:
        payload = _merge_jwt_claims(payload, payload_overrides)
    return jwt.encode(signer, payload, header=headers)


TEST_ID_TOKEN = get_id_token()


class TestCreateCustomToken(object):

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
        'ReservedClaims': (MOCK_UID, {'sub':'1234'}, ValueError),
    }

    @pytest.mark.parametrize('user,claims', valid_args.values(),
                             ids=list(valid_args))
    def test_valid_params(self, authtest, user, claims):
        verify_custom_token(authtest.create_custom_token(user, claims), claims)

    @pytest.mark.parametrize('user,claims,error', invalid_args.values(),
                             ids=list(invalid_args))
    def test_invalid_params(self, authtest, user, claims, error):
        with pytest.raises(error):
            authtest.create_custom_token(user, claims)

    def test_noncert_credential(self, non_cert_app):
        with pytest.raises(ValueError):
            auth.create_custom_token(MOCK_UID, app=non_cert_app)


class TestVerifyIdToken(object):

    valid_tokens = {
        'BinaryToken': TEST_ID_TOKEN,
        'TextToken': TEST_ID_TOKEN.decode('utf-8'),
    }

    invalid_tokens = {
        'NoKid': get_id_token(header_overrides={'kid': None}),
        'WrongKid': get_id_token(header_overrides={'kid': 'foo'}),
        'BadAudience': get_id_token({'aud': 'bad-audience'}),
        'BadIssuer': get_id_token({
            'iss': 'https://securetoken.google.com/wrong-issuer'
        }),
        'EmptySubject': get_id_token({'sub': ''}),
        'IntSubject': get_id_token({'sub': 10}),
        'LongStrSubject': get_id_token({'sub': 'a' * 129}),
        'FutureToken': get_id_token({'iat': int(time.time()) + 1000}),
        'ExpiredToken': get_id_token({
            'iat': int(time.time()) - 10000,
            'exp': int(time.time()) - 3600
        }),
        'NoneToken': None,
        'EmptyToken': '',
        'BoolToken': True,
        'IntToken': 1,
        'ListToken': [],
        'EmptyDictToken': {},
        'NonEmptyDictToken': {'a': 1},
        'BadFormatToken': 'foobar'
    }

    def setup_method(self):
        auth._request = testutils.MockRequest(200, MOCK_PUBLIC_CERTS)

    @pytest.mark.parametrize('id_token', valid_tokens.values(), ids=list(valid_tokens))
    def test_valid_token(self, authtest, id_token):
        claims = authtest.verify_id_token(id_token)
        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']

    @pytest.mark.parametrize('id_token', invalid_tokens.values(),
                             ids=list(invalid_tokens))
    def test_invalid_token(self, authtest, id_token):
        with pytest.raises(ValueError):
            authtest.verify_id_token(id_token)

    def test_project_id_env_var(self, non_cert_app):
        gcloud_project = os.environ.get(auth.GCLOUD_PROJECT_ENV_VAR)
        try:
            os.environ[auth.GCLOUD_PROJECT_ENV_VAR] = MOCK_CREDENTIAL.project_id
            claims = auth.verify_id_token(TEST_ID_TOKEN, non_cert_app)
            assert claims['admin'] is True
        finally:
            if gcloud_project:
                os.environ[auth.GCLOUD_PROJECT_ENV_VAR] = gcloud_project
            else:
                del os.environ[auth.GCLOUD_PROJECT_ENV_VAR]

    def test_no_project_id(self, non_cert_app):
        gcloud_project = os.environ.get(auth.GCLOUD_PROJECT_ENV_VAR)
        if gcloud_project:
            del os.environ[auth.GCLOUD_PROJECT_ENV_VAR]
        try:
            with pytest.raises(ValueError):
                auth.verify_id_token(TEST_ID_TOKEN, non_cert_app)
        finally:
            if gcloud_project:
                os.environ[auth.GCLOUD_PROJECT_ENV_VAR] = gcloud_project

    def test_custom_token(self, authtest):
        id_token = authtest.create_custom_token(MOCK_UID)
        with pytest.raises(ValueError):
            authtest.verify_id_token(id_token)

    def test_certificate_request_failure(self, authtest):
        auth._request = testutils.MockRequest(404, 'not found')
        with pytest.raises(exceptions.TransportError):
            authtest.verify_id_token(TEST_ID_TOKEN)


class TestUserManager(object):

    invalid_strings = [0, 1, True, False, list(), tuple(), dict()]
    invalid_bools = [None, '', 'foo', 0, 1, list(), tuple(), dict()]

    @pytest.mark.parametrize('arg', invalid_strings)
    def test_invalid_get_user(self, arg):
        with pytest.raises(ValueError):
            auth.get_user(arg)

    @pytest.mark.parametrize('arg', invalid_strings + ['a'*129])
    def test_invalid_uid(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'uid' : arg})

    @pytest.mark.parametrize('arg', invalid_strings + ['not-an-email'])
    def test_invalid_email(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'email' : arg})

    @pytest.mark.parametrize('arg', invalid_strings)
    def test_invalid_display_name(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'displayName' : arg})

    @pytest.mark.parametrize('arg', invalid_strings + ['not-a-url'])
    def test_invalid_photo_url(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'photoUrl' : arg})

    @pytest.mark.parametrize('arg', invalid_strings + ['short'])
    def test_invalid_password(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'password' : arg})

    @pytest.mark.parametrize('arg', invalid_bools)
    def test_invalid_email_verified(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'emailVerified' : arg})

    @pytest.mark.parametrize('arg', invalid_bools)
    def test_invalid_disabled(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'disabled' : arg})

    def test_invalid_property(self):
        with pytest.raises(ValueError):
            auth.create_user({'unsupported' : 'value'})
