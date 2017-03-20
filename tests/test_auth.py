"""Test cases for firebase.auth module."""
import os
import time

from oauth2client import client
from oauth2client import crypt
import pytest

import firebase
from firebase import auth
from firebase import jwt
from tests import testutils


SERVICE_ACCOUNT_EMAIL = 'test-484@mg-test-1210.iam.gserviceaccount.com'
CLIENT_CERT_URL = ('https://www.googleapis.com/robot/v1/metadata/x509/'
                   'test-484%40mg-test-1210.iam.gserviceaccount.com')

FIREBASE_AUDIENCE = ('https://identitytoolkit.googleapis.com/'
                     'google.identity.identitytoolkit.v1.IdentityToolkit')
USER = 'user1'

CREDENTIAL = auth.CertificateCredential(
    testutils.resource_filename('service_account.json'))
PUBLIC_CERTS = testutils.resource('public_certs.json')
PRIVATE_KEY = testutils.resource('private_key.pem')


class AuthFixture(object):
    def __init__(self, name=None):
        if name:
            self.app = firebase.get_app(name)
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
    firebase.initialize_app({'credential': CREDENTIAL})
    firebase.initialize_app({'credential': CREDENTIAL}, 'testApp')

def teardown_module():
    firebase.delete_app('[DEFAULT]')
    firebase.delete_app('testApp')

@pytest.fixture(params=[None, 'testApp'], ids=['DefaultApp', 'CustomApp'])
def authtest(request):
    return AuthFixture(request.param)

@pytest.fixture
def non_cert_app():
    app = firebase.initialize_app(
        {'credential': auth.Credential()}, 'non-cert-app')
    yield app
    firebase.delete_app(app.name)

def verify_custom_token(custom_token, expected_claims):
    assert isinstance(custom_token, basestring)
    token = client.verify_id_token(
        custom_token,
        FIREBASE_AUDIENCE,
        http=testutils.HttpMock(200, PUBLIC_CERTS),
        cert_uri=CLIENT_CERT_URL)
    assert token['uid'] == USER
    assert token['iss'] == SERVICE_ACCOUNT_EMAIL
    assert token['sub'] == SERVICE_ACCOUNT_EMAIL
    header, _ = jwt.decode(custom_token)
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
    signer = crypt.Signer.from_string(PRIVATE_KEY)
    headers = {
        'kid': 'd98d290613ae1468f7e5f5cf604ead38ca9c8358'
    }
    payload = {
        'aud': 'mg-test-1210',
        'iss': 'https://securetoken.google.com/mg-test-1210',
        'iat': int(time.time()) - 100,
        'exp': int(time.time()) + 3600,
        'sub': '1234567890',
        'uid': USER,
        'admin': True,
    }
    if header_overrides:
        headers = _merge_jwt_claims(headers, header_overrides)
    if payload_overrides:
        payload = _merge_jwt_claims(payload, payload_overrides)
    return jwt.encode(payload, signer, headers=headers)


class TestCreateCustomToken(object):

    valid_args = {
        'Basic': (USER, {'one': 2, 'three': 'four'}),
        'NoDevClaims': (USER, None),
        'EmptyDevClaims': (USER, {}),
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
        'BoolClaims': (USER, True, ValueError),
        'IntClaims': (USER, 1, ValueError),
        'StrClaims': (USER, 'foo', ValueError),
        'ListClaims': (USER, [], ValueError),
        'TupleClaims': (USER, (1, 2), ValueError),
        'ReservedClaims': (USER, {'sub':'1234'}, ValueError),
    }

    @pytest.mark.parametrize('user,claims', valid_args.values(),
                             ids=valid_args.keys())
    def test_valid_params(self, authtest, user, claims):
        verify_custom_token(authtest.create_custom_token(user, claims), claims)

    @pytest.mark.parametrize('user,claims,error', invalid_args.values(),
                             ids=invalid_args.keys())
    def test_invalid_params(self, authtest, user, claims, error):
        with pytest.raises(error):
            authtest.create_custom_token(user, claims)

    def test_noncert_credential(self, non_cert_app):
        with pytest.raises(ValueError):
            auth.create_custom_token(USER, app=non_cert_app)


class TestVerifyIdToken(object):

    invalid_tokens = {
        'NoKid': (get_id_token(header_overrides={'kid': None}),
                  crypt.AppIdentityError),
        'WrongKid': (get_id_token(header_overrides={'kid': 'foo'}),
                     client.VerifyJwtTokenError),
        'WrongAlg': (get_id_token(header_overrides={'alg': 'HS256'}),
                     crypt.AppIdentityError),
        'BadAudience': (get_id_token({'aud': 'bad-audience'}),
                        crypt.AppIdentityError),
        'BadIssuer': (get_id_token({
            'iss': 'https://securetoken.google.com/wrong-issuer'
        }), crypt.AppIdentityError),
        'EmptySubject': (get_id_token({'sub': ''}),
                         crypt.AppIdentityError),
        'IntSubject': (get_id_token({'sub': 10}),
                       crypt.AppIdentityError),
        'LongStrSubject': (get_id_token({'sub': 'a' * 129}),
                           crypt.AppIdentityError),
        'FutureToken': (get_id_token({'iat': int(time.time()) + 1000}),
                        crypt.AppIdentityError),
        'ExpiredToken': (get_id_token({
            'iat': int(time.time()) - 10000,
            'exp': int(time.time()) - 3600
        }), crypt.AppIdentityError),
        'NoneToken': (None, ValueError),
        'EmptyToken': ('', ValueError),
        'BoolToken': (True, ValueError),
        'IntToken': (1, ValueError),
        'ListToken': ([], ValueError),
        'EmptyDictToken': ({}, ValueError),
        'NonEmptyDictToken': ({'a': 1}, ValueError),
        'BadFormatToken': ('foobar', crypt.AppIdentityError)
    }

    def setup_method(self):
        auth._http = testutils.HttpMock(200, PUBLIC_CERTS)

    def test_valid_token(self, authtest):
        id_token = get_id_token()
        claims = authtest.verify_id_token(id_token)
        assert claims['admin'] is True
        assert claims['uid'] == USER

    @pytest.mark.parametrize('id_token,error', invalid_tokens.values(),
                             ids=invalid_tokens.keys())
    def test_invalid_token(self, authtest, id_token, error):
        with pytest.raises(error):
            authtest.verify_id_token(id_token)

    def test_project_id_env_var(self, non_cert_app):
        id_token = get_id_token()
        gcloud_project = os.environ.get(auth.GCLOUD_PROJECT_ENV_VAR)
        try:
            os.environ[auth.GCLOUD_PROJECT_ENV_VAR] = 'mg-test-1210'
            claims = auth.verify_id_token(id_token, non_cert_app)
            assert claims['admin'] is True
            assert claims['uid'] == USER
        finally:
            if gcloud_project:
                os.environ[auth.GCLOUD_PROJECT_ENV_VAR] = gcloud_project
            else:
                del os.environ[auth.GCLOUD_PROJECT_ENV_VAR]

    def test_no_project_id(self, non_cert_app):
        id_token = get_id_token()
        gcloud_project = None
        if os.environ.has_key(auth.GCLOUD_PROJECT_ENV_VAR):
            gcloud_project = os.environ.get(auth.GCLOUD_PROJECT_ENV_VAR)
            del os.environ[auth.GCLOUD_PROJECT_ENV_VAR]
        try:
            with pytest.raises(ValueError):
                auth.verify_id_token(id_token, non_cert_app)
        finally:
            if gcloud_project:
                os.environ[auth.GCLOUD_PROJECT_ENV_VAR] = gcloud_project

    def test_custom_token(self, authtest):
        id_token = authtest.create_custom_token(USER)
        with pytest.raises(crypt.AppIdentityError):
            authtest.verify_id_token(id_token)

    def test_certificate_request_failure(self, authtest):
        id_token = get_id_token()
        auth._http = testutils.HttpMock(404, 'not found')
        with pytest.raises(client.VerifyJwtTokenError):
            authtest.verify_id_token(id_token)
