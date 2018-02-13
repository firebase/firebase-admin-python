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

"""Test cases for the firebase_admin.auth module."""
import json
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
from firebase_admin import _user_mgt
from tests import testutils


FIREBASE_AUDIENCE = ('https://identitytoolkit.googleapis.com/'
                     'google.identity.identitytoolkit.v1.IdentityToolkit')
GCLOUD_PROJECT_ENV_VAR = 'GCLOUD_PROJECT'

MOCK_UID = 'user1'
MOCK_CREDENTIAL = credentials.Certificate(
    testutils.resource_filename('service_account.json'))
MOCK_PUBLIC_CERTS = testutils.resource('public_certs.json')
MOCK_PRIVATE_KEY = testutils.resource('private_key.pem')
MOCK_SERVICE_ACCOUNT_EMAIL = MOCK_CREDENTIAL.service_account_email

INVALID_STRINGS = [None, '', 0, 1, True, False, list(), tuple(), dict()]
INVALID_BOOLS = [None, '', 'foo', 0, 1, list(), tuple(), dict()]
INVALID_DICTS = [None, 'foo', 0, 1, True, False, list(), tuple()]
INVALID_POSITIVE_NUMS = [None, 'foo', 0, -1, True, False, list(), tuple(), dict()]


MOCK_GET_USER_RESPONSE = testutils.resource('get_user.json')
MOCK_LIST_USERS_RESPONSE = testutils.resource('list_users.json')

def _revoked_tokens_response():
    mock_user = json.loads(testutils.resource('get_user.json'))
    mock_user['users'][0]['validSince'] = str(int(time.time())+100)
    return json.dumps(mock_user)

MOCK_GET_USER_REVOKED_TOKENS_RESPONSE = _revoked_tokens_response()

class AuthFixture(object):
    def __init__(self, name=None):
        if name:
            self.app = firebase_admin.get_app(name)
        else:
            self.app = None

    def create_custom_token(self, *args):
        if self.app:
            return auth.create_custom_token(*args, app=self.app)
        return auth.create_custom_token(*args)

    # Using **kwargs to pass along the check_revoked if passed.
    def verify_id_token(self, *args, **kwargs):
        if self.app:
            return auth.verify_id_token(*args, app=self.app, **kwargs)
        return auth.verify_id_token(*args, **kwargs)

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
        'SingleReservedClaim': (MOCK_UID, {'sub':'1234'}, ValueError),
        'MultipleReservedClaims': (MOCK_UID, {'sub':'1234', 'aud':'foo'}, ValueError),
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

    @pytest.mark.parametrize('id_token', valid_tokens.values(), ids=list(valid_tokens))
    def test_valid_token_check_revoked(self, user_mgt_app, id_token):
        _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_RESPONSE)
        claims = auth.verify_id_token(id_token, app=user_mgt_app, check_revoked=True)
        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']

    @pytest.mark.parametrize('id_token', valid_tokens.values(), ids=list(valid_tokens))
    def test_revoked_token_check_revoked(self, user_mgt_app, id_token):
        _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_REVOKED_TOKENS_RESPONSE)

        with pytest.raises(auth.AuthError) as excinfo:
            auth.verify_id_token(id_token, app=user_mgt_app, check_revoked=True)

        assert excinfo.value.code == 'ID_TOKEN_REVOKED'
        assert str(excinfo.value) == 'The Firebase ID token has been revoked.'

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_check_revoked(self, arg):
        with pytest.raises(ValueError):
            auth.verify_id_token("id_token", check_revoked=arg)

    @pytest.mark.parametrize('id_token', valid_tokens.values(), ids=list(valid_tokens))
    def test_revoked_token_do_not_check_revoked(self, user_mgt_app, id_token):
        _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_REVOKED_TOKENS_RESPONSE)
        claims = auth.verify_id_token(id_token, app=user_mgt_app, check_revoked=False)
        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']

    def test_revoke_refresh_tokens(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        before_time = time.time()
        auth.revoke_refresh_tokens('testuser', app=user_mgt_app)
        after_time = time.time()

        request = json.loads(recorder[0].body.decode())
        assert request['localId'] == 'testuser'
        assert int(request['validSince']) >= int(before_time)
        assert int(request['validSince']) <= int(after_time)

    @pytest.mark.parametrize('id_token', invalid_tokens.values(), ids=list(invalid_tokens))
    def test_invalid_token(self, authtest, id_token):
        with pytest.raises(ValueError):
            authtest.verify_id_token(id_token)

    def test_project_id_option(self):
        app = firebase_admin.initialize_app(
            testutils.MockCredential(), options={'projectId': 'mock-project-id'}, name='myApp')
        try:
            claims = auth.verify_id_token(TEST_ID_TOKEN, app)
            assert claims['admin'] is True
            assert claims['uid'] == claims['sub']
        finally:
            firebase_admin.delete_app(app)

    @pytest.mark.parametrize('env_var_app', [{'GCLOUD_PROJECT': 'mock-project-id'}], indirect=True)
    def test_project_id_env_var(self, env_var_app):
        claims = auth.verify_id_token(TEST_ID_TOKEN, env_var_app)
        assert claims['admin'] is True

    @pytest.mark.parametrize('env_var_app', [{}], indirect=True)
    def test_no_project_id(self, env_var_app):
        with pytest.raises(ValueError):
            auth.verify_id_token(TEST_ID_TOKEN, env_var_app)

    def test_custom_token(self, authtest):
        id_token = authtest.create_custom_token(MOCK_UID)
        with pytest.raises(ValueError):
            authtest.verify_id_token(id_token)

    def test_certificate_request_failure(self, authtest):
        auth._request = testutils.MockRequest(404, 'not found')
        with pytest.raises(exceptions.TransportError):
            authtest.verify_id_token(TEST_ID_TOKEN)


@pytest.fixture(scope='module')
def user_mgt_app():
    app = firebase_admin.initialize_app(testutils.MockCredential(), name='userMgt',
                                        options={'projectId': 'mock-project-id'})
    yield app
    firebase_admin.delete_app(app)

def _instrument_user_manager(app, status, payload):
    auth_service = auth._get_auth_service(app)
    user_manager = auth_service.user_manager
    recorder = []
    user_manager._session.mount(
        _user_mgt.ID_TOOLKIT_URL,
        testutils.MockAdapter(payload, status, recorder))
    return user_manager, recorder

def _check_user_record(user, expected_uid='testuser'):
    assert isinstance(user, auth.UserRecord)
    assert user.uid == expected_uid
    assert user.email == 'testuser@example.com'
    assert user.phone_number == '+1234567890'
    assert user.display_name == 'Test User'
    assert user.photo_url == 'http://www.example.com/testuser/photo.png'
    assert user.disabled is False
    assert user.email_verified is True
    assert user.user_metadata.creation_timestamp == 1234567890000
    assert user.user_metadata.last_sign_in_timestamp is None
    assert user.provider_id == 'firebase'

    claims = user.custom_claims
    assert claims['admin'] is True
    assert claims['package'] == 'gold'

    assert len(user.provider_data) == 2
    provider = user.provider_data[0]
    assert provider.uid == 'testuser@example.com'
    assert provider.email == 'testuser@example.com'
    assert provider.phone_number is None
    assert provider.display_name == 'Test User'
    assert provider.photo_url == 'http://www.example.com/testuser/photo.png'
    assert provider.provider_id == 'password'

    provider = user.provider_data[1]
    assert provider.uid == '+1234567890'
    assert provider.email is None
    assert provider.phone_number == '+1234567890'
    assert provider.display_name is None
    assert provider.photo_url is None
    assert provider.provider_id == 'phone'


class TestUserRecord(object):

    # Input dict must be non-empty, and must not contain unsupported keys.
    @pytest.mark.parametrize('data', INVALID_DICTS + [{}, {'foo':'bar'}])
    def test_invalid_record(self, data):
        with pytest.raises(ValueError):
            auth.UserRecord(data)

    @pytest.mark.parametrize('data', INVALID_DICTS)
    def test_invalid_metadata(self, data):
        with pytest.raises(ValueError):
            auth.UserMetadata(data)

    def test_metadata(self):
        metadata = auth.UserMetadata({'createdAt' : 10, 'lastLoginAt' : 20})
        assert metadata.creation_timestamp == 10
        assert metadata.last_sign_in_timestamp == 20
        metadata = auth.UserMetadata({})
        assert metadata.creation_timestamp is None
        assert metadata.last_sign_in_timestamp is None

    def test_exported_record(self):
        user = auth.ExportedUserRecord({
            'localId' : 'user',
            'passwordHash' : 'passwordHash',
            'salt' : 'passwordSalt',
        })
        assert user.uid == 'user'
        assert user.password_hash == 'passwordHash'
        assert user.password_salt == 'passwordSalt'

    def test_exported_record_no_password(self):
        user = auth.ExportedUserRecord({
            'localId' : 'user',
        })
        assert user.uid == 'user'
        assert user.password_hash is None
        assert user.password_salt is None

    def test_exported_record_empty_password(self):
        user = auth.ExportedUserRecord({
            'localId' : 'user',
            'passwordHash' : '',
            'salt' : '',
        })
        assert user.uid == 'user'
        assert user.password_hash == ''
        assert user.password_salt == ''

    def test_custom_claims(self):
        user = auth.UserRecord({
            'localId' : 'user',
            'customAttributes': '{"admin": true, "package": "gold"}'
        })
        assert user.custom_claims == {'admin' : True, 'package' : 'gold'}

    def test_no_custom_claims(self):
        user = auth.UserRecord({'localId' : 'user'})
        assert user.custom_claims is None

    def test_empty_custom_claims(self):
        user = auth.UserRecord({'localId' : 'user', 'customAttributes' : '{}'})
        assert user.custom_claims is None

    @pytest.mark.parametrize('data', INVALID_DICTS + [{}, {'foo':'bar'}])
    def test_invalid_provider(self, data):
        with pytest.raises(ValueError):
            auth._ProviderUserInfo(data)


class TestGetUser(object):

    VALID_UID = 'testuser'
    VALID_EMAIL = 'testuser@example.com'
    VALID_PHONE = '+1234567890'

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_get_user(self, arg):
        with pytest.raises(ValueError):
            auth.get_user(arg)

    def test_get_user(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_RESPONSE)
        _check_user_record(auth.get_user(self.VALID_UID, user_mgt_app))

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-an-email'])
    def test_invalid_get_user_by_email(self, arg):
        with pytest.raises(ValueError):
            auth.get_user_by_email(arg)

    def test_get_user_by_email(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_RESPONSE)
        _check_user_record(auth.get_user_by_email(self.VALID_EMAIL, user_mgt_app))

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-a-phone'])
    def test_invalid_get_user_by_phone(self, arg):
        with pytest.raises(ValueError):
            auth.get_user_by_phone_number(arg)

    def test_get_user_by_phone(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_RESPONSE)
        _check_user_record(auth.get_user_by_phone_number(self.VALID_PHONE, user_mgt_app))

    def test_get_user_non_existing(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{"users":[]}')
        with pytest.raises(auth.AuthError) as excinfo:
            auth.get_user('nonexistentuser', user_mgt_app)
        assert excinfo.value.code == _user_mgt.USER_NOT_FOUND_ERROR

    def test_get_user_http_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(auth.AuthError) as excinfo:
            auth.get_user('testuser', user_mgt_app)
        assert excinfo.value.code == _user_mgt.INTERNAL_ERROR
        assert '{"error":"test"}' in str(excinfo.value)

    def test_get_user_by_email_http_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(auth.AuthError) as excinfo:
            auth.get_user_by_email('non.existent.user@example.com', user_mgt_app)
        assert excinfo.value.code == _user_mgt.INTERNAL_ERROR
        assert '{"error":"test"}' in str(excinfo.value)

    def test_get_user_by_phone_http_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(auth.AuthError) as excinfo:
            auth.get_user_by_phone_number(self.VALID_PHONE, user_mgt_app)
        assert excinfo.value.code == _user_mgt.INTERNAL_ERROR
        assert '{"error":"test"}' in str(excinfo.value)


class TestCreateUser(object):

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_uid(self, arg):
        with pytest.raises(ValueError):
            auth.create_user(uid=arg)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-an-email'])
    def test_invalid_email(self, arg):
        with pytest.raises(ValueError):
            auth.create_user(email=arg)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-a-phone', '+'])
    def test_invalid_phone(self, arg):
        with pytest.raises(ValueError):
            auth.create_user(phone_number=arg)

    @pytest.mark.parametrize('arg', INVALID_STRINGS)
    def test_invalid_display_name(self, arg):
        with pytest.raises(ValueError):
            auth.create_user(display_name=arg)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-a-url'])
    def test_invalid_photo_url(self, arg):
        with pytest.raises(ValueError):
            auth.create_user(photo_url=arg)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['short'])
    def test_invalid_password(self, arg):
        with pytest.raises(ValueError):
            auth.create_user(password=arg)

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_email_verified(self, arg):
        with pytest.raises(ValueError):
            auth.create_user(email_verified=arg)

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_disabled(self, arg):
        with pytest.raises(ValueError):
            auth.create_user(disabled=arg)

    def test_invalid_property(self):
        with pytest.raises(ValueError):
            auth.create_user(unsupported='value')

    def test_create_user(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        assert user_mgt.create_user() == 'testuser'
        request = json.loads(recorder[0].body.decode())
        assert request == {}

    @pytest.mark.parametrize('phone', [
        '+11234567890', '+1 123 456 7890', '+1 (123) 456-7890',
    ])
    def test_create_user_with_phone(self, user_mgt_app, phone):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        assert user_mgt.create_user(phone_number=phone) == 'testuser'
        request = json.loads(recorder[0].body.decode())
        assert request == {'phoneNumber' : phone}

    def test_create_user_with_email(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        assert user_mgt.create_user(email='test@example.com') == 'testuser'
        request = json.loads(recorder[0].body.decode())
        assert request == {'email' : 'test@example.com'}

    def test_create_user_with_id(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        assert user_mgt.create_user(uid='testuser') == 'testuser'
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser'}

    def test_create_user_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(auth.AuthError) as excinfo:
            auth.create_user(app=user_mgt_app)
        assert excinfo.value.code == _user_mgt.USER_CREATE_ERROR
        assert '{"error":"test"}' in str(excinfo.value)


class TestUpdateUser(object):

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_uid(self, arg):
        with pytest.raises(ValueError):
            auth.update_user(arg)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-an-email'])
    def test_invalid_email(self, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', email=arg)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['not-a-phone', '+'])
    def test_invalid_phone(self, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', phone_number=arg)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:])
    def test_invalid_display_name(self, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', display_name=arg)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['not-a-url'])
    def test_invalid_photo_url(self, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', photo_url=arg)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['short'])
    def test_invalid_password(self, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', password=arg)

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_email_verified(self, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', email_verified=arg)

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_disabled(self, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', disabled=arg)

    @pytest.mark.parametrize('arg', INVALID_DICTS[1:] + ['"json"'])
    def test_invalid_custom_claims(self, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', custom_claims=arg)

    def test_invalid_property(self):
        with pytest.raises(ValueError):
            auth.update_user('user', unsupported='arg')

    @pytest.mark.parametrize('arg', INVALID_POSITIVE_NUMS)
    def test_invalid_valid_since(self, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', valid_since=arg)

    def test_update_user(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        user_mgt.update_user('testuser')
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser'}

    def test_disable_user(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        user_mgt.update_user('testuser', disabled=True)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser', 'disableUser' : True}

    def test_update_user_custom_claims(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        claims = {'admin':True, 'package':'gold'}
        user_mgt.update_user('testuser', custom_claims=claims)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser', 'customAttributes' : json.dumps(claims)}

    def test_update_user_delete_fields(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        user_mgt.update_user('testuser', display_name=None, photo_url=None, phone_number=None)
        request = json.loads(recorder[0].body.decode())
        assert request == {
            'localId' : 'testuser',
            'deleteAttribute' : ['DISPLAY_NAME', 'PHOTO_URL'],
            'deleteProvider' : ['phone'],
        }

    def test_update_user_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(auth.AuthError) as excinfo:
            auth.update_user('user', app=user_mgt_app)
        assert excinfo.value.code == _user_mgt.USER_UPDATE_ERROR
        assert '{"error":"test"}' in str(excinfo.value)

    def test_update_user_valid_since(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        user_mgt.update_user('testuser', valid_since=1)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId': 'testuser', 'validSince': 1}


class TestSetCustomUserClaims(object):

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_uid(self, arg):
        with pytest.raises(ValueError):
            auth.set_custom_user_claims(arg, {'foo': 'bar'})

    @pytest.mark.parametrize('arg', INVALID_DICTS[1:] + ['"json"'])
    def test_invalid_custom_claims(self, arg):
        with pytest.raises(ValueError):
            auth.set_custom_user_claims('user', arg)

    @pytest.mark.parametrize('key', _user_mgt.RESERVED_CLAIMS)
    def test_single_reserved_claim(self, key):
        claims = {key : 'value'}
        with pytest.raises(ValueError) as excinfo:
            auth.set_custom_user_claims('user', claims)
        assert str(excinfo.value) == 'Claim "{0}" is reserved, and must not be set.'.format(key)

    def test_multiple_reserved_claims(self):
        claims = {key : 'value' for key in _user_mgt.RESERVED_CLAIMS}
        with pytest.raises(ValueError) as excinfo:
            auth.set_custom_user_claims('user', claims)
        joined = ', '.join(sorted(claims.keys()))
        assert str(excinfo.value) == ('Claims "{0}" are reserved, and must not be '
                                      'set.'.format(joined))

    def test_large_claims_payload(self):
        claims = {'key' : 'A'*1000}
        with pytest.raises(ValueError) as excinfo:
            auth.set_custom_user_claims('user', claims)
        assert str(excinfo.value) == 'Custom claims payload must not exceed 1000 characters.'

    def test_set_custom_user_claims(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        claims = {'admin':True, 'package':'gold'}
        auth.set_custom_user_claims('testuser', claims, app=user_mgt_app)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser', 'customAttributes' : json.dumps(claims)}

    def test_set_custom_user_claims_str(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        claims = json.dumps({'admin':True, 'package':'gold'})
        auth.set_custom_user_claims('testuser', claims, app=user_mgt_app)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser', 'customAttributes' : claims}

    def test_set_custom_user_claims_none(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        auth.set_custom_user_claims('testuser', None, app=user_mgt_app)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser', 'customAttributes' : json.dumps({})}

    def test_set_custom_user_claims_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(auth.AuthError) as excinfo:
            auth.set_custom_user_claims('user', {}, app=user_mgt_app)
        assert excinfo.value.code == _user_mgt.USER_UPDATE_ERROR
        assert '{"error":"test"}' in str(excinfo.value)


class TestDeleteUser(object):

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_delete_user(self, arg):
        with pytest.raises(ValueError):
            auth.get_user(arg)

    def test_delete_user(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{"kind":"deleteresponse"}')
        # should not raise
        auth.delete_user('testuser', user_mgt_app)

    def test_delete_user_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(auth.AuthError) as excinfo:
            auth.delete_user('user', app=user_mgt_app)
        assert excinfo.value.code == _user_mgt.USER_DELETE_ERROR
        assert '{"error":"test"}' in str(excinfo.value)


class TestListUsers(object):

    @pytest.mark.parametrize('arg', [None, 'foo', list(), dict(), 0, -1, 1001, False])
    def test_invalid_max_results(self, arg):
        with pytest.raises(ValueError):
            auth.list_users(max_results=arg)

    def test_list_single_page(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, MOCK_LIST_USERS_RESPONSE)
        page = auth.list_users(app=user_mgt_app)
        self._check_page(page)
        assert page.next_page_token == ''
        assert page.has_next_page is False
        assert page.get_next_page() is None
        users = [user for user in page.iterate_all()]
        assert len(users) == 2
        self._check_rpc_calls(recorder)

    def test_list_multiple_pages(self, user_mgt_app):
        # Page 1
        response = {
            'users': [{'localId': 'user1'}, {'localId': 'user2'}, {'localId': 'user3'}],
            'nextPageToken': 'token'
        }
        _, recorder = _instrument_user_manager(user_mgt_app, 200, json.dumps(response))
        page = auth.list_users(app=user_mgt_app)
        assert len(page.users) == 3
        assert page.next_page_token == 'token'
        assert page.has_next_page is True
        self._check_rpc_calls(recorder)

        # Page 2 (also the last page)
        response = {'users': [{'localId': 'user4'}]}
        _, recorder = _instrument_user_manager(user_mgt_app, 200, json.dumps(response))
        page = page.get_next_page()
        assert len(page.users) == 1
        assert page.next_page_token == ''
        assert page.has_next_page is False
        assert page.get_next_page() is None
        self._check_rpc_calls(recorder, {'maxResults': 1000, 'nextPageToken': 'token'})

    def test_list_users_paged_iteration(self, user_mgt_app):
        # Page 1
        response = {
            'users': [{'localId': 'user1'}, {'localId': 'user2'}, {'localId': 'user3'}],
            'nextPageToken': 'token'
        }
        _, recorder = _instrument_user_manager(user_mgt_app, 200, json.dumps(response))
        page = auth.list_users(app=user_mgt_app)
        assert page.next_page_token == 'token'
        assert page.has_next_page is True
        iterator = page.iterate_all()
        for index in range(3):
            user = next(iterator)
            assert user.uid == 'user{0}'.format(index+1)
        assert len(recorder) == 1
        self._check_rpc_calls(recorder)

        # Page 2 (also the last page)
        response = {'users': [{'localId': 'user4'}]}
        _, recorder = _instrument_user_manager(user_mgt_app, 200, json.dumps(response))
        user = next(iterator)
        assert user.uid == 'user4'
        with pytest.raises(StopIteration):
            next(iterator)
        self._check_rpc_calls(recorder, {'maxResults': 1000, 'nextPageToken': 'token'})

    def test_list_users_iterator_state(self, user_mgt_app):
        response = {
            'users': [{'localId': 'user1'}, {'localId': 'user2'}, {'localId': 'user3'}]
        }
        _, recorder = _instrument_user_manager(user_mgt_app, 200, json.dumps(response))
        page = auth.list_users(app=user_mgt_app)

        # Iterate through 2 results and break.
        index = 0
        iterator = page.iterate_all()
        for user in iterator:
            index += 1
            assert user.uid == 'user{0}'.format(index)
            if index == 2:
                break

        # Iterator should resume from where left off.
        user = next(iterator)
        assert user.uid == 'user3'
        with pytest.raises(StopIteration):
            next(iterator)
        self._check_rpc_calls(recorder)

    def test_list_users_stop_iteration(self, user_mgt_app):
        response = {
            'users': [{'localId': 'user1'}, {'localId': 'user2'}, {'localId': 'user3'}]
        }
        _, recorder = _instrument_user_manager(user_mgt_app, 200, json.dumps(response))
        page = auth.list_users(app=user_mgt_app)
        assert len(page.users) == 3

        iterator = page.iterate_all()
        users = [user for user in iterator]
        assert len(page.users) == 3
        with pytest.raises(StopIteration):
            next(iterator)
        assert len(users) == 3
        self._check_rpc_calls(recorder)

    def test_list_users_no_users_response(self, user_mgt_app):
        response = {'users': []}
        _instrument_user_manager(user_mgt_app, 200, json.dumps(response))
        page = auth.list_users(app=user_mgt_app)
        assert len(page.users) is 0
        users = [user for user in page.iterate_all()]
        assert len(users) is 0

    def test_list_users_with_max_results(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, MOCK_LIST_USERS_RESPONSE)
        page = auth.list_users(max_results=500, app=user_mgt_app)
        self._check_page(page)
        self._check_rpc_calls(recorder, {'maxResults' : 500})

    def test_list_users_with_all_args(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, MOCK_LIST_USERS_RESPONSE)
        page = auth.list_users(page_token='foo', max_results=500, app=user_mgt_app)
        self._check_page(page)
        self._check_rpc_calls(recorder, {'nextPageToken' : 'foo', 'maxResults' : 500})

    def test_list_users_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(auth.AuthError) as excinfo:
            auth.list_users(app=user_mgt_app)
        assert excinfo.value.code == _user_mgt.USER_DOWNLOAD_ERROR
        assert '{"error":"test"}' in str(excinfo.value)

    def _check_page(self, page):
        assert isinstance(page, auth.ListUsersPage)
        index = 0
        assert len(page.users) == 2
        for user in page.users:
            assert isinstance(user, auth.ExportedUserRecord)
            _check_user_record(user, 'testuser{0}'.format(index))
            assert user.password_hash == 'passwordHash'
            assert user.password_salt == 'passwordSalt'
            index += 1

    def _check_rpc_calls(self, recorder, expected=None):
        if expected is None:
            expected = {'maxResults' : 1000}
        assert len(recorder) == 1
        request = json.loads(recorder[0].body.decode())
        assert request == expected
