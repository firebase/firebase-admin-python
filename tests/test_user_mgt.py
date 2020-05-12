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

"""Test cases for the firebase_admin._user_mgt module."""

import base64
import json
import time
from urllib import parse

import pytest

import firebase_admin
from firebase_admin import auth
from firebase_admin import exceptions
from firebase_admin import _auth_utils
from firebase_admin import _http_client
from firebase_admin import _user_import
from firebase_admin import _user_mgt
from tests import testutils


INVALID_STRINGS = [None, '', 0, 1, True, False, list(), tuple(), dict()]
INVALID_DICTS = [None, 'foo', 0, 1, True, False, list(), tuple()]
INVALID_INTS = [None, 'foo', '1', -1, 1.1, True, False, list(), tuple(), dict()]
INVALID_TIMESTAMPS = ['foo', '1', 0, -1, 1.1, True, False, list(), tuple(), dict()]

MOCK_GET_USER_RESPONSE = testutils.resource('get_user.json')
MOCK_LIST_USERS_RESPONSE = testutils.resource('list_users.json')

MOCK_ACTION_CODE_DATA = {
    'url': 'http://localhost',
    'handle_code_in_app': True,
    'dynamic_link_domain': 'http://testly',
    'ios_bundle_id': 'test.bundle',
    'android_package_name': 'test.bundle',
    'android_minimum_version': '7',
    'android_install_app': True,
}
MOCK_ACTION_CODE_SETTINGS = auth.ActionCodeSettings(**MOCK_ACTION_CODE_DATA)

USER_MGT_URL_PREFIX = 'https://identitytoolkit.googleapis.com/v1/projects/mock-project-id'


@pytest.fixture(scope='module')
def user_mgt_app():
    app = firebase_admin.initialize_app(testutils.MockCredential(), name='userMgt',
                                        options={'projectId': 'mock-project-id'})
    yield app
    firebase_admin.delete_app(app)

def _instrument_user_manager(app, status, payload):
    client = auth._get_client(app)
    user_manager = client._user_manager
    recorder = []
    user_manager.http_client.session.mount(
        _user_mgt.UserManager.ID_TOOLKIT_URL,
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
    assert user.tenant_id is None

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


def _check_request(recorder, want_url, want_body=None):
    assert len(recorder) == 1
    req = recorder[0]
    assert req.method == 'POST'
    assert req.url == '{0}{1}'.format(USER_MGT_URL_PREFIX, want_url)
    if want_body:
        body = json.loads(req.body.decode())
        assert body == want_body


class TestAuthServiceInitialization:

    def test_default_timeout(self, user_mgt_app):
        client = auth._get_client(user_mgt_app)
        user_manager = client._user_manager
        assert user_manager.http_client.timeout == _http_client.DEFAULT_TIMEOUT_SECONDS

    def test_fail_on_no_project_id(self):
        app = firebase_admin.initialize_app(testutils.MockCredential(), name='userMgt2')
        with pytest.raises(ValueError):
            auth._get_client(app)
        firebase_admin.delete_app(app)


class TestUserRecord:

    # Input dict must be non-empty, and must not contain unsupported keys.
    @pytest.mark.parametrize('data', INVALID_DICTS + [{}, {'foo':'bar'}])
    def test_invalid_record(self, data):
        with pytest.raises(ValueError):
            auth.UserRecord(data)

    def test_metadata(self):
        metadata = auth.UserMetadata(10, 20)
        assert metadata.creation_timestamp == 10
        assert metadata.last_sign_in_timestamp == 20
        metadata = auth.UserMetadata()
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

    def test_redacted_passwords_cleared(self):
        user = auth.ExportedUserRecord({
            'localId': 'user',
            'passwordHash': base64.b64encode(b'REDACTED'),
        })
        assert user.password_hash is None

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
            _user_mgt.ProviderUserInfo(data)

    def test_tokens_valid_after_time(self):
        user = auth.UserRecord({'localId' : 'user', 'validSince' : 100})
        assert user.tokens_valid_after_timestamp == 100000

    def test_no_tokens_valid_after_time(self):
        user = auth.UserRecord({'localId' : 'user'})
        assert user.tokens_valid_after_timestamp == 0

    def test_tenant_id(self):
        user = auth.UserRecord({'localId' : 'user', 'tenantId': 'test-tenant'})
        assert user.tenant_id == 'test-tenant'


class TestGetUser:

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_get_user(self, arg, user_mgt_app):
        with pytest.raises(ValueError):
            auth.get_user(arg, app=user_mgt_app)

    def test_get_user(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_RESPONSE)
        _check_user_record(auth.get_user('testuser', user_mgt_app))
        _check_request(recorder, '/accounts:lookup', {'localId': ['testuser']})

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-an-email'])
    def test_invalid_get_user_by_email(self, arg, user_mgt_app):
        with pytest.raises(ValueError):
            auth.get_user_by_email(arg, app=user_mgt_app)

    def test_get_user_by_email(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_RESPONSE)
        _check_user_record(auth.get_user_by_email('testuser@example.com', user_mgt_app))
        _check_request(recorder, '/accounts:lookup', {'email': ['testuser@example.com']})

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-a-phone'])
    def test_invalid_get_user_by_phone(self, arg, user_mgt_app):
        with pytest.raises(ValueError):
            auth.get_user_by_phone_number(arg, app=user_mgt_app)

    def test_get_user_by_phone(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, MOCK_GET_USER_RESPONSE)
        _check_user_record(auth.get_user_by_phone_number('+1234567890', user_mgt_app))
        _check_request(recorder, '/accounts:lookup', {'phoneNumber': ['+1234567890']})

    def test_get_user_non_existing(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{"users":[]}')
        with pytest.raises(auth.UserNotFoundError) as excinfo:
            auth.get_user('nonexistentuser', user_mgt_app)
        error_msg = 'No user record found for the provided user ID: nonexistentuser.'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is None

    def test_get_user_by_email_non_existing(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{"users":[]}')
        with pytest.raises(auth.UserNotFoundError) as excinfo:
            auth.get_user_by_email('nonexistent@user', user_mgt_app)
        error_msg = 'No user record found for the provided email: nonexistent@user.'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is None

    def test_get_user_by_phone_non_existing(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{"users":[]}')
        with pytest.raises(auth.UserNotFoundError) as excinfo:
            auth.get_user_by_phone_number('+1234567890', user_mgt_app)
        error_msg = 'No user record found for the provided phone number: +1234567890.'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is None

    def test_get_user_http_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":{"message": "USER_NOT_FOUND"}}')
        with pytest.raises(auth.UserNotFoundError) as excinfo:
            auth.get_user('testuser', user_mgt_app)
        error_msg = 'No user record found for the given identifier (USER_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def test_get_user_http_error_unexpected_code(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":{"message": "UNEXPECTED_CODE"}}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.get_user('testuser', user_mgt_app)
        assert str(excinfo.value) == 'Error while calling Auth service (UNEXPECTED_CODE).'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def test_get_user_http_error_malformed_response(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error": "UNEXPECTED_CODE"}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.get_user('testuser', user_mgt_app)
        assert str(excinfo.value) == 'Unexpected error response: {"error": "UNEXPECTED_CODE"}'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def test_get_user_by_email_http_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":{"message": "USER_NOT_FOUND"}}')
        with pytest.raises(auth.UserNotFoundError) as excinfo:
            auth.get_user_by_email('non.existent.user@example.com', user_mgt_app)
        error_msg = 'No user record found for the given identifier (USER_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def test_get_user_by_phone_http_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":{"message": "USER_NOT_FOUND"}}')
        with pytest.raises(auth.UserNotFoundError) as excinfo:
            auth.get_user_by_phone_number('+1234567890', user_mgt_app)
        error_msg = 'No user record found for the given identifier (USER_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None


class TestGetUsers:

    @staticmethod
    def _map_user_record_to_uid_email_phones(user_record):
        return {
            'uid': user_record.uid,
            'email': user_record.email,
            'phone_number': user_record.phone_number
        }

    def test_more_than_100_identifiers(self, user_mgt_app):
        identifiers = [auth.UidIdentifier('id' + str(i)) for i in range(101)]
        with pytest.raises(ValueError):
            auth.get_users(identifiers, app=user_mgt_app)

    def test_no_identifiers(self, user_mgt_app):
        get_users_results = auth.get_users([], app=user_mgt_app)
        assert get_users_results.users == []
        assert get_users_results.not_found == []

    def test_identifiers_that_do_not_exist(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{}')
        not_found_ids = [auth.UidIdentifier('id that doesnt exist')]
        get_users_results = auth.get_users(not_found_ids, app=user_mgt_app)
        assert get_users_results.users == []
        assert get_users_results.not_found == not_found_ids

    def test_invalid_uid(self):
        with pytest.raises(ValueError):
            auth.UidIdentifier('too long ' + '.'*128)

    def test_invalid_email(self):
        with pytest.raises(ValueError):
            auth.EmailIdentifier('invalid email addr')

    def test_invalid_phone_number(self):
        with pytest.raises(ValueError):
            auth.PhoneIdentifier('invalid phone number')

    def test_invalid_provider(self):
        with pytest.raises(ValueError):
            auth.ProviderIdentifier(provider_id='', provider_uid='')

    def test_success(self, user_mgt_app):
        mock_users = [{
            "localId": "uid1",
            "email": "user1@example.com",
            "phoneNumber": "+15555550001"
        }, {
            "localId": "uid2",
            "email": "user2@example.com",
            "phoneNumber": "+15555550002"
        }, {
            "localId": "uid3",
            "email": "user3@example.com",
            "phoneNumber": "+15555550003"
        }, {
            "localId": "uid4",
            "email": "user4@example.com",
            "phoneNumber": "+15555550004",
            "providerUserInfo": [{
                "providerId": "google.com",
                "rawId": "google_uid4"
            }]
        }]
        _instrument_user_manager(user_mgt_app, 200, '{ "users": ' + json.dumps(mock_users) + '}')

        get_users_results = auth.get_users([
            auth.UidIdentifier('uid1'),
            auth.EmailIdentifier('user2@example.com'),
            auth.PhoneIdentifier('+15555550003'),
            auth.ProviderIdentifier(provider_id='google.com', provider_uid='google_uid4'),
            auth.UidIdentifier('this-user-doesnt-exist'),
            ], app=user_mgt_app)

        actual = sorted(
            [self._map_user_record_to_uid_email_phones(user) for user in get_users_results.users],
            key=lambda user: user['uid'])
        expected = sorted([
            self._map_user_record_to_uid_email_phones(auth.UserRecord(user))
            for user in mock_users
        ], key=lambda user: user['uid'])
        assert actual == expected
        assert [u.uid for u in get_users_results.not_found] == ['this-user-doesnt-exist']


class TestCreateUser:

    already_exists_errors = {
        'DUPLICATE_EMAIL': auth.EmailAlreadyExistsError,
        'DUPLICATE_LOCAL_ID': auth.UidAlreadyExistsError,
        'EMAIL_EXISTS': auth.EmailAlreadyExistsError,
        'PHONE_NUMBER_EXISTS': auth.PhoneNumberAlreadyExistsError,
    }

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['a'*129])
    def test_invalid_uid(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(uid=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['not-an-email'])
    def test_invalid_email(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(email=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['not-a-phone', '+'])
    def test_invalid_phone(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(phone_number=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:])
    def test_invalid_display_name(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(display_name=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['not-a-url'])
    def test_invalid_photo_url(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(photo_url=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['short'])
    def test_invalid_password(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(password=arg, app=user_mgt_app)

    def test_invalid_property(self, user_mgt_app):
        with pytest.raises(TypeError):
            auth.create_user(unsupported='value', app=user_mgt_app)

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
        assert user_mgt.create_user(email='test@example.com', email_verified=True) == 'testuser'
        request = json.loads(recorder[0].body.decode())
        assert request == {'email' : 'test@example.com', 'emailVerified' : True}

    def test_create_user_with_id(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        assert user_mgt.create_user(uid='testuser') == 'testuser'
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser'}

    def test_create_user_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error": {"message": "UNEXPECTED_CODE"}}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.create_user(app=user_mgt_app)
        assert str(excinfo.value) == 'Error while calling Auth service (UNEXPECTED_CODE).'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    @pytest.mark.parametrize('error_code', already_exists_errors.keys())
    def test_user_already_exists(self, user_mgt_app, error_code):
        resp = {'error': {'message': error_code}}
        _instrument_user_manager(user_mgt_app, 500, json.dumps(resp))
        exc_type = self.already_exists_errors[error_code]
        with pytest.raises(exc_type) as excinfo:
            auth.create_user(app=user_mgt_app)
        assert isinstance(excinfo.value, exceptions.AlreadyExistsError)
        assert str(excinfo.value) == '{0} ({1}).'.format(exc_type.default_message, error_code)
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def test_create_user_unexpected_response(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{"error": "test"}')
        with pytest.raises(auth.UnexpectedResponseError) as excinfo:
            auth.create_user(app=user_mgt_app)
        assert str(excinfo.value) == 'Failed to create new user.'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is None
        assert isinstance(excinfo.value, exceptions.UnknownError)


class TestUpdateUser:

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_uid(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user(arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['not-an-email'])
    def test_invalid_email(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', email=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['not-a-phone', '+'])
    def test_invalid_phone(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', phone_number=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:])
    def test_invalid_display_name(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', display_name=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['not-a-url'])
    def test_invalid_photo_url(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', photo_url=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS[1:] + ['short'])
    def test_invalid_password(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', password=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_DICTS[1:] + ['"json"'])
    def test_invalid_custom_claims(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', custom_claims=arg, app=user_mgt_app)

    def test_invalid_property(self, user_mgt_app):
        with pytest.raises(TypeError):
            auth.update_user('user', unsupported='arg', app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_TIMESTAMPS)
    def test_invalid_valid_since(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', valid_since=arg, app=user_mgt_app)

    def test_update_user(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        user_mgt.update_user('testuser')
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser'}

    @pytest.mark.parametrize('arg', [True, False, 1, 0, 'foo'])
    def test_disable_user(self, arg, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        user_mgt.update_user('testuser', disabled=arg)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser', 'disableUser' : bool(arg)}

    @pytest.mark.parametrize('arg', [True, False, 1, 0, 'foo'])
    def test_set_email_verified(self, arg, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        user_mgt.update_user('testuser', email_verified=arg)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser', 'emailVerified' : bool(arg)}

    def test_update_user_custom_claims(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        claims = {'admin':True, 'package':'gold'}
        user_mgt.update_user('testuser', custom_claims=claims)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser', 'customAttributes' : json.dumps(claims)}

    def test_delete_user_custom_claims(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        user_mgt.update_user('testuser', custom_claims=auth.DELETE_ATTRIBUTE)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser', 'customAttributes' : json.dumps({})}

    def test_update_user_delete_fields(self, user_mgt_app):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        user_mgt.update_user(
            'testuser',
            display_name=auth.DELETE_ATTRIBUTE,
            photo_url=auth.DELETE_ATTRIBUTE,
            phone_number=auth.DELETE_ATTRIBUTE)
        request = json.loads(recorder[0].body.decode())
        assert request == {
            'localId' : 'testuser',
            'deleteAttribute' : ['DISPLAY_NAME', 'PHOTO_URL'],
            'deleteProvider' : ['phone'],
        }

    def test_update_user_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error": {"message": "UNEXPECTED_CODE"}}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.update_user('user', app=user_mgt_app)
        assert str(excinfo.value) == 'Error while calling Auth service (UNEXPECTED_CODE).'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def test_update_user_unexpected_response(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{"error": "test"}')
        with pytest.raises(auth.UnexpectedResponseError) as excinfo:
            auth.update_user('user', app=user_mgt_app)
        assert str(excinfo.value) == 'Failed to update user: user.'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is None
        assert isinstance(excinfo.value, exceptions.UnknownError)

    @pytest.mark.parametrize('arg', [1, 1.0])
    def test_update_user_valid_since(self, user_mgt_app, arg):
        user_mgt, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        user_mgt.update_user('testuser', valid_since=arg)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId': 'testuser', 'validSince': int(arg)}


class TestSetCustomUserClaims:

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_uid(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.set_custom_user_claims(arg, {'foo': 'bar'}, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_DICTS[1:] + ['"json"'])
    def test_invalid_custom_claims(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.set_custom_user_claims('user', arg, app=user_mgt_app)

    @pytest.mark.parametrize('key', _auth_utils.RESERVED_CLAIMS)
    def test_single_reserved_claim(self, user_mgt_app, key):
        claims = {key : 'value'}
        with pytest.raises(ValueError) as excinfo:
            auth.set_custom_user_claims('user', claims, app=user_mgt_app)
        assert str(excinfo.value) == 'Claim "{0}" is reserved, and must not be set.'.format(key)

    def test_multiple_reserved_claims(self, user_mgt_app):
        claims = {key : 'value' for key in _auth_utils.RESERVED_CLAIMS}
        with pytest.raises(ValueError) as excinfo:
            auth.set_custom_user_claims('user', claims, app=user_mgt_app)
        joined = ', '.join(sorted(claims.keys()))
        assert str(excinfo.value) == ('Claims "{0}" are reserved, and must not be '
                                      'set.'.format(joined))

    def test_large_claims_payload(self, user_mgt_app):
        claims = {'key' : 'A'*1000}
        with pytest.raises(ValueError) as excinfo:
            auth.set_custom_user_claims('user', claims, app=user_mgt_app)
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

    @pytest.mark.parametrize('claims', [None, auth.DELETE_ATTRIBUTE])
    def test_set_custom_user_claims_remove(self, user_mgt_app, claims):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        auth.set_custom_user_claims('testuser', claims, app=user_mgt_app)
        request = json.loads(recorder[0].body.decode())
        assert request == {'localId' : 'testuser', 'customAttributes' : json.dumps({})}

    def test_set_custom_user_claims_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error": {"message": "UNEXPECTED_CODE"}}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.set_custom_user_claims('user', {}, app=user_mgt_app)
        assert str(excinfo.value) == 'Error while calling Auth service (UNEXPECTED_CODE).'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None


class TestDeleteUser:

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_delete_user(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.delete_user(arg, app=user_mgt_app)

    def test_delete_user(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{"kind":"deleteresponse"}')
        # should not raise
        auth.delete_user('testuser', user_mgt_app)

    def test_delete_user_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error": {"message": "UNEXPECTED_CODE"}}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.delete_user('user', app=user_mgt_app)
        assert str(excinfo.value) == 'Error while calling Auth service (UNEXPECTED_CODE).'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def test_delete_user_unexpected_response(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{"error": "test"}')
        with pytest.raises(auth.UnexpectedResponseError) as excinfo:
            auth.delete_user('user', app=user_mgt_app)
        assert str(excinfo.value) == 'Failed to delete user: user.'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is None
        assert isinstance(excinfo.value, exceptions.UnknownError)


class TestDeleteUsers:

    def test_empty_list(self, user_mgt_app):
        delete_users_result = auth.delete_users([], app=user_mgt_app)
        assert delete_users_result.success_count == 0
        assert delete_users_result.failure_count == 0
        assert len(delete_users_result.errors) == 0

    def test_too_many_identifiers_should_fail(self, user_mgt_app):
        ids = ['id' + str(i) for i in range(1001)]
        with pytest.raises(ValueError):
            auth.delete_users(ids, app=user_mgt_app)

    def test_invalid_id_should_fail(self, user_mgt_app):
        ids = ['too long ' + '.'*128]
        with pytest.raises(ValueError):
            auth.delete_users(ids, app=user_mgt_app)

    def test_should_index_errors_correctly_in_results(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, """{
            "errors": [{
                "index": 0,
                "localId": "uid1",
                "message": "NOT_DISABLED : Disable the account before batch deletion."
            }, {
                "index": 2,
                "localId": "uid3",
                "message": "something awful"
            }]
        }""")

        delete_users_result = auth.delete_users(['uid1', 'uid2', 'uid3', 'uid4'], app=user_mgt_app)
        assert delete_users_result.success_count == 2
        assert delete_users_result.failure_count == 2
        assert len(delete_users_result.errors) == 2
        assert delete_users_result.errors[0].index == 0
        assert delete_users_result.errors[0].reason.startswith('NOT_DISABLED')
        assert delete_users_result.errors[1].index == 2
        assert delete_users_result.errors[1].reason == 'something awful'

    def test_success(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '{}')
        delete_users_result = auth.delete_users(['uid1', 'uid2', 'uid3'], app=user_mgt_app)
        assert delete_users_result.success_count == 3
        assert delete_users_result.failure_count == 0
        assert len(delete_users_result.errors) == 0


class TestListUsers:

    @pytest.mark.parametrize('arg', [None, 'foo', list(), dict(), 0, -1, 1001, False])
    def test_invalid_max_results(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.list_users(max_results=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', ['', list(), dict(), 0, -1, 1001, False])
    def test_invalid_page_token(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.list_users(page_token=arg, app=user_mgt_app)

    def test_list_single_page(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, MOCK_LIST_USERS_RESPONSE)
        page = auth.list_users(app=user_mgt_app)
        self._check_page(page)
        assert page.next_page_token == ''
        assert page.has_next_page is False
        assert page.get_next_page() is None
        users = list(user for user in page.iterate_all())
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
        self._check_rpc_calls(recorder, {'maxResults': '1000', 'nextPageToken': 'token'})

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
        self._check_rpc_calls(recorder, {'maxResults': '1000', 'nextPageToken': 'token'})

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
        users = list(user for user in iterator)
        assert len(page.users) == 3
        with pytest.raises(StopIteration):
            next(iterator)
        assert len(users) == 3
        self._check_rpc_calls(recorder)

    def test_list_users_no_users_response(self, user_mgt_app):
        response = {'users': []}
        _instrument_user_manager(user_mgt_app, 200, json.dumps(response))
        page = auth.list_users(app=user_mgt_app)
        assert len(page.users) == 0
        users = list(user for user in page.iterate_all())
        assert len(users) == 0

    def test_list_users_with_max_results(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, MOCK_LIST_USERS_RESPONSE)
        page = auth.list_users(max_results=500, app=user_mgt_app)
        self._check_page(page)
        self._check_rpc_calls(recorder, {'maxResults' : '500'})

    def test_list_users_with_all_args(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, MOCK_LIST_USERS_RESPONSE)
        page = auth.list_users(page_token='foo', max_results=500, app=user_mgt_app)
        self._check_page(page)
        self._check_rpc_calls(recorder, {'nextPageToken' : 'foo', 'maxResults' : '500'})

    def test_list_users_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.list_users(app=user_mgt_app)
        assert str(excinfo.value) == 'Unexpected error response: {"error":"test"}'

    def test_permission_error(self, user_mgt_app):
        _instrument_user_manager(
            user_mgt_app, 400, '{"error": {"message": "INSUFFICIENT_PERMISSION"}}')
        with pytest.raises(auth.InsufficientPermissionError) as excinfo:
            auth.list_users(app=user_mgt_app)
        assert isinstance(excinfo.value, exceptions.PermissionDeniedError)
        msg = ('The credential used to initialize the SDK has insufficient '
               'permissions to perform the requested operation. See '
               'https://firebase.google.com/docs/admin/setup for details '
               'on how to initialize the Admin SDK with appropriate permissions '
               '(INSUFFICIENT_PERMISSION).')
        assert str(excinfo.value) == msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

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
            expected = {'maxResults' : '1000'}
        assert len(recorder) == 1
        request = dict(parse.parse_qsl(parse.urlsplit(recorder[0].url).query))
        assert request == expected


class TestUserProvider:

    _INVALID_PROVIDERS = (
        [{'display_name': arg} for arg in INVALID_STRINGS[1:]] +
        [{'email': arg} for arg in INVALID_STRINGS[1:] + ['not-an-email']] +
        [{'photo_url': arg} for arg in INVALID_STRINGS[1:] + ['not-a-url']]
    )

    def test_uid_and_provider_id(self):
        provider = auth.UserProvider(uid='test', provider_id='google.com')
        expected = {'rawId': 'test', 'providerId': 'google.com'}
        assert provider.to_dict() == expected

    def test_all_params(self):
        provider = auth.UserProvider(
            uid='test', provider_id='google.com', email='test@example.com',
            display_name='Test Name', photo_url='https://test.com/user.png')
        expected = {
            'rawId': 'test',
            'providerId': 'google.com',
            'email': 'test@example.com',
            'displayName': 'Test Name',
            'photoUrl': 'https://test.com/user.png'
        }
        assert provider.to_dict() == expected

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_uid(self, arg):
        with pytest.raises(ValueError):
            auth.UserProvider(uid=arg, provider_id='google.com')

    @pytest.mark.parametrize('arg', INVALID_STRINGS)
    def test_invalid_provider_id(self, arg):
        with pytest.raises(ValueError):
            auth.UserProvider(uid='test', provider_id=arg)

    @pytest.mark.parametrize('arg', _INVALID_PROVIDERS)
    def test_invalid_arg(self, arg):
        with pytest.raises(ValueError):
            auth.UserProvider(uid='test', provider_id='google.com', **arg)


class TestUserMetadata:

    _INVALID_ARGS = (
        [{'creation_timestamp': arg} for arg in INVALID_TIMESTAMPS] +
        [{'last_sign_in_timestamp': arg} for arg in INVALID_TIMESTAMPS]
    )

    @pytest.mark.parametrize('arg', _INVALID_ARGS)
    def test_invalid_args(self, arg):
        with pytest.raises(ValueError):
            auth.UserMetadata(**arg)


class TestImportUserRecord:

    _INVALID_USERS = (
        [{'display_name': arg} for arg in INVALID_STRINGS[1:]] +
        [{'email': arg} for arg in INVALID_STRINGS[1:] + ['not-an-email']] +
        [{'photo_url': arg} for arg in INVALID_STRINGS[1:] + ['not-a-url']] +
        [{'phone_number': arg} for arg in INVALID_STRINGS[1:] + ['not-a-phone']] +
        [{'password_hash': arg} for arg in INVALID_STRINGS[1:] + [u'test']] +
        [{'password_salt': arg} for arg in INVALID_STRINGS[1:] + [u'test']] +
        [{'custom_claims': arg} for arg in INVALID_DICTS[1:] + ['"json"', {'key': 'a'*1000}]] +
        [{'provider_data': arg} for arg in ['foo', 1, True]]
    )

    def test_uid(self):
        user = auth.ImportUserRecord(uid='test')
        assert user.uid == 'test'
        assert user.custom_claims is None
        assert user.user_metadata is None
        assert user.to_dict() == {'localId': 'test'}

    def test_all_params(self):
        providers = [auth.UserProvider(uid='test', provider_id='google.com')]
        metadata = auth.UserMetadata(100, 150)
        user = auth.ImportUserRecord(
            uid='test', email='test@example.com', photo_url='https://test.com/user.png',
            phone_number='+1234567890', display_name='name', user_metadata=metadata,
            password_hash=b'password', password_salt=b'NaCl', custom_claims={'admin': True},
            email_verified=True, disabled=False, provider_data=providers)
        expected = {
            'localId': 'test',
            'email': 'test@example.com',
            'photoUrl': 'https://test.com/user.png',
            'phoneNumber': '+1234567890',
            'displayName': 'name',
            'createdAt': 100,
            'lastLoginAt': 150,
            'passwordHash': _user_import.b64_encode(b'password'),
            'salt': _user_import.b64_encode(b'NaCl'),
            'customAttributes': json.dumps({'admin': True}),
            'emailVerified': True,
            'disabled': False,
            'providerUserInfo': [{'rawId': 'test', 'providerId': 'google.com'}],
        }
        assert user.to_dict() == expected

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_uid(self, arg):
        with pytest.raises(ValueError):
            auth.ImportUserRecord(uid=arg)

    @pytest.mark.parametrize('args', _INVALID_USERS)
    def test_invalid_args(self, args):
        with pytest.raises(ValueError):
            auth.ImportUserRecord(uid='test', **args)

    @pytest.mark.parametrize('claims', [{}, {'admin': True}, '{"admin": true}'])
    def test_custom_claims(self, claims):
        user = auth.ImportUserRecord(uid='test', custom_claims=claims)
        assert user.custom_claims == claims
        json_claims = json.dumps(claims) if isinstance(claims, dict) else claims
        expected = {'localId': 'test', 'customAttributes': json_claims}
        assert user.to_dict() == expected

    @pytest.mark.parametrize('email_verified', [True, False])
    def test_email_verified(self, email_verified):
        user = auth.ImportUserRecord(uid='test', email_verified=email_verified)
        assert user.email_verified == email_verified
        assert user.to_dict() == {'localId': 'test', 'emailVerified': email_verified}

    @pytest.mark.parametrize('disabled', [True, False])
    def test_disabled(self, disabled):
        user = auth.ImportUserRecord(uid='test', disabled=disabled)
        assert user.disabled == disabled
        assert user.to_dict() == {'localId': 'test', 'disabled': disabled}


class TestUserImportHash:

    @pytest.mark.parametrize('func,name', [
        (auth.UserImportHash.hmac_sha512, 'HMAC_SHA512'),
        (auth.UserImportHash.hmac_sha256, 'HMAC_SHA256'),
        (auth.UserImportHash.hmac_sha1, 'HMAC_SHA1'),
        (auth.UserImportHash.hmac_md5, 'HMAC_MD5'),
    ])
    def test_hmac(self, func, name):
        hmac = func(key=b'key')
        expected = {
            'hashAlgorithm': name,
            'signerKey': _user_import.b64_encode(b'key'),
        }
        assert hmac.to_dict() == expected

    @pytest.mark.parametrize('func', [
        auth.UserImportHash.hmac_sha512, auth.UserImportHash.hmac_sha256,
        auth.UserImportHash.hmac_sha1, auth.UserImportHash.hmac_md5,
    ])
    @pytest.mark.parametrize('key', INVALID_STRINGS)
    def test_invalid_hmac(self, func, key):
        with pytest.raises(ValueError):
            func(key=key)

    @pytest.mark.parametrize('func,name,rounds', [
        (auth.UserImportHash.md5, 'MD5', [0, 8192]),
        (auth.UserImportHash.sha1, 'SHA1', [1, 8192]),
        (auth.UserImportHash.sha256, 'SHA256', [1, 8192]),
        (auth.UserImportHash.sha512, 'SHA512', [1, 8192]),
        (auth.UserImportHash.pbkdf_sha1, 'PBKDF_SHA1', [0, 120000]),
        (auth.UserImportHash.pbkdf2_sha256, 'PBKDF2_SHA256', [0, 120000]),
    ])
    def test_basic(self, func, name, rounds):
        for rnds in rounds:
            basic = func(rounds=rnds)
            expected = {
                'hashAlgorithm': name,
                'rounds': rnds,
            }
            assert basic.to_dict() == expected

    @pytest.mark.parametrize('func,rounds', [
        (auth.UserImportHash.md5, INVALID_INTS + [-1, 8193]),
        (auth.UserImportHash.sha1, INVALID_INTS + [0, 8193]),
        (auth.UserImportHash.sha256, INVALID_INTS + [0, 8193]),
        (auth.UserImportHash.sha512, INVALID_INTS + [0, 8193]),
        (auth.UserImportHash.pbkdf_sha1, INVALID_INTS + [-1, 120001]),
        (auth.UserImportHash.pbkdf2_sha256, INVALID_INTS + [-1, 120001]),
    ])
    def test_invalid_basic(self, func, rounds):
        for rnds in rounds:
            with pytest.raises(ValueError):
                func(rounds=rnds)

    def test_scrypt(self):
        scrypt = auth.UserImportHash.scrypt(
            key=b'key', salt_separator=b'sep', rounds=8, memory_cost=14)
        expected = {
            'hashAlgorithm': 'SCRYPT',
            'signerKey': _user_import.b64_encode(b'key'),
            'rounds': 8,
            'memoryCost': 14,
            'saltSeparator': _user_import.b64_encode(b'sep'),
        }
        assert scrypt.to_dict() == expected

    @pytest.mark.parametrize('arg', (
        [{'key': arg} for arg in INVALID_STRINGS] +
        [{'rounds': arg} for arg in INVALID_INTS + [0, 9]] +
        [{'memory_cost': arg} for arg in INVALID_INTS + [0, 15]] +
        [{'salt_separator': arg} for arg in INVALID_STRINGS]
    ))
    def test_invalid_scrypt(self, arg):
        params = {'key': 'key', 'rounds': 0, 'memory_cost': 14}
        params.update(arg)
        with pytest.raises(ValueError):
            auth.UserImportHash.scrypt(**params)

    def test_bcrypt(self):
        bcrypt = auth.UserImportHash.bcrypt()
        assert bcrypt.to_dict() == {'hashAlgorithm': 'BCRYPT'}

    def test_standard_scrypt(self):
        scrypt = auth.UserImportHash.standard_scrypt(
            memory_cost=14, parallelization=2, block_size=10, derived_key_length=128)
        expected = {
            'hashAlgorithm': 'STANDARD_SCRYPT',
            'memoryCost': 14,
            'parallelization': 2,
            'blockSize': 10,
            'dkLen': 128,
        }
        assert scrypt.to_dict() == expected

    @pytest.mark.parametrize('arg', (
        [{'memory_cost': arg} for arg in INVALID_INTS] +
        [{'parallelization': arg} for arg in INVALID_INTS] +
        [{'block_size': arg} for arg in INVALID_INTS] +
        [{'derived_key_length': arg} for arg in INVALID_INTS]
    ))
    def test_invalid_standard_scrypt(self, arg):
        params = {
            'memory_cost': 14,
            'parallelization': 2,
            'block_size': 10,
            'derived_key_length': 128,
        }
        params.update(arg)
        with pytest.raises(ValueError):
            auth.UserImportHash.standard_scrypt(**params)


class TestImportUsers:

    @pytest.mark.parametrize('arg', [None, list(), tuple(), dict(), 0, 1, 'foo'])
    def test_invalid_users(self, user_mgt_app, arg):
        with pytest.raises(Exception):
            auth.import_users(arg, app=user_mgt_app)

    def test_too_many_users(self, user_mgt_app):
        users = [auth.ImportUserRecord(uid='test{0}'.format(i)) for i in range(1001)]
        with pytest.raises(ValueError):
            auth.import_users(users, app=user_mgt_app)

    def test_import_users(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{}')
        users = [
            auth.ImportUserRecord(uid='user1'),
            auth.ImportUserRecord(uid='user2'),
        ]
        result = auth.import_users(users, app=user_mgt_app)
        assert result.success_count == 2
        assert result.failure_count == 0
        assert result.errors == []
        expected = {'users': [{'localId': 'user1'}, {'localId': 'user2'}]}
        _check_request(recorder, '/accounts:batchCreate', expected)

    def test_import_users_error(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, """{"error": [
            {"index": 0, "message": "Some error occured in user1"},
            {"index": 2, "message": "Another error occured in user3"}
        ]}""")
        users = [
            auth.ImportUserRecord(uid='user1'),
            auth.ImportUserRecord(uid='user2'),
            auth.ImportUserRecord(uid='user3'),
        ]
        result = auth.import_users(users, app=user_mgt_app)
        assert result.success_count == 1
        assert result.failure_count == 2
        assert len(result.errors) == 2
        err = result.errors[0]
        assert err.index == 0
        assert err.reason == 'Some error occured in user1'
        err = result.errors[1]
        assert err.index == 2
        assert err.reason == 'Another error occured in user3'
        expected = {'users': [{'localId': 'user1'}, {'localId': 'user2'}, {'localId': 'user3'}]}
        _check_request(recorder, '/accounts:batchCreate', expected)

    def test_import_users_missing_required_hash(self, user_mgt_app):
        users = [
            auth.ImportUserRecord(uid='user1', password_hash=b'password'),
            auth.ImportUserRecord(uid='user2'),
        ]
        with pytest.raises(ValueError):
            auth.import_users(users, app=user_mgt_app)

    def test_import_users_with_hash(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{}')
        users = [
            auth.ImportUserRecord(uid='user1', password_hash=b'password'),
            auth.ImportUserRecord(uid='user2'),
        ]
        hash_alg = auth.UserImportHash.scrypt(
            b'key', rounds=8, memory_cost=14, salt_separator=b'sep')
        result = auth.import_users(users, hash_alg=hash_alg, app=user_mgt_app)
        assert result.success_count == 2
        assert result.failure_count == 0
        assert result.errors == []
        expected = {
            'users': [
                {'localId': 'user1', 'passwordHash': _user_import.b64_encode(b'password')},
                {'localId': 'user2'}
            ],
            'hashAlgorithm': 'SCRYPT',
            'signerKey': _user_import.b64_encode(b'key'),
            'rounds': 8,
            'memoryCost': 14,
            'saltSeparator': _user_import.b64_encode(b'sep'),
        }
        _check_request(recorder, '/accounts:batchCreate', expected)

    def test_import_users_http_error(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 401, '{"error": {"message": "ERROR_CODE"}}')
        users = [
            auth.ImportUserRecord(uid='user1'),
            auth.ImportUserRecord(uid='user2'),
        ]
        with pytest.raises(exceptions.UnauthenticatedError) as excinfo:
            auth.import_users(users, app=user_mgt_app)
        assert str(excinfo.value) == 'Error while calling Auth service (ERROR_CODE).'

    def test_import_users_unexpected_response(self, user_mgt_app):
        _instrument_user_manager(user_mgt_app, 200, '"not dict"')
        users = [
            auth.ImportUserRecord(uid='user1'),
            auth.ImportUserRecord(uid='user2'),
        ]
        with pytest.raises(auth.UnexpectedResponseError):
            auth.import_users(users, app=user_mgt_app)


class TestRevokeRefreshTokkens:

    def test_revoke_refresh_tokens(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        before_time = time.time()
        auth.revoke_refresh_tokens('testuser', app=user_mgt_app)
        after_time = time.time()

        request = json.loads(recorder[0].body.decode())
        assert request['localId'] == 'testuser'
        assert int(request['validSince']) >= int(before_time)
        assert int(request['validSince']) <= int(after_time)


class TestActionCodeSetting:

    def test_valid_data(self):
        data = {
            'url': 'http://localhost',
            'handle_code_in_app': True,
            'dynamic_link_domain': 'http://testly',
            'ios_bundle_id': 'test.bundle',
            'android_package_name': 'test.bundle',
            'android_minimum_version': '7',
            'android_install_app': True,
        }
        settings = auth.ActionCodeSettings(**data)
        parameters = _user_mgt.encode_action_code_settings(settings)
        assert parameters['continueUrl'] == data['url']
        assert parameters['canHandleCodeInApp'] == data['handle_code_in_app']
        assert parameters['dynamicLinkDomain'] == data['dynamic_link_domain']
        assert parameters['iosBundleId'] == data['ios_bundle_id']
        assert parameters['androidPackageName'] == data['android_package_name']
        assert parameters['androidMinimumVersion'] == data['android_minimum_version']
        assert parameters['androidInstallApp'] == data['android_install_app']

    @pytest.mark.parametrize('data', [{'handle_code_in_app':'nonboolean'},
                                      {'android_install_app':'nonboolean'},
                                      {'dynamic_link_domain': False},
                                      {'ios_bundle_id':11},
                                      {'android_package_name':dict()},
                                      {'android_minimum_version':tuple()},
                                      {'android_minimum_version':'7'},
                                      {'android_install_app': True}])
    def test_bad_data(self, data):
        settings = auth.ActionCodeSettings('http://localhost', **data)
        with pytest.raises(ValueError):
            _user_mgt.encode_action_code_settings(settings)

    def test_bad_url(self):
        settings = auth.ActionCodeSettings('http:')
        with pytest.raises(ValueError):
            _user_mgt.encode_action_code_settings(settings)

    def test_encode_action_code_bad_data(self):
        with pytest.raises(AttributeError):
            _user_mgt.encode_action_code_settings({"foo":"bar"})


class TestGenerateEmailActionLink:

    def test_email_verification_no_settings(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"oobLink":"https://testlink"}')
        link = auth.generate_email_verification_link('test@test.com', app=user_mgt_app)
        request = json.loads(recorder[0].body.decode())

        assert link == 'https://testlink'
        assert request['requestType'] == 'VERIFY_EMAIL'
        self._validate_request(request)

    def test_password_reset_no_settings(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"oobLink":"https://testlink"}')
        link = auth.generate_password_reset_link('test@test.com', app=user_mgt_app)
        request = json.loads(recorder[0].body.decode())

        assert link == 'https://testlink'
        assert request['requestType'] == 'PASSWORD_RESET'
        self._validate_request(request)

    def test_email_signin_with_settings(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"oobLink":"https://testlink"}')
        link = auth.generate_sign_in_with_email_link('test@test.com',
                                                     action_code_settings=MOCK_ACTION_CODE_SETTINGS,
                                                     app=user_mgt_app)
        request = json.loads(recorder[0].body.decode())

        assert link == 'https://testlink'
        assert request['requestType'] == 'EMAIL_SIGNIN'
        self._validate_request(request, MOCK_ACTION_CODE_SETTINGS)

    def test_email_verification_with_settings(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"oobLink":"https://testlink"}')
        link = auth.generate_email_verification_link('test@test.com',
                                                     action_code_settings=MOCK_ACTION_CODE_SETTINGS,
                                                     app=user_mgt_app)
        request = json.loads(recorder[0].body.decode())

        assert link == 'https://testlink'
        assert request['requestType'] == 'VERIFY_EMAIL'
        self._validate_request(request, MOCK_ACTION_CODE_SETTINGS)

    def test_password_reset_with_settings(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"oobLink":"https://testlink"}')
        link = auth.generate_password_reset_link('test@test.com',
                                                 action_code_settings=MOCK_ACTION_CODE_SETTINGS,
                                                 app=user_mgt_app)
        request = json.loads(recorder[0].body.decode())

        assert link == 'https://testlink'
        assert request['requestType'] == 'PASSWORD_RESET'
        self._validate_request(request, MOCK_ACTION_CODE_SETTINGS)

    @pytest.mark.parametrize('func', [
        auth.generate_sign_in_with_email_link,
        auth.generate_email_verification_link,
        auth.generate_password_reset_link,
    ])
    def test_api_call_failure(self, user_mgt_app, func):
        _instrument_user_manager(user_mgt_app, 500, '{"error":{"message": "UNEXPECTED_CODE"}}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            func('test@test.com', MOCK_ACTION_CODE_SETTINGS, app=user_mgt_app)
        assert str(excinfo.value) == 'Error while calling Auth service (UNEXPECTED_CODE).'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    @pytest.mark.parametrize('func', [
        auth.generate_sign_in_with_email_link,
        auth.generate_email_verification_link,
        auth.generate_password_reset_link,
    ])
    def test_invalid_dynamic_link(self, user_mgt_app, func):
        resp = '{"error":{"message": "INVALID_DYNAMIC_LINK_DOMAIN: Because of this reason."}}'
        _instrument_user_manager(user_mgt_app, 500, resp)
        with pytest.raises(auth.InvalidDynamicLinkDomainError) as excinfo:
            func('test@test.com', MOCK_ACTION_CODE_SETTINGS, app=user_mgt_app)
        assert isinstance(excinfo.value, exceptions.InvalidArgumentError)
        assert str(excinfo.value) == ('Dynamic link domain specified in ActionCodeSettings is '
                                      'not authorized (INVALID_DYNAMIC_LINK_DOMAIN). Because '
                                      'of this reason.')
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    @pytest.mark.parametrize('func', [
        auth.generate_sign_in_with_email_link,
        auth.generate_email_verification_link,
        auth.generate_password_reset_link,
    ])
    def test_api_call_no_link(self, user_mgt_app, func):
        _instrument_user_manager(user_mgt_app, 200, '{}')
        with pytest.raises(auth.UnexpectedResponseError) as excinfo:
            func('test@test.com', MOCK_ACTION_CODE_SETTINGS, app=user_mgt_app)
        assert str(excinfo.value) == 'Failed to generate email action link.'
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is None
        assert isinstance(excinfo.value, exceptions.UnknownError)

    @pytest.mark.parametrize('func', [
        auth.generate_sign_in_with_email_link,
        auth.generate_email_verification_link,
        auth.generate_password_reset_link,
    ])
    def test_bad_settings_data(self, user_mgt_app, func):
        _instrument_user_manager(user_mgt_app, 200, '{"oobLink":"https://testlink"}')
        with pytest.raises(AttributeError):
            func('test@test.com', app=user_mgt_app, action_code_settings=1234)

    def test_bad_action_type(self, user_mgt_app):
        with pytest.raises(ValueError):
            auth._get_client(user_mgt_app) \
                ._user_manager \
                .generate_email_action_link('BAD_TYPE', 'test@test.com',
                                            action_code_settings=MOCK_ACTION_CODE_SETTINGS)

    def _validate_request(self, request, settings=None):
        assert request['email'] == 'test@test.com'
        assert request['returnOobLink']
        if settings:
            assert request['continueUrl'] == settings.url
            assert request['canHandleCodeInApp'] == settings.handle_code_in_app
            assert request['dynamicLinkDomain'] == settings.dynamic_link_domain
            assert request['iosBundleId'] == settings.ios_bundle_id
            assert request['androidPackageName'] == settings.android_package_name
            assert request['androidMinimumVersion'] == settings.android_minimum_version
            assert request['androidInstallApp'] == settings.android_install_app
