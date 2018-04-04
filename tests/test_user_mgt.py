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

import json
import time

import pytest

import firebase_admin
from firebase_admin import auth
from firebase_admin import _user_mgt
from tests import testutils


INVALID_STRINGS = [None, '', 0, 1, True, False, list(), tuple(), dict()]
INVALID_BOOLS = [None, '', 'foo', 0, 1, list(), tuple(), dict()]
INVALID_DICTS = [None, 'foo', 0, 1, True, False, list(), tuple()]
INVALID_POSITIVE_NUMS = [None, 'foo', 0, -1, True, False, list(), tuple(), dict()]

MOCK_GET_USER_RESPONSE = testutils.resource('get_user.json')
MOCK_LIST_USERS_RESPONSE = testutils.resource('list_users.json')


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
    user_manager._client.session.mount(
        auth._AuthHTTPClient.ID_TOOLKIT_URL,
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
    def test_invalid_get_user(self, arg, user_mgt_app):
        with pytest.raises(ValueError):
            auth.get_user(arg, app=user_mgt_app)

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
    def test_invalid_uid(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(uid=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-an-email'])
    def test_invalid_email(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(email=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-a-phone', '+'])
    def test_invalid_phone(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(phone_number=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS)
    def test_invalid_display_name(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(display_name=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-a-url'])
    def test_invalid_photo_url(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(photo_url=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['short'])
    def test_invalid_password(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(password=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_email_verified(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(email_verified=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_disabled(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.create_user(disabled=arg, app=user_mgt_app)

    def test_invalid_property(self, user_mgt_app):
        with pytest.raises(ValueError):
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
    def test_invalid_uid(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user(arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-an-email'])
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

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['short'])
    def test_invalid_password(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', password=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_email_verified(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', email_verified=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_disabled(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', disabled=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_DICTS[1:] + ['"json"'])
    def test_invalid_custom_claims(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', custom_claims=arg, app=user_mgt_app)

    def test_invalid_property(self, user_mgt_app):
        with pytest.raises(ValueError):
            auth.update_user('user', unsupported='arg', app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_POSITIVE_NUMS)
    def test_invalid_valid_since(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.update_user('user', valid_since=arg, app=user_mgt_app)

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
    def test_invalid_uid(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.set_custom_user_claims(arg, {'foo': 'bar'}, app=user_mgt_app)

    @pytest.mark.parametrize('arg', INVALID_DICTS[1:] + ['"json"'])
    def test_invalid_custom_claims(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.set_custom_user_claims('user', arg, app=user_mgt_app)

    @pytest.mark.parametrize('key', _user_mgt.RESERVED_CLAIMS)
    def test_single_reserved_claim(self, user_mgt_app, key):
        claims = {key : 'value'}
        with pytest.raises(ValueError) as excinfo:
            auth.set_custom_user_claims('user', claims, app=user_mgt_app)
        assert str(excinfo.value) == 'Claim "{0}" is reserved, and must not be set.'.format(key)

    def test_multiple_reserved_claims(self, user_mgt_app):
        claims = {key : 'value' for key in _user_mgt.RESERVED_CLAIMS}
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
    def test_invalid_delete_user(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.get_user(arg, app=user_mgt_app)

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


class TestRevokeRefreshTokkens(object):

    def test_revoke_refresh_tokens(self, user_mgt_app):
        _, recorder = _instrument_user_manager(user_mgt_app, 200, '{"localId":"testuser"}')
        before_time = time.time()
        auth.revoke_refresh_tokens('testuser', app=user_mgt_app)
        after_time = time.time()

        request = json.loads(recorder[0].body.decode())
        assert request['localId'] == 'testuser'
        assert int(request['validSince']) >= int(before_time)
        assert int(request['validSince']) <= int(after_time)
