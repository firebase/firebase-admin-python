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

"""Test cases for the user management functionality in firebase_admin.auth module."""
import pytest

import firebase_admin
from firebase_admin import auth
from tests import testutils


INVALID_STRINGS = [0, 1, True, False, list(), tuple(), dict()]
INVALID_BOOLS = [None, '', 'foo', 0, 1, list(), tuple(), dict()]

@pytest.fixture(scope='module')
def test_app():
    app = firebase_admin.initialize_app(testutils.MockCredential())
    yield app
    firebase_admin.delete_app(app)

def _instrument_user_manager(app, status, payload):
    auth_service = auth._get_auth_service(app)
    user_manager = auth_service.user_manager
    user_manager._session.mount(
        auth._UserManager._ID_TOOLKIT_URL,
        testutils.MockAdapter(payload, status, []))
    return user_manager


class TestGetUser(object):

    @pytest.mark.parametrize('arg', INVALID_STRINGS)
    def test_invalid_get_user(self, arg):
        with pytest.raises(ValueError):
            auth.get_user(arg)

    def test_get_user(self, test_app):
        _instrument_user_manager(test_app, 200, testutils.resource('get_user.json'))
        user = auth.get_user('testuser')
        assert user.uid == 'testuser'
        assert user.email == 'testuser@example.com'
        assert user.display_name == 'Test User'
        assert user.photo_url == 'http://www.example.com/testuser/photo.png'
        assert user.disabled is False
        assert user.email_verified is True
        assert user.user_metadata.creation_timestamp == 1234567890
        assert user.user_metadata.last_sign_in_timestamp is None
        assert user.provider_id == 'firebase'
        assert len(user.provider_data) == 1
        provider = user.provider_data[0]
        assert provider.uid == 'testuser@example.com'
        assert provider.email == 'testuser@example.com'
        assert provider.display_name == 'Test User'
        assert provider.photo_url == 'http://www.example.com/testuser/photo.png'
        assert provider.provider_id == 'password'

    def test_get_user_non_existing(self, test_app):
        _instrument_user_manager(test_app, 200, '{"users":[]}')
        with pytest.raises(auth.FirebaseAuthError) as excinfo:
            auth.get_user('testuser', test_app)
        assert excinfo.value.code == 'USER_NOT_FOUND_ERROR'

    def test_get_user_http_error(self, test_app):
        _instrument_user_manager(test_app, 500, '{}')
        with pytest.raises(auth.FirebaseAuthError) as excinfo:
            auth.get_user('testuser', test_app)
        assert excinfo.value.code == 'INTERNAL_ERROR'


class TestCreateUser(object):

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['a'*129])
    def test_invalid_uid(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'uid' : arg})

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-an-email'])
    def test_invalid_email(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'email' : arg})

    @pytest.mark.parametrize('arg', INVALID_STRINGS)
    def test_invalid_display_name(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'displayName' : arg})

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['not-a-url'])
    def test_invalid_photo_url(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'photoUrl' : arg})

    @pytest.mark.parametrize('arg', INVALID_STRINGS + ['short'])
    def test_invalid_password(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'password' : arg})

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_email_verified(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'emailVerified' : arg})

    @pytest.mark.parametrize('arg', INVALID_BOOLS)
    def test_invalid_disabled(self, arg):
        with pytest.raises(ValueError):
            auth.create_user({'disabled' : arg})

    def test_invalid_property(self):
        with pytest.raises(ValueError):
            auth.create_user({'unsupported' : 'value'})

    def test_create_user(self, test_app):
        user_mgt = _instrument_user_manager(test_app, 200, '{"localId":"testuser"}')
        assert user_mgt.create_user() == 'testuser'
