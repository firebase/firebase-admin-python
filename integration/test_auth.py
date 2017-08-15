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

"""Integration tests for firebase_admin.auth module."""
import random
import uuid

import pytest
import requests

from firebase_admin import auth


_id_toolkit_url = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken'


def _sign_in(custom_token, api_key):
    body = {'token' : custom_token.decode(), 'returnSecureToken' : True}
    params = {'key' : api_key}
    resp = requests.request('post', _id_toolkit_url, params=params, json=body)
    resp.raise_for_status()
    return resp.json().get('idToken')

def _random_id():
    random_id = str(uuid.uuid4()).lower().replace('-', '')
    email = 'test{0}@example.{1}.com'.format(random_id[:12], random_id[12:])
    return random_id, email

def _random_phone():
    return '+1' + ''.join([str(random.randint(0, 9)) for _ in range(0, 10)])

def test_custom_token(api_key):
    custom_token = auth.create_custom_token('user1')
    id_token = _sign_in(custom_token, api_key)
    claims = auth.verify_id_token(id_token)
    assert claims['uid'] == 'user1'

def test_custom_token_with_claims(api_key):
    dev_claims = {'premium' : True, 'subscription' : 'silver'}
    custom_token = auth.create_custom_token('user2', dev_claims)
    id_token = _sign_in(custom_token, api_key)
    claims = auth.verify_id_token(id_token)
    assert claims['uid'] == 'user2'
    assert claims['premium'] is True
    assert claims['subscription'] == 'silver'

def test_get_non_existing_user():
    with pytest.raises(auth.AuthError) as excinfo:
        auth.get_user('non.existing')
    assert 'USER_NOT_FOUND_ERROR' in str(excinfo.value.code)

def test_get_non_existing_user_by_email():
    with pytest.raises(auth.AuthError) as excinfo:
        auth.get_user_by_email('non.existing@definitely.non.existing')
    assert 'USER_NOT_FOUND_ERROR' in str(excinfo.value.code)

def test_update_non_existing_user():
    with pytest.raises(auth.AuthError) as excinfo:
        auth.update_user('non.existing')
    assert 'USER_UPDATE_ERROR' in str(excinfo.value.code)

def test_delete_non_existing_user():
    with pytest.raises(auth.AuthError) as excinfo:
        auth.delete_user('non.existing')
    assert 'USER_DELETE_ERROR' in str(excinfo.value.code)

@pytest.fixture
def new_user():
    user = auth.create_user()
    yield user
    auth.delete_user(user.uid)

@pytest.fixture
def new_user_with_params():
    random_id, email = _random_id()
    phone = _random_phone()
    user = auth.create_user(
        uid=random_id,
        email=email,
        phone_number=phone,
        display_name='Random User',
        photo_url='https://example.com/photo.png',
        email_verified=True,
        password='secret',
    )
    yield user
    auth.delete_user(user.uid)

def test_get_user(new_user_with_params):
    user = auth.get_user(new_user_with_params.uid)
    assert user.uid == new_user_with_params.uid
    assert user.display_name == 'Random User'
    assert user.email == new_user_with_params.email
    assert user.phone_number == new_user_with_params.phone_number
    assert user.photo_url == 'https://example.com/photo.png'
    assert user.email_verified is True
    assert user.disabled is False

    user = auth.get_user_by_email(new_user_with_params.email)
    assert user.uid == new_user_with_params.uid
    user = auth.get_user_by_phone_number(new_user_with_params.phone_number)
    assert user.uid == new_user_with_params.uid

    assert len(user.provider_data) == 2
    provider_ids = sorted([provider.provider_id for provider in user.provider_data])
    assert provider_ids == ['password', 'phone']

def test_create_user(new_user):
    user = auth.get_user(new_user.uid)
    assert user.uid == new_user.uid
    assert user.display_name is None
    assert user.email is None
    assert user.phone_number is None
    assert user.photo_url is None
    assert user.email_verified is False
    assert user.disabled is False
    assert user.user_metadata.creation_timestamp > 0
    assert user.user_metadata.last_sign_in_timestamp is None
    assert len(user.provider_data) is 0
    with pytest.raises(auth.AuthError) as excinfo:
        auth.create_user(uid=new_user.uid)
    assert excinfo.value.code == 'USER_CREATE_ERROR'

def test_update_user(new_user):
    _, email = _random_id()
    phone = _random_phone()
    user = auth.update_user(
        new_user.uid,
        email=email,
        phone_number=phone,
        display_name='Updated Name',
        photo_url='https://example.com/photo.png',
        email_verified=True,
        password='secret')
    assert user.uid == new_user.uid
    assert user.display_name == 'Updated Name'
    assert user.email == email
    assert user.phone_number == phone
    assert user.photo_url == 'https://example.com/photo.png'
    assert user.email_verified is True
    assert user.disabled is False
    assert len(user.provider_data) == 2

def test_disable_user(new_user_with_params):
    user = auth.update_user(
        new_user_with_params.uid,
        display_name=None,
        photo_url=None,
        phone_number=None,
        disabled=True)
    assert user.uid == new_user_with_params.uid
    assert user.email == new_user_with_params.email
    assert user.display_name is None
    assert user.phone_number is None
    assert user.photo_url is None
    assert user.email_verified is True
    assert user.disabled is True
    assert len(user.provider_data) == 1

def test_delete_user():
    user = auth.create_user()
    auth.delete_user(user.uid)
    with pytest.raises(auth.AuthError) as excinfo:
        auth.get_user(user.uid)
    assert excinfo.value.code == 'USER_NOT_FOUND_ERROR'
