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
        auth.update_user('non.existing', {})
    assert 'USER_UPDATE_ERROR' in str(excinfo.value.code)

def test_delete_non_existing_user():
    with pytest.raises(auth.AuthError) as excinfo:
        auth.delete_user('non.existing')
    assert 'USER_DELETE_ERROR' in str(excinfo.value.code)

def test_create_user_with_params():
    random_id = str(uuid.uuid4()).lower().replace('-', '')
    email = 'test{0}@example.{1}.com'.format(random_id[:12], random_id[12:])
    phone = '+1' + ''.join([str(random.randint(0, 9)) for _ in range(0, 10)])
    user = auth.create_user({
        'uid' : random_id,
        'email' : email,
        'phoneNumber' : phone,
        'displayName' : 'Random User',
        'photoUrl' : 'https://example.com/photo.png',
        'emailVerified' : True,
        'password' : 'secret',
    })
    try:
        assert user.uid == random_id
        assert user.display_name == 'Random User'
        assert user.email == email
        assert user.phone_number == phone
        assert user.photo_url == 'https://example.com/photo.png'
        assert user.email_verified is True
        assert user.disabled is False

        with pytest.raises(auth.AuthError) as excinfo:
            auth.create_user({'uid' : random_id})
        assert excinfo.value.code == 'USER_CREATE_ERROR'
    finally:
        auth.delete_user(random_id)

def test_user_lifecycle():
    # Create user
    user = auth.create_user()
    uid = user.uid
    assert uid

    # Get user
    user = auth.get_user(uid)
    assert user.uid == uid
    assert user.display_name is None
    assert user.email is None
    assert user.phone_number is None
    assert user.photo_url is None
    assert user.email_verified is False
    assert user.disabled is False
    assert user.user_metadata.creation_timestamp > 0
    assert user.user_metadata.last_sign_in_timestamp is None

    # Update user
    random_id = str(uuid.uuid4()).lower().replace('-', '')
    email = 'test{0}@example.{1}.com'.format(random_id[:12], random_id[12:])
    phone = '+1' + ''.join([str(random.randint(0, 9)) for _ in range(0, 10)])
    user = auth.update_user(uid, {
        'email' : email,
        'phoneNumber' : phone,
        'displayName' : 'Updated Name',
        'photoUrl' : 'https://example.com/photo.png',
        'emailVerified' : True,
        'password' : 'secret',
    })
    assert user.uid == uid
    assert user.display_name == 'Updated Name'
    assert user.email == email
    assert user.phone_number == phone
    assert user.photo_url == 'https://example.com/photo.png'
    assert user.email_verified is True
    assert user.disabled is False

    # Get user by email
    user = auth.get_user_by_email(email)
    assert user.uid == uid

    # Get user by phone
    user = auth.get_user_by_phone_number(phone)
    assert user.uid == uid

    # Disable user and remove properties
    user = auth.update_user(uid, {
        'displayName' : None,
        'photoUrl' : None,
        'disabled' : True,
    })
    assert user.uid == uid
    assert user.display_name is None
    assert user.email == email
    assert user.phone_number == phone
    assert user.photo_url is None
    assert user.email_verified is True
    assert user.disabled is True

    # Delete user
    auth.delete_user(uid)
    with pytest.raises(auth.AuthError) as excinfo:
        auth.get_user(uid)
    assert excinfo.value.code == 'USER_NOT_FOUND_ERROR'
