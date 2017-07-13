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
    with pytest.raises(auth.FirebaseAuthError) as excinfo:
        auth.get_user('non.existing')
    assert 'USER_NOT_FOUND_ERROR' in str(excinfo.value.code)

def test_user_lifecycle():
    user = auth.create_user()
    uid = user.uid
    assert uid

    user = auth.get_user(uid)
    assert user.uid == uid
    assert user.display_name is None
    assert user.email is None
    assert user.photo_url is None
    assert user.email_verified is False
    assert user.disabled is False
    assert user.user_metadata.creation_timestamp > 0
    assert user.user_metadata.last_sign_in_timestamp is None
