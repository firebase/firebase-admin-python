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
import base64
import datetime
import random
import string
import time
from typing import List
from urllib import parse
import uuid

import google.oauth2.credentials
from google.auth import transport
import pytest
import requests

import firebase_admin
from firebase_admin import auth
from firebase_admin import credentials


_verify_token_url = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken'
_verify_password_url = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword'
_password_reset_url = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/resetPassword'
_verify_email_url = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/setAccountInfo'
_email_sign_in_url = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/emailLinkSignin'

ACTION_LINK_CONTINUE_URL = 'http://localhost?a=1&b=5#f=1'

X509_CERTIFICATES = [
    ('-----BEGIN CERTIFICATE-----\nMIICZjCCAc+gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBQMQswCQYDVQQGEwJ1czE'
     'L\nMAkGA1UECAwCQ0ExDTALBgNVBAoMBEFjbWUxETAPBgNVBAMMCGFjbWUuY29tMRIw\nEAYDVQQHDAlTdW5ueXZhbGU'
     'wHhcNMTgxMjA2MDc1MTUxWhcNMjgxMjAzMDc1MTUx\nWjBQMQswCQYDVQQGEwJ1czELMAkGA1UECAwCQ0ExDTALBgNVB'
     'AoMBEFjbWUxETAP\nBgNVBAMMCGFjbWUuY29tMRIwEAYDVQQHDAlTdW5ueXZhbGUwgZ8wDQYJKoZIhvcN\nAQEBBQADg'
     'Y0AMIGJAoGBAKphmggjiVgqMLXyzvI7cKphscIIQ+wcv7Dld6MD4aKv\n7Jqr8ltujMxBUeY4LFEKw8Terb01snYpDot'
     'filaG6NxpF/GfVVmMalzwWp0mT8+H\nyzyPj89mRcozu17RwuooR6n1ofXjGcBE86lqC21UhA3WVgjPOLqB42rlE9gPn'
     'ZLB\nAgMBAAGjUDBOMB0GA1UdDgQWBBS0iM7WnbCNOnieOP1HIA+Oz/ML+zAfBgNVHSME\nGDAWgBS0iM7WnbCNOnieO'
     'P1HIA+Oz/ML+zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3\nDQEBDQUAA4GBAF3jBgS+wP+K/jTupEQur6iaqS4UvXd//d4'
     'vo1MV06oTLQMTz+rP\nOSMDNwxzfaOn6vgYLKP/Dcy9dSTnSzgxLAxfKvDQZA0vE3udsw0Bd245MmX4+GOp\nlbrN99X'
     'P1u+lFxCSdMUzvQ/jW4ysw/Nq4JdJ0gPAyPvL6Qi/3mQdIQwx\n-----END CERTIFICATE-----\n'),
    ('-----BEGIN CERTIFICATE-----\nMIICZjCCAc+gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBQMQswCQYDVQQGEwJ1czE'
     'L\nMAkGA1UECAwCQ0ExDTALBgNVBAoMBEFjbWUxETAPBgNVBAMMCGFjbWUuY29tMRIw\nEAYDVQQHDAlTdW5ueXZhbGU'
     'wHhcNMTgxMjA2MDc1ODE4WhcNMjgxMjAzMDc1ODE4\nWjBQMQswCQYDVQQGEwJ1czELMAkGA1UECAwCQ0ExDTALBgNVB'
     'AoMBEFjbWUxETAP\nBgNVBAMMCGFjbWUuY29tMRIwEAYDVQQHDAlTdW5ueXZhbGUwgZ8wDQYJKoZIhvcN\nAQEBBQADg'
     'Y0AMIGJAoGBAKuzYKfDZGA6DJgQru3wNUqv+S0hMZfP/jbp8ou/8UKu\nrNeX7cfCgt3yxoGCJYKmF6t5mvo76JY0MWw'
     'A53BxeP/oyXmJ93uHG5mFRAsVAUKs\ncVVb0Xi6ujxZGVdDWFV696L0BNOoHTfXmac6IBoZQzNNK4n1AATqwo+z7a0pf'
     'RrJ\nAgMBAAGjUDBOMB0GA1UdDgQWBBSKmi/ZKMuLN0ES7/jPa7q7jAjPiDAfBgNVHSME\nGDAWgBSKmi/ZKMuLN0ES7'
     '/jPa7q7jAjPiDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3\nDQEBDQUAA4GBAAg2a2kSn05NiUOuWOHwPUjW3wQRsGxPXtb'
     'hWMhmNdCfKKteM2+/\nLd/jz5F3qkOgGQ3UDgr3SHEoWhnLaJMF4a2tm6vL2rEIfPEK81KhTTRxSsAgMVbU\nJXBz1md'
     '6Ur0HlgQC7d1CHC8/xi2DDwHopLyxhogaZUxy9IaRxUEa2vJW\n-----END CERTIFICATE-----\n'),
]


def _sign_in(custom_token, api_key):
    body = {'token' : custom_token.decode(), 'returnSecureToken' : True}
    params = {'key' : api_key}
    resp = requests.request('post', _verify_token_url, params=params, json=body)
    resp.raise_for_status()
    return resp.json().get('idToken')

def _sign_in_with_password(email, password, api_key):
    body = {'email': email, 'password': password, 'returnSecureToken': True}
    params = {'key' : api_key}
    resp = requests.request('post', _verify_password_url, params=params, json=body)
    resp.raise_for_status()
    return resp.json().get('idToken')

def _random_string(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def _random_id():
    random_id = str(uuid.uuid4()).lower().replace('-', '')
    email = 'test{0}@example.{1}.com'.format(random_id[:12], random_id[12:])
    return random_id, email

def _random_phone():
    return '+1' + ''.join([str(random.randint(0, 9)) for _ in range(0, 10)])

def _reset_password(oob_code, new_password, api_key):
    body = {'oobCode': oob_code, 'newPassword': new_password}
    params = {'key' : api_key}
    resp = requests.request('post', _password_reset_url, params=params, json=body)
    resp.raise_for_status()
    return resp.json().get('email')

def _verify_email(oob_code, api_key):
    body = {'oobCode': oob_code}
    params = {'key' : api_key}
    resp = requests.request('post', _verify_email_url, params=params, json=body)
    resp.raise_for_status()
    return resp.json().get('email')

def _sign_in_with_email_link(email, oob_code, api_key):
    body = {'oobCode': oob_code, 'email': email}
    params = {'key' : api_key}
    resp = requests.request('post', _email_sign_in_url, params=params, json=body)
    resp.raise_for_status()
    return resp.json().get('idToken')

def _extract_link_params(link):
    query = parse.urlparse(link).query
    query_dict = dict(parse.parse_qsl(query))
    return query_dict

def test_custom_token(api_key):
    custom_token = auth.create_custom_token('user1')
    id_token = _sign_in(custom_token, api_key)
    claims = auth.verify_id_token(id_token)
    assert claims['uid'] == 'user1'

def test_custom_token_without_service_account(api_key):
    google_cred = firebase_admin.get_app().credential.get_credential()
    cred = CredentialWrapper.from_existing_credential(google_cred)
    custom_app = firebase_admin.initialize_app(cred, {
        'serviceAccountId': google_cred.service_account_email,
        'projectId': firebase_admin.get_app().project_id
    }, 'temp-app')
    try:
        custom_token = auth.create_custom_token('user1', app=custom_app)
        id_token = _sign_in(custom_token, api_key)
        claims = auth.verify_id_token(id_token)
        assert claims['uid'] == 'user1'
    finally:
        firebase_admin.delete_app(custom_app)

def test_custom_token_with_claims(api_key):
    dev_claims = {'premium' : True, 'subscription' : 'silver'}
    custom_token = auth.create_custom_token('user2', dev_claims)
    id_token = _sign_in(custom_token, api_key)
    claims = auth.verify_id_token(id_token)
    assert claims['uid'] == 'user2'
    assert claims['premium'] is True
    assert claims['subscription'] == 'silver'

def test_session_cookies(api_key):
    dev_claims = {'premium' : True, 'subscription' : 'silver'}
    custom_token = auth.create_custom_token('user3', dev_claims)
    id_token = _sign_in(custom_token, api_key)
    expires_in = datetime.timedelta(days=1)
    session_cookie = auth.create_session_cookie(id_token, expires_in=expires_in)
    claims = auth.verify_session_cookie(session_cookie)
    assert claims['uid'] == 'user3'
    assert claims['premium'] is True
    assert claims['subscription'] == 'silver'
    assert claims['iss'].startswith('https://session.firebase.google.com')
    estimated_exp = int(time.time() + expires_in.total_seconds())
    assert abs(claims['exp'] - estimated_exp) < 5

def test_session_cookie_error():
    expires_in = datetime.timedelta(days=1)
    with pytest.raises(auth.InvalidIdTokenError):
        auth.create_session_cookie('not.a.token', expires_in=expires_in)

def test_get_non_existing_user():
    with pytest.raises(auth.UserNotFoundError) as excinfo:
        auth.get_user('non.existing')
    assert str(excinfo.value) == 'No user record found for the provided user ID: non.existing.'

def test_get_non_existing_user_by_email():
    with pytest.raises(auth.UserNotFoundError) as excinfo:
        auth.get_user_by_email('non.existing@definitely.non.existing')
    error_msg = ('No user record found for the provided email: '
                 'non.existing@definitely.non.existing.')
    assert str(excinfo.value) == error_msg

def test_update_non_existing_user():
    with pytest.raises(auth.UserNotFoundError):
        auth.update_user('non.existing')

def test_delete_non_existing_user():
    with pytest.raises(auth.UserNotFoundError):
        auth.delete_user('non.existing')

@pytest.fixture
def new_user():
    user = auth.create_user()
    yield user
    auth.delete_user(user.uid)

@pytest.fixture
def new_user_with_params() -> auth.UserRecord:
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

@pytest.fixture
def new_user_list():
    users = [
        auth.create_user(password='password').uid,
        auth.create_user(password='password').uid,
        auth.create_user(password='password').uid,
    ]
    yield users
    # TODO(rsgowman): Using auth.delete_users() would make more sense here, but
    # that's currently rate limited to 1qps, so using it in this context would
    # almost certainly trigger errors. When/if that limit is relaxed, switch to
    # batch delete.
    for uid in users:
        auth.delete_user(uid)

@pytest.fixture
def new_user_record_list() -> List[auth.UserRecord]:
    uid1, email1 = _random_id()
    uid2, email2 = _random_id()
    uid3, email3 = _random_id()
    users = [
        auth.create_user(
            uid=uid1, email=email1, password='password', phone_number=_random_phone()),
        auth.create_user(
            uid=uid2, email=email2, password='password', phone_number=_random_phone()),
        auth.create_user(
            uid=uid3, email=email3, password='password', phone_number=_random_phone()),
    ]
    yield users
    for user in users:
        auth.delete_user(user.uid)

@pytest.fixture
def new_user_with_provider() -> auth.UserRecord:
    uid4, email4 = _random_id()
    google_uid, google_email = _random_id()
    import_user1 = auth.ImportUserRecord(
        uid=uid4,
        email=email4,
        provider_data=[
            auth.UserProvider(
                uid=google_uid,
                provider_id='google.com',
                email=google_email,
            )
        ])
    user_import_result = auth.import_users([import_user1])
    assert user_import_result.success_count == 1
    assert user_import_result.failure_count == 0

    user = auth.get_user(uid4)
    yield user
    auth.delete_user(user.uid)

@pytest.fixture
def new_user_email_unverified():
    random_id, email = _random_id()
    user = auth.create_user(
        uid=random_id,
        email=email,
        email_verified=False,
        password='password'
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

class TestGetUsers:
    @staticmethod
    def _map_user_record_to_uid_email_phones(user_record):
        return {
            'uid': user_record.uid,
            'email': user_record.email,
            'phone_number': user_record.phone_number
        }

    def test_multiple_uid_types(self, new_user_record_list, new_user_with_provider):
        get_users_results = auth.get_users([
            auth.UidIdentifier(new_user_record_list[0].uid),
            auth.EmailIdentifier(new_user_record_list[1].email),
            auth.PhoneIdentifier(new_user_record_list[2].phone_number),
            auth.ProviderIdentifier(
                new_user_with_provider.provider_data[0].provider_id,
                new_user_with_provider.provider_data[0].uid,
            )])
        actual = sorted([
            self._map_user_record_to_uid_email_phones(user)
            for user in get_users_results.users
        ], key=lambda user: user['uid'])
        expected = sorted([
            self._map_user_record_to_uid_email_phones(user)
            for user in new_user_record_list + [new_user_with_provider]
        ], key=lambda user: user['uid'])

        assert actual == expected

    def test_existing_and_non_existing_users(self, new_user_record_list):
        get_users_results = auth.get_users([
            auth.UidIdentifier(new_user_record_list[0].uid),
            auth.UidIdentifier('uid_that_doesnt_exist'),
            auth.UidIdentifier(new_user_record_list[2].uid)])
        actual = sorted([
            self._map_user_record_to_uid_email_phones(user)
            for user in get_users_results.users
        ], key=lambda user: user['uid'])
        expected = sorted([
            self._map_user_record_to_uid_email_phones(user)
            for user in [new_user_record_list[0], new_user_record_list[2]]
        ], key=lambda user: user['uid'])

        assert actual == expected

    def test_non_existing_users(self):
        not_found_ids = [auth.UidIdentifier('non-existing user')]
        get_users_results = auth.get_users(not_found_ids)

        assert get_users_results.users == []
        assert get_users_results.not_found == not_found_ids

    def test_de_dups_duplicate_users(self, new_user):
        get_users_results = auth.get_users([
            auth.UidIdentifier(new_user.uid),
            auth.UidIdentifier(new_user.uid)])
        actual = [
            self._map_user_record_to_uid_email_phones(user)
            for user in get_users_results.users]
        expected = [self._map_user_record_to_uid_email_phones(new_user)]
        assert actual == expected

def test_last_refresh_timestamp(new_user_with_params: auth.UserRecord, api_key):
    # new users should not have a last_refresh_timestamp set
    assert new_user_with_params.user_metadata.last_refresh_timestamp is None

    # login to cause the last_refresh_timestamp to be set
    _sign_in_with_password(new_user_with_params.email, 'secret', api_key)

    # Attempt to retrieve the user 3 times (with a small delay between each
    # attempt). Occassionally, this call retrieves the user data without the
    # lastLoginTime/lastRefreshTime set; possibly because it's hitting a
    # different server than the login request uses.
    user_record = None
    for iteration in range(0, 3):
        user_record = auth.get_user(new_user_with_params.uid)
        if user_record.user_metadata.last_refresh_timestamp is not None:
            break

        time.sleep(2 ** iteration)

    # Ensure the last refresh time occurred at approximately 'now'. (With a
    # tolerance of up to 1 minute; we ideally want to ensure that any timezone
    # considerations are handled properly, so as long as we're within an hour,
    # we're in good shape.)
    millis_per_second = 1000
    millis_per_minute = millis_per_second * 60

    last_refresh_timestamp = user_record.user_metadata.last_refresh_timestamp
    assert last_refresh_timestamp == pytest.approx(
        time.time()*millis_per_second, 1*millis_per_minute)

def test_list_users(new_user_list):
    err_msg_template = (
        'Missing {field} field. A common cause would be forgetting to add the "Firebase ' +
        'Authentication Admin" permission. See instructions in CONTRIBUTING.md')

    fetched = []
    # Test exporting all user accounts.
    page = auth.list_users()
    while page:
        for user in page.users:
            assert isinstance(user, auth.ExportedUserRecord)
            if user.uid in new_user_list:
                fetched.append(user.uid)
                assert user.password_hash is not None, (
                    err_msg_template.format(field='password_hash'))
                assert user.password_salt is not None, (
                    err_msg_template.format(field='password_salt'))
        page = page.get_next_page()
    assert len(fetched) == len(new_user_list)

    fetched = []
    page = auth.list_users()
    for user in page.iterate_all():
        assert isinstance(user, auth.ExportedUserRecord)
        if user.uid in new_user_list:
            fetched.append(user.uid)
            assert user.password_hash is not None, (
                err_msg_template.format(field='password_hash'))
            assert user.password_salt is not None, (
                err_msg_template.format(field='password_salt'))
    assert len(fetched) == len(new_user_list)

def test_create_user(new_user):
    user = auth.get_user(new_user.uid)
    assert user.uid == new_user.uid
    assert user.display_name is None
    assert user.email is None
    assert user.phone_number is None
    assert user.photo_url is None
    assert user.email_verified is False
    assert user.disabled is False
    assert user.custom_claims is None
    assert user.user_metadata.creation_timestamp > 0
    assert user.user_metadata.last_sign_in_timestamp is None
    assert len(user.provider_data) == 0
    with pytest.raises(auth.UidAlreadyExistsError):
        auth.create_user(uid=new_user.uid)

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
    assert user.custom_claims is None
    assert len(user.provider_data) == 2

def test_set_custom_user_claims(new_user, api_key):
    claims = {'admin' : True, 'package' : 'gold'}
    auth.set_custom_user_claims(new_user.uid, claims)
    user = auth.get_user(new_user.uid)
    assert user.custom_claims == claims
    custom_token = auth.create_custom_token(new_user.uid)
    id_token = _sign_in(custom_token, api_key)
    dev_claims = auth.verify_id_token(id_token)
    for key, value in claims.items():
        assert dev_claims[key] == value

def test_update_custom_user_claims(new_user):
    assert new_user.custom_claims is None
    claims = {'admin' : True, 'package' : 'gold'}
    auth.set_custom_user_claims(new_user.uid, claims)
    user = auth.get_user(new_user.uid)
    assert user.custom_claims == claims

    claims = {'admin' : False, 'subscription' : 'guest'}
    auth.set_custom_user_claims(new_user.uid, claims)
    user = auth.get_user(new_user.uid)
    assert user.custom_claims == claims

    auth.set_custom_user_claims(new_user.uid, None)
    user = auth.get_user(new_user.uid)
    assert user.custom_claims is None

def test_disable_user(new_user_with_params):
    user = auth.update_user(
        new_user_with_params.uid,
        display_name=auth.DELETE_ATTRIBUTE,
        photo_url=auth.DELETE_ATTRIBUTE,
        phone_number=auth.DELETE_ATTRIBUTE,
        disabled=True)
    assert user.uid == new_user_with_params.uid
    assert user.email == new_user_with_params.email
    assert user.display_name is None
    assert user.phone_number is None
    assert user.photo_url is None
    assert user.email_verified is True
    assert user.disabled is True
    assert len(user.provider_data) == 1

def test_remove_provider(new_user_with_provider):
    provider_ids = [provider.provider_id for provider in new_user_with_provider.provider_data]
    assert 'google.com' in provider_ids
    user = auth.update_user(new_user_with_provider.uid, providers_to_delete=['google.com'])
    assert user.uid == new_user_with_provider.uid
    new_provider_ids = [provider.provider_id for provider in user.provider_data]
    assert 'google.com' not in new_provider_ids

def test_delete_user():
    user = auth.create_user()
    auth.delete_user(user.uid)
    with pytest.raises(auth.UserNotFoundError):
        auth.get_user(user.uid)


class TestDeleteUsers:
    def test_delete_multiple_users(self):
        uid1 = auth.create_user(disabled=True).uid
        uid2 = auth.create_user(disabled=False).uid
        uid3 = auth.create_user(disabled=True).uid

        delete_users_result = self._slow_delete_users(auth, [uid1, uid2, uid3])
        assert delete_users_result.success_count == 3
        assert delete_users_result.failure_count == 0
        assert len(delete_users_result.errors) == 0

        get_users_results = auth.get_users(
            [auth.UidIdentifier(uid1), auth.UidIdentifier(uid2), auth.UidIdentifier(uid3)])
        assert len(get_users_results.users) == 0

    def test_is_idempotent(self):
        uid = auth.create_user().uid

        delete_users_result = self._slow_delete_users(auth, [uid])
        assert delete_users_result.success_count == 1
        assert delete_users_result.failure_count == 0

        # Delete the user again, ensuring that everything still counts as a
        # success.
        delete_users_result = self._slow_delete_users(auth, [uid])
        assert delete_users_result.success_count == 1
        assert delete_users_result.failure_count == 0

    def _slow_delete_users(self, auth, uids):
        """The batchDelete endpoint has a rate limit of 1 QPS. Use this test
        helper to ensure you don't exceed the quota."""
        time.sleep(1)
        return auth.delete_users(uids)


def test_revoke_refresh_tokens(new_user):
    user = auth.get_user(new_user.uid)
    old_valid_after = user.tokens_valid_after_timestamp
    time.sleep(1)
    auth.revoke_refresh_tokens(new_user.uid)
    user = auth.get_user(new_user.uid)
    new_valid_after = user.tokens_valid_after_timestamp
    assert new_valid_after > old_valid_after

def test_verify_id_token_revoked(new_user, api_key):
    custom_token = auth.create_custom_token(new_user.uid)
    id_token = _sign_in(custom_token, api_key)
    claims = auth.verify_id_token(id_token)
    assert claims['iat'] * 1000 >= new_user.tokens_valid_after_timestamp

    time.sleep(1)
    auth.revoke_refresh_tokens(new_user.uid)
    claims = auth.verify_id_token(id_token, check_revoked=False)
    user = auth.get_user(new_user.uid)
    # verify_id_token succeeded because it didn't check revoked.
    assert claims['iat'] * 1000 < user.tokens_valid_after_timestamp

    with pytest.raises(auth.RevokedIdTokenError) as excinfo:
        claims = auth.verify_id_token(id_token, check_revoked=True)
    assert str(excinfo.value) == 'The Firebase ID token has been revoked.'

    # Sign in again, verify works.
    id_token = _sign_in(custom_token, api_key)
    claims = auth.verify_id_token(id_token, check_revoked=True)
    assert claims['iat'] * 1000 >= user.tokens_valid_after_timestamp

def test_verify_id_token_disabled(new_user, api_key):
    custom_token = auth.create_custom_token(new_user.uid)
    id_token = _sign_in(custom_token, api_key)
    claims = auth.verify_id_token(id_token, check_revoked=True)

    # Disable the user record.
    auth.update_user(new_user.uid, disabled=True)
    # Verify the ID token without checking revocation. This should
    # not raise.
    claims = auth.verify_id_token(id_token, check_revoked=False)
    assert claims['sub'] == new_user.uid

    # Verify the ID token while checking revocation. This should
    # raise an exception.
    with pytest.raises(auth.UserDisabledError) as excinfo:
        auth.verify_id_token(id_token, check_revoked=True)
    assert str(excinfo.value) == 'The user record is disabled.'

def test_verify_session_cookie_revoked(new_user, api_key):
    custom_token = auth.create_custom_token(new_user.uid)
    id_token = _sign_in(custom_token, api_key)
    session_cookie = auth.create_session_cookie(id_token, expires_in=datetime.timedelta(days=1))

    time.sleep(1)
    auth.revoke_refresh_tokens(new_user.uid)
    claims = auth.verify_session_cookie(session_cookie, check_revoked=False)
    user = auth.get_user(new_user.uid)
    # verify_session_cookie succeeded because it didn't check revoked.
    assert claims['iat'] * 1000 < user.tokens_valid_after_timestamp

    with pytest.raises(auth.RevokedSessionCookieError) as excinfo:
        claims = auth.verify_session_cookie(session_cookie, check_revoked=True)
    assert str(excinfo.value) == 'The Firebase session cookie has been revoked.'

    # Sign in again, verify works.
    id_token = _sign_in(custom_token, api_key)
    session_cookie = auth.create_session_cookie(id_token, expires_in=datetime.timedelta(days=1))
    claims = auth.verify_session_cookie(session_cookie, check_revoked=True)
    assert claims['iat'] * 1000 >= user.tokens_valid_after_timestamp

def test_verify_session_cookie_disabled(new_user, api_key):
    custom_token = auth.create_custom_token(new_user.uid)
    id_token = _sign_in(custom_token, api_key)
    session_cookie = auth.create_session_cookie(id_token, expires_in=datetime.timedelta(days=1))

    # Disable the user record.
    auth.update_user(new_user.uid, disabled=True)
    # Verify the session cookie without checking revocation. This should
    # not raise.
    claims = auth.verify_session_cookie(session_cookie, check_revoked=False)
    assert claims['sub'] == new_user.uid

    # Verify the session cookie while checking revocation. This should
    # raise an exception.
    with pytest.raises(auth.UserDisabledError) as excinfo:
        auth.verify_session_cookie(session_cookie, check_revoked=True)
    assert str(excinfo.value) == 'The user record is disabled.'

def test_import_users():
    uid, email = _random_id()
    user = auth.ImportUserRecord(uid=uid, email=email)
    result = auth.import_users([user])
    try:
        assert result.success_count == 1
        assert result.failure_count == 0
        saved_user = auth.get_user(uid)
        assert saved_user.email == email
    finally:
        auth.delete_user(uid)

def test_import_users_with_password(api_key):
    uid, email = _random_id()
    password_hash = base64.b64decode(
        'V358E8LdWJXAO7muq0CufVpEOXaj8aFiC7T/rcaGieN04q/ZPJ08WhJEHGjj9lz/2TT+/86N5VjVoc5DdBhBiw==')
    user = auth.ImportUserRecord(
        uid=uid, email=email, password_hash=password_hash, password_salt=b'NaCl')

    scrypt_key = base64.b64decode(
        'jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==')
    salt_separator = base64.b64decode('Bw==')
    scrypt = auth.UserImportHash.scrypt(
        key=scrypt_key, salt_separator=salt_separator, rounds=8, memory_cost=14)
    result = auth.import_users([user], hash_alg=scrypt)
    try:
        assert result.success_count == 1
        assert result.failure_count == 0
        saved_user = auth.get_user(uid)
        assert saved_user.email == email
        id_token = _sign_in_with_password(email, 'password', api_key)
        assert len(id_token) > 0
    finally:
        auth.delete_user(uid)

def test_password_reset(new_user_email_unverified, api_key):
    link = auth.generate_password_reset_link(new_user_email_unverified.email)
    assert isinstance(link, str)
    query_dict = _extract_link_params(link)
    user_email = _reset_password(query_dict['oobCode'], 'newPassword', api_key)
    assert new_user_email_unverified.email == user_email
    # password reset also set email_verified to True
    assert auth.get_user(new_user_email_unverified.uid).email_verified

def test_email_verification(new_user_email_unverified, api_key):
    link = auth.generate_email_verification_link(new_user_email_unverified.email)
    assert isinstance(link, str)
    query_dict = _extract_link_params(link)
    user_email = _verify_email(query_dict['oobCode'], api_key)
    assert new_user_email_unverified.email == user_email
    assert auth.get_user(new_user_email_unverified.uid).email_verified

def test_password_reset_with_settings(new_user_email_unverified, api_key):
    action_code_settings = auth.ActionCodeSettings(ACTION_LINK_CONTINUE_URL)
    link = auth.generate_password_reset_link(new_user_email_unverified.email,
                                             action_code_settings=action_code_settings)
    assert isinstance(link, str)
    query_dict = _extract_link_params(link)
    assert query_dict['continueUrl'] == ACTION_LINK_CONTINUE_URL
    user_email = _reset_password(query_dict['oobCode'], 'newPassword', api_key)
    assert new_user_email_unverified.email == user_email
    # password reset also set email_verified to True
    assert auth.get_user(new_user_email_unverified.uid).email_verified

def test_email_verification_with_settings(new_user_email_unverified, api_key):
    action_code_settings = auth.ActionCodeSettings(ACTION_LINK_CONTINUE_URL)
    link = auth.generate_email_verification_link(new_user_email_unverified.email,
                                                 action_code_settings=action_code_settings)
    assert isinstance(link, str)
    query_dict = _extract_link_params(link)
    assert query_dict['continueUrl'] == ACTION_LINK_CONTINUE_URL
    user_email = _verify_email(query_dict['oobCode'], api_key)
    assert new_user_email_unverified.email == user_email
    assert auth.get_user(new_user_email_unverified.uid).email_verified

def test_email_sign_in_with_settings(new_user_email_unverified, api_key):
    action_code_settings = auth.ActionCodeSettings(ACTION_LINK_CONTINUE_URL)
    link = auth.generate_sign_in_with_email_link(new_user_email_unverified.email,
                                                 action_code_settings=action_code_settings)
    assert isinstance(link, str)
    query_dict = _extract_link_params(link)
    assert query_dict['continueUrl'] == ACTION_LINK_CONTINUE_URL
    oob_code = query_dict['oobCode']
    id_token = _sign_in_with_email_link(new_user_email_unverified.email, oob_code, api_key)
    assert id_token is not None and len(id_token) > 0
    assert auth.get_user(new_user_email_unverified.uid).email_verified


@pytest.fixture(scope='module')
def oidc_provider():
    provider_config = _create_oidc_provider_config()
    yield provider_config
    auth.delete_oidc_provider_config(provider_config.provider_id)


def test_create_oidc_provider_config(oidc_provider):
    assert isinstance(oidc_provider, auth.OIDCProviderConfig)
    assert oidc_provider.client_id == 'OIDC_CLIENT_ID'
    assert oidc_provider.issuer == 'https://oidc.com/issuer'
    assert oidc_provider.display_name == 'OIDC_DISPLAY_NAME'
    assert oidc_provider.enabled is True
    assert oidc_provider.id_token_response_type is True
    assert oidc_provider.code_response_type is False
    assert oidc_provider.client_secret is None


def test_get_oidc_provider_config(oidc_provider):
    provider_config = auth.get_oidc_provider_config(oidc_provider.provider_id)
    assert isinstance(provider_config, auth.OIDCProviderConfig)
    assert provider_config.provider_id == oidc_provider.provider_id
    assert provider_config.client_id == 'OIDC_CLIENT_ID'
    assert provider_config.issuer == 'https://oidc.com/issuer'
    assert provider_config.display_name == 'OIDC_DISPLAY_NAME'
    assert provider_config.enabled is True
    assert provider_config.id_token_response_type is True
    assert provider_config.code_response_type is False
    assert provider_config.client_secret is None


def test_list_oidc_provider_configs(oidc_provider):
    page = auth.list_oidc_provider_configs()
    result = None
    for provider_config in page.iterate_all():
        if provider_config.provider_id == oidc_provider.provider_id:
            result = provider_config
            break

    assert result is not None


def test_update_oidc_provider_config():
    provider_config = _create_oidc_provider_config()
    try:
        provider_config = auth.update_oidc_provider_config(
            provider_config.provider_id,
            client_id='UPDATED_OIDC_CLIENT_ID',
            issuer='https://oidc.com/updated_issuer',
            display_name='UPDATED_OIDC_DISPLAY_NAME',
            enabled=False,
            client_secret='CLIENT_SECRET',
            id_token_response_type=False,
            code_response_type=True)
        assert provider_config.client_id == 'UPDATED_OIDC_CLIENT_ID'
        assert provider_config.issuer == 'https://oidc.com/updated_issuer'
        assert provider_config.display_name == 'UPDATED_OIDC_DISPLAY_NAME'
        assert provider_config.enabled is False
        assert provider_config.id_token_response_type is False
        assert provider_config.code_response_type is True
        assert provider_config.client_secret == 'CLIENT_SECRET'
    finally:
        auth.delete_oidc_provider_config(provider_config.provider_id)


def test_delete_oidc_provider_config():
    provider_config = _create_oidc_provider_config()
    auth.delete_oidc_provider_config(provider_config.provider_id)
    with pytest.raises(auth.ConfigurationNotFoundError):
        auth.get_oidc_provider_config(provider_config.provider_id)


@pytest.fixture(scope='module')
def saml_provider():
    provider_config = _create_saml_provider_config()
    yield provider_config
    auth.delete_saml_provider_config(provider_config.provider_id)


def test_create_saml_provider_config(saml_provider):
    assert isinstance(saml_provider, auth.SAMLProviderConfig)
    assert saml_provider.idp_entity_id == 'IDP_ENTITY_ID'
    assert saml_provider.sso_url == 'https://example.com/login'
    assert saml_provider.x509_certificates == [X509_CERTIFICATES[0]]
    assert saml_provider.rp_entity_id == 'RP_ENTITY_ID'
    assert saml_provider.callback_url == 'https://projectId.firebaseapp.com/__/auth/handler'
    assert saml_provider.display_name == 'SAML_DISPLAY_NAME'
    assert saml_provider.enabled is True


def test_get_saml_provider_config(saml_provider):
    provider_config = auth.get_saml_provider_config(saml_provider.provider_id)
    assert isinstance(provider_config, auth.SAMLProviderConfig)
    assert provider_config.provider_id == saml_provider.provider_id
    assert provider_config.idp_entity_id == 'IDP_ENTITY_ID'
    assert provider_config.sso_url == 'https://example.com/login'
    assert provider_config.x509_certificates == [X509_CERTIFICATES[0]]
    assert provider_config.rp_entity_id == 'RP_ENTITY_ID'
    assert provider_config.callback_url == 'https://projectId.firebaseapp.com/__/auth/handler'
    assert provider_config.display_name == 'SAML_DISPLAY_NAME'
    assert provider_config.enabled is True


def test_list_saml_provider_configs(saml_provider):
    page = auth.list_saml_provider_configs()
    result = None
    for provider_config in page.iterate_all():
        if provider_config.provider_id == saml_provider.provider_id:
            result = provider_config
            break

    assert result is not None


def test_update_saml_provider_config():
    provider_config = _create_saml_provider_config()
    try:
        provider_config = auth.update_saml_provider_config(
            provider_config.provider_id,
            idp_entity_id='UPDATED_IDP_ENTITY_ID',
            sso_url='https://example.com/updated_login',
            x509_certificates=[X509_CERTIFICATES[1]],
            rp_entity_id='UPDATED_RP_ENTITY_ID',
            callback_url='https://updatedProjectId.firebaseapp.com/__/auth/handler',
            display_name='UPDATED_SAML_DISPLAY_NAME',
            enabled=False)
        assert provider_config.idp_entity_id == 'UPDATED_IDP_ENTITY_ID'
        assert provider_config.sso_url == 'https://example.com/updated_login'
        assert provider_config.x509_certificates == [X509_CERTIFICATES[1]]
        assert provider_config.rp_entity_id == 'UPDATED_RP_ENTITY_ID'
        assert provider_config.callback_url == ('https://updatedProjectId.firebaseapp.com/'
                                                '__/auth/handler')
        assert provider_config.display_name == 'UPDATED_SAML_DISPLAY_NAME'
        assert provider_config.enabled is False
    finally:
        auth.delete_saml_provider_config(provider_config.provider_id)


def test_delete_saml_provider_config():
    provider_config = _create_saml_provider_config()
    auth.delete_saml_provider_config(provider_config.provider_id)
    with pytest.raises(auth.ConfigurationNotFoundError):
        auth.get_saml_provider_config(provider_config.provider_id)


def _create_oidc_provider_config():
    provider_id = 'oidc.{0}'.format(_random_string())
    return auth.create_oidc_provider_config(
        provider_id=provider_id,
        client_id='OIDC_CLIENT_ID',
        issuer='https://oidc.com/issuer',
        display_name='OIDC_DISPLAY_NAME',
        enabled=True,
        id_token_response_type=True,
        code_response_type=False)


def _create_saml_provider_config():
    provider_id = 'saml.{0}'.format(_random_string())
    return auth.create_saml_provider_config(
        provider_id=provider_id,
        idp_entity_id='IDP_ENTITY_ID',
        sso_url='https://example.com/login',
        x509_certificates=[X509_CERTIFICATES[0]],
        rp_entity_id='RP_ENTITY_ID',
        callback_url='https://projectId.firebaseapp.com/__/auth/handler',
        display_name='SAML_DISPLAY_NAME',
        enabled=True)


class CredentialWrapper(credentials.Base):
    """A custom Firebase credential that wraps an OAuth2 token."""

    def __init__(self, token):
        self._delegate = google.oauth2.credentials.Credentials(token)

    def get_credential(self):
        return self._delegate

    @classmethod
    def from_existing_credential(cls, google_cred):
        if not google_cred.token:
            request = transport.requests.Request()
            google_cred.refresh(request)
        return CredentialWrapper(google_cred.token)
