# Copyright 2020 Google Inc.
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

"""Test cases for the firebase_admin.tenant_mgt module."""

import json
from urllib import parse

import pytest

import firebase_admin
from firebase_admin import auth
from firebase_admin import exceptions
from firebase_admin import tenant_mgt
from tests import testutils


GET_TENANT_RESPONSE = """{
    "name": "projects/mock-project-id/tenants/tenant-id",
    "displayName": "Test Tenant",
    "allowPasswordSignup": true,
    "enableEmailLinkSignin": true
}"""

TENANT_NOT_FOUND_RESPONSE = """{
    "error": {
        "message": "TENANT_NOT_FOUND"
    }
}"""

LIST_TENANTS_RESPONSE = """{
    "tenants": [
        {
            "name": "projects/mock-project-id/tenants/tenant0",
            "displayName": "Test Tenant",
            "allowPasswordSignup": true,
            "enableEmailLinkSignin": true
        },
        {
            "name": "projects/mock-project-id/tenants/tenant1",
            "displayName": "Test Tenant",
            "allowPasswordSignup": true,
            "enableEmailLinkSignin": true
        }
    ]
}"""

LIST_TENANTS_RESPONSE_WITH_TOKEN = """{
    "tenants": [
        {
            "name": "projects/mock-project-id/tenants/tenant0"
        },
        {
            "name": "projects/mock-project-id/tenants/tenant1"
        },
        {
            "name": "projects/mock-project-id/tenants/tenant2"
        }
    ],
    "nextPageToken": "token"
}"""

MOCK_GET_USER_RESPONSE = testutils.resource('get_user.json')

INVALID_TENANT_IDS = [None, '', 0, 1, True, False, list(), tuple(), dict()]
INVALID_BOOLEANS = ['', 1, 0, list(), tuple(), dict()]

USER_MGT_URL_PREFIX = 'https://identitytoolkit.googleapis.com/v1/projects/mock-project-id'
TENANT_MGT_URL_PREFIX = 'https://identitytoolkit.googleapis.com/v2beta1/projects/mock-project-id'


@pytest.fixture(scope='module')
def tenant_mgt_app():
    app = firebase_admin.initialize_app(
        testutils.MockCredential(), name='tenantMgt', options={'projectId': 'mock-project-id'})
    yield app
    firebase_admin.delete_app(app)


def _instrument_tenant_mgt(app, status, payload):
    service = tenant_mgt._get_tenant_mgt_service(app)
    recorder = []
    service.client.session.mount(
        tenant_mgt._TenantManagementService.TENANT_MGT_URL,
        testutils.MockAdapter(payload, status, recorder))
    return service, recorder


def _instrument_user_mgt(client, status, payload):
    recorder = []
    user_manager = client._user_manager
    user_manager._client.session.mount(
        auth._AuthService.ID_TOOLKIT_URL,
        testutils.MockAdapter(payload, status, recorder))
    return recorder


class TestTenant:

    @pytest.mark.parametrize('data', [None, 'foo', 0, 1, True, False, list(), tuple(), dict()])
    def test_invalid_data(self, data):
        with pytest.raises(ValueError):
            tenant_mgt.Tenant(data)

    def test_tenant(self):
        data = {
            'name': 'projects/test-project/tenants/tenant-id',
            'displayName': 'Test Tenant',
            'allowPasswordSignup': True,
            'enableEmailLinkSignin': True,
        }
        tenant = tenant_mgt.Tenant(data)
        assert tenant.tenant_id == 'tenant-id'
        assert tenant.display_name == 'Test Tenant'
        assert tenant.allow_password_sign_up is True
        assert tenant.enable_email_link_sign_in is True

    def test_tenant_optional_params(self):
        data = {
            'name': 'projects/test-project/tenants/tenant-id',
        }
        tenant = tenant_mgt.Tenant(data)
        assert tenant.tenant_id == 'tenant-id'
        assert tenant.display_name is None
        assert tenant.allow_password_sign_up is False
        assert tenant.enable_email_link_sign_in is False


class TestGetTenant:

    @pytest.mark.parametrize('tenant_id', INVALID_TENANT_IDS)
    def test_invalid_tenant_id(self, tenant_id):
        with pytest.raises(ValueError):
            tenant_mgt.get_tenant(tenant_id)

    def test_get_tenant(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.get_tenant('tenant-id', app=tenant_mgt_app)

        _assert_tenant(tenant)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/tenants/tenant-id'.format(TENANT_MGT_URL_PREFIX)

    def test_tenant_not_found(self, tenant_mgt_app):
        _instrument_tenant_mgt(tenant_mgt_app, 500, TENANT_NOT_FOUND_RESPONSE)
        with pytest.raises(tenant_mgt.TenantNotFoundError) as excinfo:
            tenant_mgt.get_tenant('tenant-id', app=tenant_mgt_app)

        error_msg = 'No tenant found for the given identifier (TENANT_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None


class TestCreateTenant:

    @pytest.mark.parametrize('display_name', [True, False, 1, 0, list(), tuple(), dict()])
    def test_invalid_display_name(self, display_name, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.create_tenant(display_name=display_name, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid type for displayName')

    @pytest.mark.parametrize('allow', INVALID_BOOLEANS)
    def test_invalid_allow_password_sign_up(self, allow, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.create_tenant(allow_password_sign_up=allow, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid type for allowPasswordSignup')

    @pytest.mark.parametrize('enable', INVALID_BOOLEANS)
    def test_invalid_enable_email_link_sign_in(self, enable, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.create_tenant(enable_email_link_sign_in=enable, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid type for enableEmailLinkSignin')

    def test_create_tenant(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.create_tenant(
            display_name='My Tenant', allow_password_sign_up=True, enable_email_link_sign_in=True,
            app=tenant_mgt_app)

        _assert_tenant(tenant)
        self._assert_request(recorder, {
            'displayName': 'My Tenant',
            'allowPasswordSignup': True,
            'enableEmailLinkSignin': True,
        })

    def test_create_tenant_false_values(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.create_tenant(
            display_name='', allow_password_sign_up=False, enable_email_link_sign_in=False,
            app=tenant_mgt_app)

        _assert_tenant(tenant)
        self._assert_request(recorder, {
            'displayName': '',
            'allowPasswordSignup': False,
            'enableEmailLinkSignin': False,
        })

    def test_create_tenant_minimal(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.create_tenant(app=tenant_mgt_app)

        _assert_tenant(tenant)
        self._assert_request(recorder, {})

    def test_error(self, tenant_mgt_app):
        _instrument_tenant_mgt(tenant_mgt_app, 500, '{}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            tenant_mgt.create_tenant(app=tenant_mgt_app)

        error_msg = 'Unexpected error response: {}'
        assert excinfo.value.code == exceptions.INTERNAL
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def _assert_request(self, recorder, body):
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'POST'
        assert req.url == '{0}/tenants'.format(TENANT_MGT_URL_PREFIX)
        got = json.loads(req.body.decode())
        assert got == body


class TestUpdateTenant:

    @pytest.mark.parametrize('tenant_id', INVALID_TENANT_IDS)
    def test_invalid_tenant_id(self, tenant_id, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.update_tenant(tenant_id, display_name='My Tenant', app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Tenant ID must be a non-empty string')

    @pytest.mark.parametrize('display_name', [True, False, 1, 0, list(), tuple(), dict()])
    def test_invalid_display_name(self, display_name, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.update_tenant('tenant-id', display_name=display_name, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid type for displayName')

    @pytest.mark.parametrize('allow', INVALID_BOOLEANS)
    def test_invalid_allow_password_sign_up(self, allow, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.update_tenant('tenant-id', allow_password_sign_up=allow, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid type for allowPasswordSignup')

    @pytest.mark.parametrize('enable', INVALID_BOOLEANS)
    def test_invalid_enable_email_link_sign_in(self, enable, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.update_tenant(
                'tenant-id', enable_email_link_sign_in=enable, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid type for enableEmailLinkSignin')

    def test_update_tenant(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.update_tenant(
            'tenant-id', display_name='My Tenant', allow_password_sign_up=True,
            enable_email_link_sign_in=True, app=tenant_mgt_app)

        _assert_tenant(tenant)
        body = {
            'displayName': 'My Tenant',
            'allowPasswordSignup': True,
            'enableEmailLinkSignin': True,
        }
        mask = ['allowPasswordSignup', 'displayName', 'enableEmailLinkSignin']
        self._assert_request(recorder, body, mask)

    def test_update_tenant_false_values(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.update_tenant(
            'tenant-id', display_name='', allow_password_sign_up=False,
            enable_email_link_sign_in=False, app=tenant_mgt_app)

        _assert_tenant(tenant)
        body = {
            'displayName': '',
            'allowPasswordSignup': False,
            'enableEmailLinkSignin': False,
        }
        mask = ['allowPasswordSignup', 'displayName', 'enableEmailLinkSignin']
        self._assert_request(recorder, body, mask)

    def test_update_tenant_minimal(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.update_tenant(
            'tenant-id', display_name='My Tenant', app=tenant_mgt_app)

        _assert_tenant(tenant)
        body = {'displayName': 'My Tenant'}
        mask = ['displayName']
        self._assert_request(recorder, body, mask)

    def test_tenant_not_found_error(self, tenant_mgt_app):
        _instrument_tenant_mgt(tenant_mgt_app, 500, TENANT_NOT_FOUND_RESPONSE)
        with pytest.raises(tenant_mgt.TenantNotFoundError) as excinfo:
            tenant_mgt.update_tenant('tenant', display_name='My Tenant', app=tenant_mgt_app)

        error_msg = 'No tenant found for the given identifier (TENANT_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def _assert_request(self, recorder, body, mask):
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'PATCH'
        assert req.url == '{0}/tenants/tenant-id?updateMask={1}'.format(
            TENANT_MGT_URL_PREFIX, ','.join(mask))
        got = json.loads(req.body.decode())
        assert got == body


class TestDeleteTenant:

    @pytest.mark.parametrize('tenant_id', INVALID_TENANT_IDS)
    def test_invalid_tenant_id(self, tenant_id):
        with pytest.raises(ValueError):
            tenant_mgt.delete_tenant(tenant_id)

    def test_delete_tenant(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, '{}')
        tenant_mgt.delete_tenant('tenant-id', app=tenant_mgt_app)

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'DELETE'
        assert req.url == '{0}/tenants/tenant-id'.format(TENANT_MGT_URL_PREFIX)

    def test_tenant_not_found(self, tenant_mgt_app):
        _instrument_tenant_mgt(tenant_mgt_app, 500, TENANT_NOT_FOUND_RESPONSE)
        with pytest.raises(tenant_mgt.TenantNotFoundError) as excinfo:
            tenant_mgt.delete_tenant('tenant-id', app=tenant_mgt_app)

        error_msg = 'No tenant found for the given identifier (TENANT_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None


class TestListTenants:

    @pytest.mark.parametrize('arg', [None, 'foo', list(), dict(), 0, -1, 101, False])
    def test_invalid_max_results(self, tenant_mgt_app, arg):
        with pytest.raises(ValueError):
            tenant_mgt.list_tenants(max_results=arg, app=tenant_mgt_app)

    @pytest.mark.parametrize('arg', ['', list(), dict(), 0, -1, True, False])
    def test_invalid_page_token(self, tenant_mgt_app, arg):
        with pytest.raises(ValueError):
            tenant_mgt.list_tenants(page_token=arg, app=tenant_mgt_app)

    def test_list_single_page(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, LIST_TENANTS_RESPONSE)
        page = tenant_mgt.list_tenants(app=tenant_mgt_app)
        self._assert_tenants_page(page)
        assert page.next_page_token == ''
        assert page.has_next_page is False
        assert page.get_next_page() is None
        tenants = [tenant for tenant in page.iterate_all()]
        assert len(tenants) == 2
        self._assert_request(recorder)

    def test_list_multiple_pages(self, tenant_mgt_app):
        # Page 1
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, LIST_TENANTS_RESPONSE_WITH_TOKEN)
        page = tenant_mgt.list_tenants(app=tenant_mgt_app)
        assert len(page.tenants) == 3
        assert page.next_page_token == 'token'
        assert page.has_next_page is True
        self._assert_request(recorder)

        # Page 2 (also the last page)
        response = {'tenants': [{'name': 'projects/mock-project-id/tenants/tenant3'}]}
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, json.dumps(response))
        page = page.get_next_page()
        assert len(page.tenants) == 1
        assert page.next_page_token == ''
        assert page.has_next_page is False
        assert page.get_next_page() is None
        self._assert_request(recorder, {'pageSize': '100', 'pageToken': 'token'})

    def test_list_tenants_paged_iteration(self, tenant_mgt_app):
        # Page 1
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, LIST_TENANTS_RESPONSE_WITH_TOKEN)
        page = tenant_mgt.list_tenants(app=tenant_mgt_app)
        iterator = page.iterate_all()
        for index in range(3):
            tenant = next(iterator)
            assert tenant.tenant_id == 'tenant{0}'.format(index)
        self._assert_request(recorder)

        # Page 2 (also the last page)
        response = {'tenants': [{'name': 'projects/mock-project-id/tenants/tenant3'}]}
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, json.dumps(response))
        tenant = next(iterator)
        assert tenant.tenant_id == 'tenant3'

        with pytest.raises(StopIteration):
            next(iterator)
        self._assert_request(recorder, {'pageSize': '100', 'pageToken': 'token'})

    def test_list_tenants_iterator_state(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, LIST_TENANTS_RESPONSE)
        page = tenant_mgt.list_tenants(app=tenant_mgt_app)

        # Advance iterator.
        iterator = page.iterate_all()
        tenant = next(iterator)
        assert tenant.tenant_id == 'tenant0'

        # Iterator should resume from where left off.
        tenant = next(iterator)
        assert tenant.tenant_id == 'tenant1'

        with pytest.raises(StopIteration):
            next(iterator)
        self._assert_request(recorder)

    def test_list_tenants_stop_iteration(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, LIST_TENANTS_RESPONSE)
        page = tenant_mgt.list_tenants(app=tenant_mgt_app)
        iterator = page.iterate_all()
        tenants = [tenant for tenant in iterator]
        assert len(tenants) == 2

        with pytest.raises(StopIteration):
            next(iterator)
        self._assert_request(recorder)

    def test_list_tenants_no_tenants_response(self, tenant_mgt_app):
        response = {'tenants': []}
        _instrument_tenant_mgt(tenant_mgt_app, 200, json.dumps(response))
        page = tenant_mgt.list_tenants(app=tenant_mgt_app)
        assert len(page.tenants) == 0
        tenants = [tenant for tenant in page.iterate_all()]
        assert len(tenants) == 0

    def test_list_tenants_with_max_results(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, LIST_TENANTS_RESPONSE)
        page = tenant_mgt.list_tenants(max_results=50, app=tenant_mgt_app)
        self._assert_tenants_page(page)
        self._assert_request(recorder, {'pageSize' : '50'})

    def test_list_tenants_with_all_args(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, LIST_TENANTS_RESPONSE)
        page = tenant_mgt.list_tenants(page_token='foo', max_results=50, app=tenant_mgt_app)
        self._assert_tenants_page(page)
        self._assert_request(recorder, {'pageToken' : 'foo', 'pageSize' : '50'})

    def test_list_tenants_error(self, tenant_mgt_app):
        _instrument_tenant_mgt(tenant_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            tenant_mgt.list_tenants(app=tenant_mgt_app)
        assert str(excinfo.value) == 'Unexpected error response: {"error":"test"}'

    def _assert_tenants_page(self, page):
        assert isinstance(page, tenant_mgt.ListTenantsPage)
        assert len(page.tenants) == 2
        for idx, tenant in enumerate(page.tenants):
            _assert_tenant(tenant, 'tenant{0}'.format(idx))

    def _assert_request(self, recorder, expected=None):
        if expected is None:
            expected = {'pageSize' : '100'}

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        request = dict(parse.parse_qsl(parse.urlsplit(req.url).query))
        assert request == expected


class TestAuthForTenant:

    @pytest.mark.parametrize('tenant_id', INVALID_TENANT_IDS)
    def test_invalid_tenant_id(self, tenant_id):
        with pytest.raises(ValueError):
            tenant_mgt.auth_for_tenant(tenant_id)

    def test_client(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant1', app=tenant_mgt_app)
        assert client.tenant_id == 'tenant1'

    def test_client_reuse(self, tenant_mgt_app):
        client1 = tenant_mgt.auth_for_tenant('tenant1', app=tenant_mgt_app)
        client2 = tenant_mgt.auth_for_tenant('tenant1', app=tenant_mgt_app)
        client3 = tenant_mgt.auth_for_tenant('tenant2', app=tenant_mgt_app)
        assert client1 is client2
        assert client1 is not client3


class TestTenantAwareUserManagement:

    def test_get_user(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, MOCK_GET_USER_RESPONSE)

        user = client.get_user('testuser')

        assert isinstance(user, auth.UserRecord)
        assert user.uid == 'testuser'
        assert user.email == 'testuser@example.com'
        self._assert_request(recorder, '/accounts:lookup', {'localId': ['testuser']})

    def test_get_user_by_email(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, MOCK_GET_USER_RESPONSE)

        user = client.get_user_by_email('testuser@example.com')

        assert isinstance(user, auth.UserRecord)
        assert user.uid == 'testuser'
        assert user.email == 'testuser@example.com'
        self._assert_request(recorder, '/accounts:lookup', {'email': ['testuser@example.com']})

    def test_get_user_by_phone_number(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, MOCK_GET_USER_RESPONSE)

        user = client.get_user_by_phone_number('+1234567890')

        assert isinstance(user, auth.UserRecord)
        assert user.uid == 'testuser'
        assert user.email == 'testuser@example.com'
        self._assert_request(recorder, '/accounts:lookup', {'phoneNumber': ['+1234567890']})

    def test_delete_user(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, '{"kind":"deleteresponse"}')

        client.delete_user('testuser')

        self._assert_request(recorder, '/accounts:delete', {'localId': 'testuser'})

    def test_set_custom_user_claims(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, '{"localId":"testuser"}')
        claims = {'admin': True}

        client.set_custom_user_claims('testuser', claims)

        self._assert_request(recorder, '/accounts:update', {
            'localId': 'testuser',
            'customAttributes': json.dumps(claims),
        })

    def test_revoke_refresh_tokens(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, '{"localId":"testuser"}')
        claims = {'admin': True}

        client.revoke_refresh_tokens('testuser')

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'POST'
        assert req.url == '{0}/tenants/tenant-id/accounts:update'.format(
            USER_MGT_URL_PREFIX)
        body = json.loads(req.body.decode())
        assert body['localId'] == 'testuser'
        assert 'validSince' in body

    def test_generate_password_reset_link(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, '{"oobLink":"https://testlink"}')

        link = client.generate_password_reset_link('test@test.com')

        assert link == 'https://testlink'
        self._assert_request(recorder, '/accounts:sendOobCode', {
            'email': 'test@test.com',
            'requestType': 'PASSWORD_RESET',
            'returnOobLink': True,
        })

    def test_generate_email_verification_link(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, '{"oobLink":"https://testlink"}')

        link = client.generate_email_verification_link('test@test.com')

        assert link == 'https://testlink'
        self._assert_request(recorder, '/accounts:sendOobCode', {
            'email': 'test@test.com',
            'requestType': 'VERIFY_EMAIL',
            'returnOobLink': True,
        })

    def test_generate_sign_in_with_email_link(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, '{"oobLink":"https://testlink"}')
        settings = auth.ActionCodeSettings(url='http://localhost')

        link = client.generate_sign_in_with_email_link('test@test.com', settings)

        assert link == 'https://testlink'
        self._assert_request(recorder, '/accounts:sendOobCode', {
            'email': 'test@test.com',
            'requestType': 'EMAIL_SIGNIN',
            'returnOobLink': True,
            'continueUrl': 'http://localhost',
        })

    def _assert_request(self, recorder, want_url, want_body):
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'POST'
        assert req.url == '{0}/tenants/tenant-id{1}'.format(USER_MGT_URL_PREFIX, want_url)
        body = json.loads(req.body.decode())
        assert body == want_body


def _assert_tenant(tenant, tenant_id='tenant-id'):
    assert isinstance(tenant, tenant_mgt.Tenant)
    assert tenant.tenant_id == tenant_id
    assert tenant.display_name == 'Test Tenant'
    assert tenant.allow_password_sign_up is True
    assert tenant.enable_email_link_sign_in is True
