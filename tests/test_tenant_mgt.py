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
from firebase_admin import credentials
from firebase_admin import exceptions
from firebase_admin import tenant_mgt
from firebase_admin import _auth_providers
from firebase_admin import _user_mgt
from tests import testutils
from tests import test_token_gen


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
MOCK_LIST_USERS_RESPONSE = testutils.resource('list_users.json')

OIDC_PROVIDER_CONFIG_RESPONSE = testutils.resource('oidc_provider_config.json')
OIDC_PROVIDER_CONFIG_REQUEST = {
    'displayName': 'oidcProviderName',
    'enabled': True,
    'clientId': 'CLIENT_ID',
    'issuer': 'https://oidc.com/issuer',
}

SAML_PROVIDER_CONFIG_RESPONSE = testutils.resource('saml_provider_config.json')
SAML_PROVIDER_CONFIG_REQUEST = body = {
    'displayName': 'samlProviderName',
    'enabled': True,
    'idpConfig': {
        'idpEntityId': 'IDP_ENTITY_ID',
        'ssoUrl': 'https://example.com/login',
        'idpCertificates': [{'x509Certificate': 'CERT1'}, {'x509Certificate': 'CERT2'}]
    },
    'spConfig': {
        'spEntityId': 'RP_ENTITY_ID',
        'callbackUri': 'https://projectId.firebaseapp.com/__/auth/handler',
    }
}

LIST_OIDC_PROVIDER_CONFIGS_RESPONSE = testutils.resource('list_oidc_provider_configs.json')
LIST_SAML_PROVIDER_CONFIGS_RESPONSE = testutils.resource('list_saml_provider_configs.json')

INVALID_TENANT_IDS = [None, '', 0, 1, True, False, list(), tuple(), dict()]
INVALID_BOOLEANS = ['', 1, 0, list(), tuple(), dict()]

USER_MGT_URL_PREFIX = 'https://identitytoolkit.googleapis.com/v1/projects/mock-project-id'
PROVIDER_MGT_URL_PREFIX = 'https://identitytoolkit.googleapis.com/v2/projects/mock-project-id'
TENANT_MGT_URL_PREFIX = 'https://identitytoolkit.googleapis.com/v2/projects/mock-project-id'


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
    user_manager.http_client.session.mount(
        _user_mgt.UserManager.ID_TOOLKIT_URL,
        testutils.MockAdapter(payload, status, recorder))
    return recorder


def _instrument_provider_mgt(client, status, payload):
    recorder = []
    provider_manager = client._provider_manager
    provider_manager.http_client.session.mount(
        _auth_providers.ProviderConfigClient.PROVIDER_CONFIG_URL,
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
    def test_invalid_tenant_id(self, tenant_id, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.get_tenant(tenant_id, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid tenant ID')

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
    def test_invalid_display_name_type(self, display_name, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.create_tenant(display_name=display_name, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid type for displayName')

    @pytest.mark.parametrize('display_name', ['', 'foo', '1test', 'foo bar', 'a'*21])
    def test_invalid_display_name_value(self, display_name, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.create_tenant(display_name=display_name, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('displayName must start')

    @pytest.mark.parametrize('allow', INVALID_BOOLEANS)
    def test_invalid_allow_password_sign_up(self, allow, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.create_tenant(
                display_name='test', allow_password_sign_up=allow, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid type for allowPasswordSignup')

    @pytest.mark.parametrize('enable', INVALID_BOOLEANS)
    def test_invalid_enable_email_link_sign_in(self, enable, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.create_tenant(
                display_name='test', enable_email_link_sign_in=enable, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid type for enableEmailLinkSignin')

    def test_create_tenant(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.create_tenant(
            display_name='My-Tenant', allow_password_sign_up=True, enable_email_link_sign_in=True,
            app=tenant_mgt_app)

        _assert_tenant(tenant)
        self._assert_request(recorder, {
            'displayName': 'My-Tenant',
            'allowPasswordSignup': True,
            'enableEmailLinkSignin': True,
        })

    def test_create_tenant_false_values(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.create_tenant(
            display_name='test', allow_password_sign_up=False, enable_email_link_sign_in=False,
            app=tenant_mgt_app)

        _assert_tenant(tenant)
        self._assert_request(recorder, {
            'displayName': 'test',
            'allowPasswordSignup': False,
            'enableEmailLinkSignin': False,
        })

    def test_create_tenant_minimal(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.create_tenant(display_name='test', app=tenant_mgt_app)

        _assert_tenant(tenant)
        self._assert_request(recorder, {'displayName': 'test'})

    def test_error(self, tenant_mgt_app):
        _instrument_tenant_mgt(tenant_mgt_app, 500, '{}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            tenant_mgt.create_tenant(display_name='test', app=tenant_mgt_app)

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
    def test_invalid_display_name_type(self, display_name, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.update_tenant('tenant-id', display_name=display_name, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid type for displayName')

    @pytest.mark.parametrize('display_name', ['', 'foo', '1test', 'foo bar', 'a'*21])
    def test_invalid_display_name_value(self, display_name, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.update_tenant('tenant-id', display_name=display_name, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('displayName must start')

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

    def test_update_tenant_no_args(self, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.update_tenant('tenant-id', app=tenant_mgt_app)
        assert str(excinfo.value).startswith('At least one parameter must be specified for update')

    def test_update_tenant(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.update_tenant(
            'tenant-id', display_name='My-Tenant', allow_password_sign_up=True,
            enable_email_link_sign_in=True, app=tenant_mgt_app)

        _assert_tenant(tenant)
        body = {
            'displayName': 'My-Tenant',
            'allowPasswordSignup': True,
            'enableEmailLinkSignin': True,
        }
        mask = ['allowPasswordSignup', 'displayName', 'enableEmailLinkSignin']
        self._assert_request(recorder, body, mask)

    def test_update_tenant_false_values(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.update_tenant(
            'tenant-id', allow_password_sign_up=False,
            enable_email_link_sign_in=False, app=tenant_mgt_app)

        _assert_tenant(tenant)
        body = {
            'allowPasswordSignup': False,
            'enableEmailLinkSignin': False,
        }
        mask = ['allowPasswordSignup', 'enableEmailLinkSignin']
        self._assert_request(recorder, body, mask)

    def test_update_tenant_minimal(self, tenant_mgt_app):
        _, recorder = _instrument_tenant_mgt(tenant_mgt_app, 200, GET_TENANT_RESPONSE)
        tenant = tenant_mgt.update_tenant(
            'tenant-id', display_name='My-Tenant', app=tenant_mgt_app)

        _assert_tenant(tenant)
        body = {'displayName': 'My-Tenant'}
        mask = ['displayName']
        self._assert_request(recorder, body, mask)

    def test_tenant_not_found_error(self, tenant_mgt_app):
        _instrument_tenant_mgt(tenant_mgt_app, 500, TENANT_NOT_FOUND_RESPONSE)
        with pytest.raises(tenant_mgt.TenantNotFoundError) as excinfo:
            tenant_mgt.update_tenant('tenant', display_name='My-Tenant', app=tenant_mgt_app)

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
    def test_invalid_tenant_id(self, tenant_id, tenant_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            tenant_mgt.delete_tenant(tenant_id, app=tenant_mgt_app)
        assert str(excinfo.value).startswith('Invalid tenant ID')

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
    def test_invalid_tenant_id(self, tenant_id, tenant_mgt_app):
        with pytest.raises(ValueError):
            tenant_mgt.auth_for_tenant(tenant_id, app=tenant_mgt_app)

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

    def test_create_user(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, '{"localId":"testuser"}')

        uid = client._user_manager.create_user()

        assert uid == 'testuser'
        self._assert_request(recorder, '/accounts', {})

    def test_update_user(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, '{"localId":"testuser"}')

        uid = client._user_manager.update_user('testuser', email='testuser@example.com')

        assert uid == 'testuser'
        self._assert_request(recorder, '/accounts:update', {
            'localId': 'testuser',
            'email': 'testuser@example.com',
        })

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

        client.revoke_refresh_tokens('testuser')

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'POST'
        assert req.url == '{0}/tenants/tenant-id/accounts:update'.format(
            USER_MGT_URL_PREFIX)
        body = json.loads(req.body.decode())
        assert body['localId'] == 'testuser'
        assert 'validSince' in body

    def test_list_users(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, MOCK_LIST_USERS_RESPONSE)

        page = client.list_users()

        assert isinstance(page, auth.ListUsersPage)
        assert page.next_page_token == ''
        assert page.has_next_page is False
        assert page.get_next_page() is None
        users = list(user for user in page.iterate_all())
        assert len(users) == 2

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/tenants/tenant-id/accounts:batchGet?maxResults=1000'.format(
            USER_MGT_URL_PREFIX)

    def test_import_users(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_user_mgt(client, 200, '{}')
        users = [
            auth.ImportUserRecord(uid='user1'),
            auth.ImportUserRecord(uid='user2'),
        ]

        result = client.import_users(users)

        assert isinstance(result, auth.UserImportResult)
        assert result.success_count == 2
        assert result.failure_count == 0
        assert result.errors == []
        self._assert_request(recorder, '/accounts:batchCreate', {
            'users': [{'localId': 'user1'}, {'localId': 'user2'}],
        })

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

    def test_get_oidc_provider_config(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_provider_mgt(client, 200, OIDC_PROVIDER_CONFIG_RESPONSE)

        provider_config = client.get_oidc_provider_config('oidc.provider')

        self._assert_oidc_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/tenants/tenant-id/oauthIdpConfigs/oidc.provider'.format(
            PROVIDER_MGT_URL_PREFIX)

    def test_create_oidc_provider_config(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_provider_mgt(client, 200, OIDC_PROVIDER_CONFIG_RESPONSE)

        provider_config = client.create_oidc_provider_config(
            'oidc.provider', client_id='CLIENT_ID', issuer='https://oidc.com/issuer',
            display_name='oidcProviderName', enabled=True)

        self._assert_oidc_provider_config(provider_config)
        self._assert_request(
            recorder, '/oauthIdpConfigs?oauthIdpConfigId=oidc.provider',
            OIDC_PROVIDER_CONFIG_REQUEST, prefix=PROVIDER_MGT_URL_PREFIX)

    def test_update_oidc_provider_config(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_provider_mgt(client, 200, OIDC_PROVIDER_CONFIG_RESPONSE)

        provider_config = client.update_oidc_provider_config(
            'oidc.provider', client_id='CLIENT_ID', issuer='https://oidc.com/issuer',
            display_name='oidcProviderName', enabled=True)

        self._assert_oidc_provider_config(provider_config)
        mask = ['clientId', 'displayName', 'enabled', 'issuer']
        url = '/oauthIdpConfigs/oidc.provider?updateMask={0}'.format(','.join(mask))
        self._assert_request(
            recorder, url, OIDC_PROVIDER_CONFIG_REQUEST, method='PATCH',
            prefix=PROVIDER_MGT_URL_PREFIX)

    def test_delete_oidc_provider_config(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_provider_mgt(client, 200, '{}')

        client.delete_oidc_provider_config('oidc.provider')

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'DELETE'
        assert req.url == '{0}/tenants/tenant-id/oauthIdpConfigs/oidc.provider'.format(
            PROVIDER_MGT_URL_PREFIX)

    def test_list_oidc_provider_configs(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_provider_mgt(client, 200, LIST_OIDC_PROVIDER_CONFIGS_RESPONSE)

        page = client.list_oidc_provider_configs()

        assert isinstance(page, auth.ListProviderConfigsPage)
        index = 0
        assert len(page.provider_configs) == 2
        for provider_config in page.provider_configs:
            self._assert_oidc_provider_config(
                provider_config, want_id='oidc.provider{0}'.format(index))
            index += 1

        assert page.next_page_token == ''
        assert page.has_next_page is False
        assert page.get_next_page() is None
        provider_configs = list(config for config in page.iterate_all())
        assert len(provider_configs) == 2

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}{1}'.format(
            PROVIDER_MGT_URL_PREFIX, '/tenants/tenant-id/oauthIdpConfigs?pageSize=100')

    def test_get_saml_provider_config(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_provider_mgt(client, 200, SAML_PROVIDER_CONFIG_RESPONSE)

        provider_config = client.get_saml_provider_config('saml.provider')

        self._assert_saml_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/tenants/tenant-id/inboundSamlConfigs/saml.provider'.format(
            PROVIDER_MGT_URL_PREFIX)

    def test_create_saml_provider_config(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_provider_mgt(client, 200, SAML_PROVIDER_CONFIG_RESPONSE)

        provider_config = client.create_saml_provider_config(
            'saml.provider', idp_entity_id='IDP_ENTITY_ID', sso_url='https://example.com/login',
            x509_certificates=['CERT1', 'CERT2'], rp_entity_id='RP_ENTITY_ID',
            callback_url='https://projectId.firebaseapp.com/__/auth/handler',
            display_name='samlProviderName', enabled=True)

        self._assert_saml_provider_config(provider_config)
        self._assert_request(
            recorder, '/inboundSamlConfigs?inboundSamlConfigId=saml.provider',
            SAML_PROVIDER_CONFIG_REQUEST, prefix=PROVIDER_MGT_URL_PREFIX)

    def test_update_saml_provider_config(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_provider_mgt(client, 200, SAML_PROVIDER_CONFIG_RESPONSE)

        provider_config = client.update_saml_provider_config(
            'saml.provider', idp_entity_id='IDP_ENTITY_ID', sso_url='https://example.com/login',
            x509_certificates=['CERT1', 'CERT2'], rp_entity_id='RP_ENTITY_ID',
            callback_url='https://projectId.firebaseapp.com/__/auth/handler',
            display_name='samlProviderName', enabled=True)

        self._assert_saml_provider_config(provider_config)
        mask = [
            'displayName', 'enabled', 'idpConfig.idpCertificates', 'idpConfig.idpEntityId',
            'idpConfig.ssoUrl', 'spConfig.callbackUri', 'spConfig.spEntityId',
        ]
        url = '/inboundSamlConfigs/saml.provider?updateMask={0}'.format(','.join(mask))
        self._assert_request(
            recorder, url, SAML_PROVIDER_CONFIG_REQUEST, method='PATCH',
            prefix=PROVIDER_MGT_URL_PREFIX)

    def test_delete_saml_provider_config(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_provider_mgt(client, 200, '{}')

        client.delete_saml_provider_config('saml.provider')

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'DELETE'
        assert req.url == '{0}/tenants/tenant-id/inboundSamlConfigs/saml.provider'.format(
            PROVIDER_MGT_URL_PREFIX)

    def test_list_saml_provider_configs(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        recorder = _instrument_provider_mgt(client, 200, LIST_SAML_PROVIDER_CONFIGS_RESPONSE)

        page = client.list_saml_provider_configs()

        assert isinstance(page, auth.ListProviderConfigsPage)
        index = 0
        assert len(page.provider_configs) == 2
        for provider_config in page.provider_configs:
            self._assert_saml_provider_config(
                provider_config, want_id='saml.provider{0}'.format(index))
            index += 1

        assert page.next_page_token == ''
        assert page.has_next_page is False
        assert page.get_next_page() is None
        provider_configs = list(config for config in page.iterate_all())
        assert len(provider_configs) == 2

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}{1}'.format(
            PROVIDER_MGT_URL_PREFIX, '/tenants/tenant-id/inboundSamlConfigs?pageSize=100')

    def test_tenant_not_found(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('tenant-id', app=tenant_mgt_app)
        _instrument_user_mgt(client, 500, TENANT_NOT_FOUND_RESPONSE)
        with pytest.raises(tenant_mgt.TenantNotFoundError) as excinfo:
            client.get_user('testuser')

        error_msg = 'No tenant found for the given identifier (TENANT_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def _assert_request(
            self, recorder, want_url, want_body, method='POST', prefix=USER_MGT_URL_PREFIX):
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == method
        assert req.url == '{0}/tenants/tenant-id{1}'.format(prefix, want_url)
        body = json.loads(req.body.decode())
        assert body == want_body

    def _assert_oidc_provider_config(self, provider_config, want_id='oidc.provider'):
        assert isinstance(provider_config, auth.OIDCProviderConfig)
        assert provider_config.provider_id == want_id
        assert provider_config.display_name == 'oidcProviderName'
        assert provider_config.enabled is True
        assert provider_config.client_id == 'CLIENT_ID'
        assert provider_config.issuer == 'https://oidc.com/issuer'

    def _assert_saml_provider_config(self, provider_config, want_id='saml.provider'):
        assert isinstance(provider_config, auth.SAMLProviderConfig)
        assert provider_config.provider_id == want_id
        assert provider_config.display_name == 'samlProviderName'
        assert provider_config.enabled is True
        assert provider_config.idp_entity_id == 'IDP_ENTITY_ID'
        assert provider_config.sso_url == 'https://example.com/login'
        assert provider_config.x509_certificates == ['CERT1', 'CERT2']
        assert provider_config.rp_entity_id == 'RP_ENTITY_ID'
        assert provider_config.callback_url == 'https://projectId.firebaseapp.com/__/auth/handler'


class TestVerifyIdToken:

    def test_valid_token(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('test-tenant', app=tenant_mgt_app)
        client._token_verifier.request = test_token_gen.MOCK_REQUEST

        claims = client.verify_id_token(test_token_gen.TEST_ID_TOKEN_WITH_TENANT)

        assert claims['admin'] is True
        assert claims['uid'] == claims['sub']
        assert claims['firebase']['tenant'] == 'test-tenant'

    def test_invalid_tenant_id(self, tenant_mgt_app):
        client = tenant_mgt.auth_for_tenant('other-tenant', app=tenant_mgt_app)
        client._token_verifier.request = test_token_gen.MOCK_REQUEST

        with pytest.raises(tenant_mgt.TenantIdMismatchError) as excinfo:
            client.verify_id_token(test_token_gen.TEST_ID_TOKEN_WITH_TENANT)

        assert 'Invalid tenant ID: test-tenant' in str(excinfo.value)
        assert isinstance(excinfo.value, exceptions.InvalidArgumentError)
        assert excinfo.value.cause is None
        assert excinfo.value.http_response is None


@pytest.fixture(scope='module')
def tenant_aware_custom_token_app():
    cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
    app = firebase_admin.initialize_app(cred, name='tenantAwareCustomToken')
    yield app
    firebase_admin.delete_app(app)


class TestCreateCustomToken:

    def test_custom_token(self, tenant_aware_custom_token_app):
        client = tenant_mgt.auth_for_tenant('test-tenant', app=tenant_aware_custom_token_app)

        custom_token = client.create_custom_token('user1')

        test_token_gen.verify_custom_token(
            custom_token, expected_claims=None, tenant_id='test-tenant')

    def test_custom_token_with_claims(self, tenant_aware_custom_token_app):
        client = tenant_mgt.auth_for_tenant('test-tenant', app=tenant_aware_custom_token_app)
        claims = {'admin': True}

        custom_token = client.create_custom_token('user1', claims)

        test_token_gen.verify_custom_token(
            custom_token, expected_claims=claims, tenant_id='test-tenant')


def _assert_tenant(tenant, tenant_id='tenant-id'):
    assert isinstance(tenant, tenant_mgt.Tenant)
    assert tenant.tenant_id == tenant_id
    assert tenant.display_name == 'Test Tenant'
    assert tenant.allow_password_sign_up is True
    assert tenant.enable_email_link_sign_in is True
