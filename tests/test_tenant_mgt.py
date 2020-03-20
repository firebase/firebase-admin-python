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

import pytest

import firebase_admin
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

INVALID_TENANT_IDS = [None, '', 0, 1, True, False, list(), tuple(), dict()]
INVALID_BOOLEANS = ['', 1, 0, list(), tuple(), dict()]

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
            tenant_mgt.delete_tenant(tenant_id)

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


def _assert_tenant(tenant):
    assert tenant.tenant_id == 'tenant-id'
    assert tenant.display_name == 'Test Tenant'
    assert tenant.allow_password_sign_up is True
    assert tenant.enable_email_link_sign_in is True
