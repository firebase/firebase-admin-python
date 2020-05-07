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

"""Integration tests for firebase_admin.tenant_mgt module."""

import random
import string
import time
from urllib import parse
import uuid

import requests
import pytest

from firebase_admin import auth
from firebase_admin import tenant_mgt
from integration import test_auth


ACTION_LINK_CONTINUE_URL = 'http://localhost?a=1&b=5#f=1'
ACTION_CODE_SETTINGS = auth.ActionCodeSettings(ACTION_LINK_CONTINUE_URL)
VERIFY_TOKEN_URL = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken'


@pytest.fixture(scope='module')
def sample_tenant():
    tenant = tenant_mgt.create_tenant(
        display_name='admin-python-tenant',
        allow_password_sign_up=True,
        enable_email_link_sign_in=True)
    yield tenant
    tenant_mgt.delete_tenant(tenant.tenant_id)


@pytest.fixture(scope='module')
def tenant_user(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    email = _random_email()
    user = client.create_user(email=email)
    yield user
    client.delete_user(user.uid)


def test_get_tenant(sample_tenant):
    tenant = tenant_mgt.get_tenant(sample_tenant.tenant_id)
    assert isinstance(tenant, tenant_mgt.Tenant)
    assert tenant.tenant_id == sample_tenant.tenant_id
    assert tenant.display_name == 'admin-python-tenant'
    assert tenant.allow_password_sign_up is True
    assert tenant.enable_email_link_sign_in is True


def test_list_tenants(sample_tenant):
    page = tenant_mgt.list_tenants()
    result = None
    for tenant in page.iterate_all():
        if tenant.tenant_id == sample_tenant.tenant_id:
            result = tenant
            break
    assert isinstance(result, tenant_mgt.Tenant)
    assert result.tenant_id == sample_tenant.tenant_id
    assert result.display_name == 'admin-python-tenant'
    assert result.allow_password_sign_up is True
    assert result.enable_email_link_sign_in is True


def test_update_tenant():
    tenant = tenant_mgt.create_tenant(
        display_name='py-update-test', allow_password_sign_up=True, enable_email_link_sign_in=True)
    try:
        tenant = tenant_mgt.update_tenant(
            tenant.tenant_id, display_name='updated-py-tenant', allow_password_sign_up=False,
            enable_email_link_sign_in=False)
        assert isinstance(tenant, tenant_mgt.Tenant)
        assert tenant.tenant_id == tenant.tenant_id
        assert tenant.display_name == 'updated-py-tenant'
        assert tenant.allow_password_sign_up is False
        assert tenant.enable_email_link_sign_in is False
    finally:
        tenant_mgt.delete_tenant(tenant.tenant_id)


def test_delete_tenant():
    tenant = tenant_mgt.create_tenant(display_name='py-delete-test')
    tenant_mgt.delete_tenant(tenant.tenant_id)
    with pytest.raises(tenant_mgt.TenantNotFoundError):
        tenant_mgt.get_tenant(tenant.tenant_id)


def test_auth_for_client(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    assert isinstance(client, auth.Client)
    assert client.tenant_id == sample_tenant.tenant_id


def test_custom_token(sample_tenant, api_key):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    custom_token = client.create_custom_token('user1')
    id_token = _sign_in(custom_token, sample_tenant.tenant_id, api_key)
    claims = client.verify_id_token(id_token)
    assert claims['uid'] == 'user1'
    assert claims['firebase']['tenant'] == sample_tenant.tenant_id


def test_custom_token_with_claims(sample_tenant, api_key):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    custom_token = client.create_custom_token('user1', {'premium': True})
    id_token = _sign_in(custom_token, sample_tenant.tenant_id, api_key)
    claims = client.verify_id_token(id_token)
    assert claims['uid'] == 'user1'
    assert claims['premium'] is True
    assert claims['firebase']['tenant'] == sample_tenant.tenant_id


def test_create_user(sample_tenant, tenant_user):
    assert tenant_user.tenant_id == sample_tenant.tenant_id


def test_update_user(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    user = client.create_user()
    try:
        email = _random_email()
        phone = _random_phone()
        user = client.update_user(user.uid, email=email, phone_number=phone)
        assert user.tenant_id == sample_tenant.tenant_id
        assert user.email == email
        assert user.phone_number == phone
    finally:
        client.delete_user(user.uid)


def test_get_user(sample_tenant, tenant_user):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    user = client.get_user(tenant_user.uid)
    assert user.uid == tenant_user.uid
    assert user.tenant_id == sample_tenant.tenant_id


def test_list_users(sample_tenant, tenant_user):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    page = client.list_users()
    result = None
    for user in page.iterate_all():
        if user.uid == tenant_user.uid:
            result = user
            break
    assert result.tenant_id == sample_tenant.tenant_id


def test_set_custom_user_claims(sample_tenant, tenant_user):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    client.set_custom_user_claims(tenant_user.uid, {'premium': True})
    user = client.get_user(tenant_user.uid)
    assert user.custom_claims == {'premium': True}


def test_delete_user(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    user = client.create_user()
    client.delete_user(user.uid)
    with pytest.raises(auth.UserNotFoundError):
        client.get_user(user.uid)


def test_revoke_refresh_tokens(sample_tenant, tenant_user):
    valid_since = int(time.time())
    time.sleep(1)
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    client.revoke_refresh_tokens(tenant_user.uid)
    user = client.get_user(tenant_user.uid)
    assert user.tokens_valid_after_timestamp > valid_since


def test_password_reset_link(sample_tenant, tenant_user):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    link = client.generate_password_reset_link(tenant_user.email, ACTION_CODE_SETTINGS)
    assert _tenant_id_from_link(link) == sample_tenant.tenant_id


def test_email_verification_link(sample_tenant, tenant_user):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    link = client.generate_email_verification_link(tenant_user.email, ACTION_CODE_SETTINGS)
    assert _tenant_id_from_link(link) == sample_tenant.tenant_id


def test_sign_in_with_email_link(sample_tenant, tenant_user):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    link = client.generate_sign_in_with_email_link(tenant_user.email, ACTION_CODE_SETTINGS)
    assert _tenant_id_from_link(link) == sample_tenant.tenant_id


def test_import_users(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    user = auth.ImportUserRecord(
        uid=_random_uid(), email=_random_email())
    result = client.import_users([user])
    try:
        assert result.success_count == 1
        assert result.failure_count == 0
        saved_user = client.get_user(user.uid)
        assert saved_user.email == user.email
    finally:
        client.delete_user(user.uid)


@pytest.fixture(scope='module')
def oidc_provider(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    provider_config = _create_oidc_provider_config(client)
    yield provider_config
    client.delete_oidc_provider_config(provider_config.provider_id)


def test_create_oidc_provider_config(oidc_provider):
    assert isinstance(oidc_provider, auth.OIDCProviderConfig)
    assert oidc_provider.client_id == 'OIDC_CLIENT_ID'
    assert oidc_provider.issuer == 'https://oidc.com/issuer'
    assert oidc_provider.display_name == 'OIDC_DISPLAY_NAME'
    assert oidc_provider.enabled is True


def test_get_oidc_provider_config(sample_tenant, oidc_provider):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    provider_config = client.get_oidc_provider_config(oidc_provider.provider_id)
    assert isinstance(provider_config, auth.OIDCProviderConfig)
    assert provider_config.provider_id == oidc_provider.provider_id
    assert provider_config.client_id == 'OIDC_CLIENT_ID'
    assert provider_config.issuer == 'https://oidc.com/issuer'
    assert provider_config.display_name == 'OIDC_DISPLAY_NAME'
    assert provider_config.enabled is True


def test_list_oidc_provider_configs(sample_tenant, oidc_provider):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    page = client.list_oidc_provider_configs()
    result = None
    for provider_config in page.iterate_all():
        if provider_config.provider_id == oidc_provider.provider_id:
            result = provider_config
            break

    assert result is not None


def test_update_oidc_provider_config(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    provider_config = _create_oidc_provider_config(client)
    try:
        provider_config = client.update_oidc_provider_config(
            provider_config.provider_id,
            client_id='UPDATED_OIDC_CLIENT_ID',
            issuer='https://oidc.com/updated_issuer',
            display_name='UPDATED_OIDC_DISPLAY_NAME',
            enabled=False)
        assert provider_config.client_id == 'UPDATED_OIDC_CLIENT_ID'
        assert provider_config.issuer == 'https://oidc.com/updated_issuer'
        assert provider_config.display_name == 'UPDATED_OIDC_DISPLAY_NAME'
        assert provider_config.enabled is False
    finally:
        client.delete_oidc_provider_config(provider_config.provider_id)


def test_delete_oidc_provider_config(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    provider_config = _create_oidc_provider_config(client)
    client.delete_oidc_provider_config(provider_config.provider_id)
    with pytest.raises(auth.ConfigurationNotFoundError):
        client.get_oidc_provider_config(provider_config.provider_id)


@pytest.fixture(scope='module')
def saml_provider(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    provider_config = _create_saml_provider_config(client)
    yield provider_config
    client.delete_saml_provider_config(provider_config.provider_id)


def test_create_saml_provider_config(saml_provider):
    assert isinstance(saml_provider, auth.SAMLProviderConfig)
    assert saml_provider.idp_entity_id == 'IDP_ENTITY_ID'
    assert saml_provider.sso_url == 'https://example.com/login'
    assert saml_provider.x509_certificates == [test_auth.X509_CERTIFICATES[0]]
    assert saml_provider.rp_entity_id == 'RP_ENTITY_ID'
    assert saml_provider.callback_url == 'https://projectId.firebaseapp.com/__/auth/handler'
    assert saml_provider.display_name == 'SAML_DISPLAY_NAME'
    assert saml_provider.enabled is True


def test_get_saml_provider_config(sample_tenant, saml_provider):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    provider_config = client.get_saml_provider_config(saml_provider.provider_id)
    assert isinstance(provider_config, auth.SAMLProviderConfig)
    assert provider_config.provider_id == saml_provider.provider_id
    assert provider_config.idp_entity_id == 'IDP_ENTITY_ID'
    assert provider_config.sso_url == 'https://example.com/login'
    assert provider_config.x509_certificates == [test_auth.X509_CERTIFICATES[0]]
    assert provider_config.rp_entity_id == 'RP_ENTITY_ID'
    assert provider_config.callback_url == 'https://projectId.firebaseapp.com/__/auth/handler'
    assert provider_config.display_name == 'SAML_DISPLAY_NAME'
    assert provider_config.enabled is True


def test_list_saml_provider_configs(sample_tenant, saml_provider):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    page = client.list_saml_provider_configs()
    result = None
    for provider_config in page.iterate_all():
        if provider_config.provider_id == saml_provider.provider_id:
            result = provider_config
            break

    assert result is not None


def test_update_saml_provider_config(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    provider_config = _create_saml_provider_config(client)
    try:
        provider_config = client.update_saml_provider_config(
            provider_config.provider_id,
            idp_entity_id='UPDATED_IDP_ENTITY_ID',
            sso_url='https://example.com/updated_login',
            x509_certificates=[test_auth.X509_CERTIFICATES[1]],
            rp_entity_id='UPDATED_RP_ENTITY_ID',
            callback_url='https://updatedProjectId.firebaseapp.com/__/auth/handler',
            display_name='UPDATED_SAML_DISPLAY_NAME',
            enabled=False)
        assert provider_config.idp_entity_id == 'UPDATED_IDP_ENTITY_ID'
        assert provider_config.sso_url == 'https://example.com/updated_login'
        assert provider_config.x509_certificates == [test_auth.X509_CERTIFICATES[1]]
        assert provider_config.rp_entity_id == 'UPDATED_RP_ENTITY_ID'
        assert provider_config.callback_url == ('https://updatedProjectId.firebaseapp.com/'
                                                '__/auth/handler')
        assert provider_config.display_name == 'UPDATED_SAML_DISPLAY_NAME'
        assert provider_config.enabled is False
    finally:
        client.delete_saml_provider_config(provider_config.provider_id)


def test_delete_saml_provider_config(sample_tenant):
    client = tenant_mgt.auth_for_tenant(sample_tenant.tenant_id)
    provider_config = _create_saml_provider_config(client)
    client.delete_saml_provider_config(provider_config.provider_id)
    with pytest.raises(auth.ConfigurationNotFoundError):
        client.get_saml_provider_config(provider_config.provider_id)


def _create_oidc_provider_config(client):
    provider_id = 'oidc.{0}'.format(_random_string())
    return client.create_oidc_provider_config(
        provider_id=provider_id,
        client_id='OIDC_CLIENT_ID',
        issuer='https://oidc.com/issuer',
        display_name='OIDC_DISPLAY_NAME',
        enabled=True)


def _create_saml_provider_config(client):
    provider_id = 'saml.{0}'.format(_random_string())
    return client.create_saml_provider_config(
        provider_id=provider_id,
        idp_entity_id='IDP_ENTITY_ID',
        sso_url='https://example.com/login',
        x509_certificates=[test_auth.X509_CERTIFICATES[0]],
        rp_entity_id='RP_ENTITY_ID',
        callback_url='https://projectId.firebaseapp.com/__/auth/handler',
        display_name='SAML_DISPLAY_NAME',
        enabled=True)


def _random_uid():
    return str(uuid.uuid4()).lower().replace('-', '')


def _random_email():
    random_id = str(uuid.uuid4()).lower().replace('-', '')
    return 'test{0}@example.{1}.com'.format(random_id[:12], random_id[12:])


def _random_phone():
    return '+1' + ''.join([str(random.randint(0, 9)) for _ in range(0, 10)])


def _random_string(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def _tenant_id_from_link(link):
    query = parse.urlparse(link).query
    parsed_query = parse.parse_qs(query)
    return parsed_query['tenantId'][0]


def _sign_in(custom_token, tenant_id, api_key):
    body = {
        'token' : custom_token.decode(),
        'returnSecureToken' : True,
        'tenantId': tenant_id,
    }
    params = {'key' : api_key}
    resp = requests.request('post', VERIFY_TOKEN_URL, params=params, json=body)
    resp.raise_for_status()
    return resp.json().get('idToken')
