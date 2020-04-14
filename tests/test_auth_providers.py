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

"""Test cases for the firebase_admin._auth_providers module."""

import json

import pytest

import firebase_admin
from firebase_admin import auth
from firebase_admin import exceptions
from firebase_admin import _auth_providers
from tests import testutils

USER_MGT_URL_PREFIX = 'https://identitytoolkit.googleapis.com/v2beta1/projects/mock-project-id'
OIDC_PROVIDER_CONFIG_RESPONSE = testutils.resource('oidc_provider_config.json')
SAML_PROVIDER_CONFIG_RESPONSE = testutils.resource('saml_provider_config.json')
LIST_OIDC_PROVIDER_CONFIGS_RESPONSE = testutils.resource('list_oidc_provider_configs.json')
LIST_SAML_PROVIDER_CONFIGS_RESPONSE = testutils.resource('list_saml_provider_configs.json')

CONFIG_NOT_FOUND_RESPONSE = """{
    "error": {
        "message": "CONFIGURATION_NOT_FOUND"
    }
}"""

INVALID_PROVIDER_IDS = [None, True, False, 1, 0, list(), tuple(), dict(), '']


@pytest.fixture(scope='module')
def user_mgt_app():
    app = firebase_admin.initialize_app(testutils.MockCredential(), name='providerConfig',
                                        options={'projectId': 'mock-project-id'})
    yield app
    firebase_admin.delete_app(app)


def _instrument_provider_mgt(app, status, payload):
    client = auth._get_client(app)
    provider_manager = client._provider_manager
    recorder = []
    provider_manager.http_client.session.mount(
        _auth_providers.ProviderConfigClient.PROVIDER_CONFIG_URL,
        testutils.MockAdapter(payload, status, recorder))
    return recorder


class TestOIDCProviderConfig:

    VALID_CREATE_OPTIONS = {
        'provider_id': 'oidc.provider',
        'client_id': 'CLIENT_ID',
        'issuer': 'https://oidc.com/issuer',
        'display_name': 'oidcProviderName',
        'enabled': True,
    }

    OIDC_CONFIG_REQUEST = {
        'displayName': 'oidcProviderName',
        'enabled': True,
        'clientId': 'CLIENT_ID',
        'issuer': 'https://oidc.com/issuer',
    }

    @pytest.mark.parametrize('provider_id', INVALID_PROVIDER_IDS + ['saml.provider'])
    def test_get_invalid_provider_id(self, user_mgt_app, provider_id):
        with pytest.raises(ValueError) as excinfo:
            auth.get_oidc_provider_config(provider_id, app=user_mgt_app)

        assert str(excinfo.value).startswith('Invalid OIDC provider ID')

    def test_get(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, OIDC_PROVIDER_CONFIG_RESPONSE)

        provider_config = auth.get_oidc_provider_config('oidc.provider', app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}{1}'.format(USER_MGT_URL_PREFIX, '/oauthIdpConfigs/oidc.provider')

    @pytest.mark.parametrize('invalid_opts', [
        {'provider_id': None}, {'provider_id': ''}, {'provider_id': 'saml.provider'},
        {'client_id': None}, {'client_id': ''},
        {'issuer': None}, {'issuer': ''}, {'issuer': 'not a url'},
        {'display_name': True},
        {'enabled': 'true'},
    ])
    def test_create_invalid_args(self, user_mgt_app, invalid_opts):
        options = dict(self.VALID_CREATE_OPTIONS)
        options.update(invalid_opts)
        with pytest.raises(ValueError):
            auth.create_oidc_provider_config(**options, app=user_mgt_app)

    def test_create(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, OIDC_PROVIDER_CONFIG_RESPONSE)

        provider_config = auth.create_oidc_provider_config(
            **self.VALID_CREATE_OPTIONS, app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'POST'
        assert req.url == '{0}/oauthIdpConfigs?oauthIdpConfigId=oidc.provider'.format(
            USER_MGT_URL_PREFIX)
        got = json.loads(req.body.decode())
        assert got == self.OIDC_CONFIG_REQUEST

    def test_create_minimal(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, OIDC_PROVIDER_CONFIG_RESPONSE)
        options = dict(self.VALID_CREATE_OPTIONS)
        del options['display_name']
        del options['enabled']
        want = dict(self.OIDC_CONFIG_REQUEST)
        del want['displayName']
        del want['enabled']

        provider_config = auth.create_oidc_provider_config(**options, app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'POST'
        assert req.url == '{0}/oauthIdpConfigs?oauthIdpConfigId=oidc.provider'.format(
            USER_MGT_URL_PREFIX)
        got = json.loads(req.body.decode())
        assert got == want

    def test_create_empty_values(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, OIDC_PROVIDER_CONFIG_RESPONSE)
        options = dict(self.VALID_CREATE_OPTIONS)
        options['display_name'] = ''
        options['enabled'] = False
        want = dict(self.OIDC_CONFIG_REQUEST)
        want['displayName'] = ''
        want['enabled'] = False

        provider_config = auth.create_oidc_provider_config(**options, app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'POST'
        assert req.url == '{0}/oauthIdpConfigs?oauthIdpConfigId=oidc.provider'.format(
            USER_MGT_URL_PREFIX)
        got = json.loads(req.body.decode())
        assert got == want

    @pytest.mark.parametrize('invalid_opts', [
        {},
        {'provider_id': None}, {'provider_id': ''}, {'provider_id': 'saml.provider'},
        {'client_id': ''},
        {'issuer': ''}, {'issuer': 'not a url'},
        {'display_name': True},
        {'enabled': 'true'},
    ])
    def test_update_invalid_args(self, user_mgt_app, invalid_opts):
        options = {'provider_id': 'oidc.provider'}
        options.update(invalid_opts)
        with pytest.raises(ValueError):
            auth.update_oidc_provider_config(**options, app=user_mgt_app)

    def test_update(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, OIDC_PROVIDER_CONFIG_RESPONSE)

        provider_config = auth.update_oidc_provider_config(
            **self.VALID_CREATE_OPTIONS, app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'PATCH'
        mask = ['clientId', 'displayName', 'enabled', 'issuer']
        assert req.url == '{0}/oauthIdpConfigs/oidc.provider?updateMask={1}'.format(
            USER_MGT_URL_PREFIX, ','.join(mask))
        got = json.loads(req.body.decode())
        assert got == self.OIDC_CONFIG_REQUEST

    def test_update_minimal(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, OIDC_PROVIDER_CONFIG_RESPONSE)

        provider_config = auth.update_oidc_provider_config(
            'oidc.provider', display_name='oidcProviderName', app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'PATCH'
        assert req.url == '{0}/oauthIdpConfigs/oidc.provider?updateMask=displayName'.format(
            USER_MGT_URL_PREFIX)
        got = json.loads(req.body.decode())
        assert got == {'displayName': 'oidcProviderName'}

    def test_update_empty_values(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, OIDC_PROVIDER_CONFIG_RESPONSE)

        provider_config = auth.update_oidc_provider_config(
            'oidc.provider', display_name=auth.DELETE_ATTRIBUTE, enabled=False, app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'PATCH'
        mask = ['displayName', 'enabled']
        assert req.url == '{0}/oauthIdpConfigs/oidc.provider?updateMask={1}'.format(
            USER_MGT_URL_PREFIX, ','.join(mask))
        got = json.loads(req.body.decode())
        assert got == {'displayName': None, 'enabled': False}

    @pytest.mark.parametrize('provider_id', INVALID_PROVIDER_IDS + ['saml.provider'])
    def test_delete_invalid_provider_id(self, user_mgt_app, provider_id):
        with pytest.raises(ValueError) as excinfo:
            auth.delete_oidc_provider_config(provider_id, app=user_mgt_app)

        assert str(excinfo.value).startswith('Invalid OIDC provider ID')

    def test_delete(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, '{}')

        auth.delete_oidc_provider_config('oidc.provider', app=user_mgt_app)

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'DELETE'
        assert req.url == '{0}{1}'.format(USER_MGT_URL_PREFIX, '/oauthIdpConfigs/oidc.provider')

    @pytest.mark.parametrize('arg', [None, 'foo', list(), dict(), 0, -1, 101, False])
    def test_invalid_max_results(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.list_oidc_provider_configs(max_results=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', ['', list(), dict(), 0, -1, 101, False])
    def test_invalid_page_token(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.list_oidc_provider_configs(page_token=arg, app=user_mgt_app)

    def test_list_single_page(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, LIST_OIDC_PROVIDER_CONFIGS_RESPONSE)
        page = auth.list_oidc_provider_configs(app=user_mgt_app)

        self._assert_page(page)
        provider_configs = list(config for config in page.iterate_all())
        assert len(provider_configs) == 2

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}{1}'.format(USER_MGT_URL_PREFIX, '/oauthIdpConfigs?pageSize=100')

    def test_list_multiple_pages(self, user_mgt_app):
        sample_response = json.loads(OIDC_PROVIDER_CONFIG_RESPONSE)
        configs = _create_list_response(sample_response)

        # Page 1
        response = {
            'oauthIdpConfigs': configs[:2],
            'nextPageToken': 'token'
        }
        recorder = _instrument_provider_mgt(user_mgt_app, 200, json.dumps(response))
        page = auth.list_oidc_provider_configs(max_results=10, app=user_mgt_app)

        self._assert_page(page, next_page_token='token')
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/oauthIdpConfigs?pageSize=10'.format(USER_MGT_URL_PREFIX)

        # Page 2 (also the last page)
        response = {'oauthIdpConfigs': configs[2:]}
        recorder = _instrument_provider_mgt(user_mgt_app, 200, json.dumps(response))
        page = page.get_next_page()

        self._assert_page(page, count=1, start=2)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/oauthIdpConfigs?pageSize=10&pageToken=token'.format(
            USER_MGT_URL_PREFIX)

    def test_paged_iteration(self, user_mgt_app):
        sample_response = json.loads(OIDC_PROVIDER_CONFIG_RESPONSE)
        configs = _create_list_response(sample_response)

        # Page 1
        response = {
            'oauthIdpConfigs': configs[:2],
            'nextPageToken': 'token'
        }
        recorder = _instrument_provider_mgt(user_mgt_app, 200, json.dumps(response))
        page = auth.list_oidc_provider_configs(app=user_mgt_app)
        iterator = page.iterate_all()

        for index in range(2):
            provider_config = next(iterator)
            assert provider_config.provider_id == 'oidc.provider{0}'.format(index)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/oauthIdpConfigs?pageSize=100'.format(USER_MGT_URL_PREFIX)

        # Page 2 (also the last page)
        response = {'oauthIdpConfigs': configs[2:]}
        recorder = _instrument_provider_mgt(user_mgt_app, 200, json.dumps(response))

        provider_config = next(iterator)
        assert provider_config.provider_id == 'oidc.provider2'
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/oauthIdpConfigs?pageSize=100&pageToken=token'.format(
            USER_MGT_URL_PREFIX)

        with pytest.raises(StopIteration):
            next(iterator)

    def test_list_empty_response(self, user_mgt_app):
        response = {'oauthIdpConfigs': []}
        _instrument_provider_mgt(user_mgt_app, 200, json.dumps(response))
        page = auth.list_oidc_provider_configs(app=user_mgt_app)
        assert len(page.provider_configs) == 0
        provider_configs = list(config for config in page.iterate_all())
        assert len(provider_configs) == 0

    def test_list_error(self, user_mgt_app):
        _instrument_provider_mgt(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.list_oidc_provider_configs(app=user_mgt_app)
        assert str(excinfo.value) == 'Unexpected error response: {"error":"test"}'

    def test_config_not_found(self, user_mgt_app):
        _instrument_provider_mgt(user_mgt_app, 500, CONFIG_NOT_FOUND_RESPONSE)

        with pytest.raises(auth.ConfigurationNotFoundError) as excinfo:
            auth.get_oidc_provider_config('oidc.provider', app=user_mgt_app)

        error_msg = 'No auth provider found for the given identifier (CONFIGURATION_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def _assert_provider_config(self, provider_config, want_id='oidc.provider'):
        assert isinstance(provider_config, auth.OIDCProviderConfig)
        assert provider_config.provider_id == want_id
        assert provider_config.display_name == 'oidcProviderName'
        assert provider_config.enabled is True
        assert provider_config.issuer == 'https://oidc.com/issuer'
        assert provider_config.client_id == 'CLIENT_ID'

    def _assert_page(self, page, count=2, start=0, next_page_token=''):
        assert isinstance(page, auth.ListProviderConfigsPage)
        index = start
        assert len(page.provider_configs) == count
        for provider_config in page.provider_configs:
            self._assert_provider_config(provider_config, want_id='oidc.provider{0}'.format(index))
            index += 1

        if next_page_token:
            assert page.next_page_token == next_page_token
            assert page.has_next_page is True
        else:
            assert page.next_page_token == ''
            assert page.has_next_page is False
            assert page.get_next_page() is None


class TestSAMLProviderConfig:

    VALID_CREATE_OPTIONS = {
        'provider_id': 'saml.provider',
        'idp_entity_id': 'IDP_ENTITY_ID',
        'sso_url': 'https://example.com/login',
        'x509_certificates': ['CERT1', 'CERT2'],
        'rp_entity_id': 'RP_ENTITY_ID',
        'callback_url': 'https://projectId.firebaseapp.com/__/auth/handler',
        'display_name': 'samlProviderName',
        'enabled': True,
    }

    SAML_CONFIG_REQUEST = {
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

    @pytest.mark.parametrize('provider_id', INVALID_PROVIDER_IDS + ['oidc.provider'])
    def test_get_invalid_provider_id(self, user_mgt_app, provider_id):
        with pytest.raises(ValueError) as excinfo:
            auth.get_saml_provider_config(provider_id, app=user_mgt_app)

        assert str(excinfo.value).startswith('Invalid SAML provider ID')

    def test_get(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, SAML_PROVIDER_CONFIG_RESPONSE)

        provider_config = auth.get_saml_provider_config('saml.provider', app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}{1}'.format(USER_MGT_URL_PREFIX, '/inboundSamlConfigs/saml.provider')

    @pytest.mark.parametrize('invalid_opts', [
        {'provider_id': None}, {'provider_id': ''}, {'provider_id': 'oidc.provider'},
        {'idp_entity_id': None}, {'idp_entity_id': ''},
        {'sso_url': None}, {'sso_url': ''}, {'sso_url': 'not a url'},
        {'x509_certificates': None}, {'x509_certificates': []}, {'x509_certificates': 'cert'},
        {'x509_certificates': [None]}, {'x509_certificates': ['foo', {}]},
        {'rp_entity_id': None}, {'rp_entity_id': ''},
        {'callback_url': None}, {'callback_url': ''}, {'callback_url': 'not a url'},
        {'display_name': True},
        {'enabled': 'true'},
    ])
    def test_create_invalid_args(self, user_mgt_app, invalid_opts):
        options = dict(self.VALID_CREATE_OPTIONS)
        options.update(invalid_opts)
        with pytest.raises(ValueError):
            auth.create_saml_provider_config(**options, app=user_mgt_app)

    def test_create(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, SAML_PROVIDER_CONFIG_RESPONSE)

        provider_config = auth.create_saml_provider_config(
            **self.VALID_CREATE_OPTIONS, app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'POST'
        assert req.url == '{0}/inboundSamlConfigs?inboundSamlConfigId=saml.provider'.format(
            USER_MGT_URL_PREFIX)
        got = json.loads(req.body.decode())
        assert got == self.SAML_CONFIG_REQUEST

    def test_create_minimal(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, SAML_PROVIDER_CONFIG_RESPONSE)
        options = dict(self.VALID_CREATE_OPTIONS)
        del options['display_name']
        del options['enabled']
        want = dict(self.SAML_CONFIG_REQUEST)
        del want['displayName']
        del want['enabled']

        provider_config = auth.create_saml_provider_config(**options, app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'POST'
        assert req.url == '{0}/inboundSamlConfigs?inboundSamlConfigId=saml.provider'.format(
            USER_MGT_URL_PREFIX)
        got = json.loads(req.body.decode())
        assert got == want

    def test_create_empty_values(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, SAML_PROVIDER_CONFIG_RESPONSE)
        options = dict(self.VALID_CREATE_OPTIONS)
        options['display_name'] = ''
        options['enabled'] = False
        want = dict(self.SAML_CONFIG_REQUEST)
        want['displayName'] = ''
        want['enabled'] = False

        provider_config = auth.create_saml_provider_config(**options, app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'POST'
        assert req.url == '{0}/inboundSamlConfigs?inboundSamlConfigId=saml.provider'.format(
            USER_MGT_URL_PREFIX)
        got = json.loads(req.body.decode())
        assert got == want

    @pytest.mark.parametrize('invalid_opts', [
        {},
        {'provider_id': None}, {'provider_id': ''}, {'provider_id': 'oidc.provider'},
        {'idp_entity_id': ''},
        {'sso_url': ''}, {'sso_url': 'not a url'},
        {'x509_certificates': []}, {'x509_certificates': 'cert'},
        {'x509_certificates': [None]}, {'x509_certificates': ['foo', {}]},
        {'rp_entity_id': ''},
        {'callback_url': ''}, {'callback_url': 'not a url'},
        {'display_name': True},
        {'enabled': 'true'},
    ])
    def test_update_invalid_args(self, user_mgt_app, invalid_opts):
        options = {'provider_id': 'saml.provider'}
        options.update(invalid_opts)
        with pytest.raises(ValueError):
            auth.update_saml_provider_config(**options, app=user_mgt_app)

    def test_update(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, SAML_PROVIDER_CONFIG_RESPONSE)

        provider_config = auth.update_saml_provider_config(
            **self.VALID_CREATE_OPTIONS, app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'PATCH'
        mask = [
            'displayName', 'enabled', 'idpConfig.idpCertificates', 'idpConfig.idpEntityId',
            'idpConfig.ssoUrl', 'spConfig.callbackUri', 'spConfig.spEntityId',
        ]
        assert req.url == '{0}/inboundSamlConfigs/saml.provider?updateMask={1}'.format(
            USER_MGT_URL_PREFIX, ','.join(mask))
        got = json.loads(req.body.decode())
        assert got == self.SAML_CONFIG_REQUEST

    def test_update_minimal(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, SAML_PROVIDER_CONFIG_RESPONSE)

        provider_config = auth.update_saml_provider_config(
            'saml.provider', display_name='samlProviderName', app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'PATCH'
        assert req.url == '{0}/inboundSamlConfigs/saml.provider?updateMask=displayName'.format(
            USER_MGT_URL_PREFIX)
        got = json.loads(req.body.decode())
        assert got == {'displayName': 'samlProviderName'}

    def test_update_empty_values(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, SAML_PROVIDER_CONFIG_RESPONSE)

        provider_config = auth.update_saml_provider_config(
            'saml.provider', display_name=auth.DELETE_ATTRIBUTE, enabled=False, app=user_mgt_app)

        self._assert_provider_config(provider_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'PATCH'
        mask = ['displayName', 'enabled']
        assert req.url == '{0}/inboundSamlConfigs/saml.provider?updateMask={1}'.format(
            USER_MGT_URL_PREFIX, ','.join(mask))
        got = json.loads(req.body.decode())
        assert got == {'displayName': None, 'enabled': False}

    @pytest.mark.parametrize('provider_id', INVALID_PROVIDER_IDS + ['oidc.provider'])
    def test_delete_invalid_provider_id(self, user_mgt_app, provider_id):
        with pytest.raises(ValueError) as excinfo:
            auth.delete_saml_provider_config(provider_id, app=user_mgt_app)

        assert str(excinfo.value).startswith('Invalid SAML provider ID')

    def test_delete(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, '{}')

        auth.delete_saml_provider_config('saml.provider', app=user_mgt_app)

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'DELETE'
        assert req.url == '{0}{1}'.format(USER_MGT_URL_PREFIX, '/inboundSamlConfigs/saml.provider')

    def test_config_not_found(self, user_mgt_app):
        _instrument_provider_mgt(user_mgt_app, 500, CONFIG_NOT_FOUND_RESPONSE)

        with pytest.raises(auth.ConfigurationNotFoundError) as excinfo:
            auth.get_saml_provider_config('saml.provider', app=user_mgt_app)

        error_msg = 'No auth provider found for the given identifier (CONFIGURATION_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    @pytest.mark.parametrize('arg', [None, 'foo', list(), dict(), 0, -1, 101, False])
    def test_invalid_max_results(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.list_saml_provider_configs(max_results=arg, app=user_mgt_app)

    @pytest.mark.parametrize('arg', ['', list(), dict(), 0, -1, 101, False])
    def test_invalid_page_token(self, user_mgt_app, arg):
        with pytest.raises(ValueError):
            auth.list_saml_provider_configs(page_token=arg, app=user_mgt_app)

    def test_list_single_page(self, user_mgt_app):
        recorder = _instrument_provider_mgt(user_mgt_app, 200, LIST_SAML_PROVIDER_CONFIGS_RESPONSE)
        page = auth.list_saml_provider_configs(app=user_mgt_app)

        self._assert_page(page)
        provider_configs = list(config for config in page.iterate_all())
        assert len(provider_configs) == 2

        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}{1}'.format(USER_MGT_URL_PREFIX, '/inboundSamlConfigs?pageSize=100')

    def test_list_multiple_pages(self, user_mgt_app):
        sample_response = json.loads(SAML_PROVIDER_CONFIG_RESPONSE)
        configs = _create_list_response(sample_response)

        # Page 1
        response = {
            'inboundSamlConfigs': configs[:2],
            'nextPageToken': 'token'
        }
        recorder = _instrument_provider_mgt(user_mgt_app, 200, json.dumps(response))
        page = auth.list_saml_provider_configs(max_results=10, app=user_mgt_app)

        self._assert_page(page, next_page_token='token')
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/inboundSamlConfigs?pageSize=10'.format(USER_MGT_URL_PREFIX)

        # Page 2 (also the last page)
        response = {'inboundSamlConfigs': configs[2:]}
        recorder = _instrument_provider_mgt(user_mgt_app, 200, json.dumps(response))
        page = page.get_next_page()

        self._assert_page(page, count=1, start=2)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/inboundSamlConfigs?pageSize=10&pageToken=token'.format(
            USER_MGT_URL_PREFIX)

    def test_paged_iteration(self, user_mgt_app):
        sample_response = json.loads(SAML_PROVIDER_CONFIG_RESPONSE)
        configs = _create_list_response(sample_response)

        # Page 1
        response = {
            'inboundSamlConfigs': configs[:2],
            'nextPageToken': 'token'
        }
        recorder = _instrument_provider_mgt(user_mgt_app, 200, json.dumps(response))
        page = auth.list_saml_provider_configs(app=user_mgt_app)
        iterator = page.iterate_all()

        for index in range(2):
            provider_config = next(iterator)
            assert provider_config.provider_id == 'saml.provider{0}'.format(index)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/inboundSamlConfigs?pageSize=100'.format(USER_MGT_URL_PREFIX)

        # Page 2 (also the last page)
        response = {'inboundSamlConfigs': configs[2:]}
        recorder = _instrument_provider_mgt(user_mgt_app, 200, json.dumps(response))

        provider_config = next(iterator)
        assert provider_config.provider_id == 'saml.provider2'
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/inboundSamlConfigs?pageSize=100&pageToken=token'.format(
            USER_MGT_URL_PREFIX)

        with pytest.raises(StopIteration):
            next(iterator)

    def test_list_empty_response(self, user_mgt_app):
        response = {'inboundSamlConfigs': []}
        _instrument_provider_mgt(user_mgt_app, 200, json.dumps(response))
        page = auth.list_saml_provider_configs(app=user_mgt_app)
        assert len(page.provider_configs) == 0
        provider_configs = list(config for config in page.iterate_all())
        assert len(provider_configs) == 0

    def test_list_error(self, user_mgt_app):
        _instrument_provider_mgt(user_mgt_app, 500, '{"error":"test"}')
        with pytest.raises(exceptions.InternalError) as excinfo:
            auth.list_saml_provider_configs(app=user_mgt_app)
        assert str(excinfo.value) == 'Unexpected error response: {"error":"test"}'

    def _assert_provider_config(self, provider_config, want_id='saml.provider'):
        assert isinstance(provider_config, auth.SAMLProviderConfig)
        assert provider_config.provider_id == want_id
        assert provider_config.display_name == 'samlProviderName'
        assert provider_config.enabled is True
        assert provider_config.idp_entity_id == 'IDP_ENTITY_ID'
        assert provider_config.sso_url == 'https://example.com/login'
        assert provider_config.x509_certificates == ['CERT1', 'CERT2']
        assert provider_config.rp_entity_id == 'RP_ENTITY_ID'
        assert provider_config.callback_url == 'https://projectId.firebaseapp.com/__/auth/handler'

    def _assert_page(self, page, count=2, start=0, next_page_token=''):
        assert isinstance(page, auth.ListProviderConfigsPage)
        index = start
        assert len(page.provider_configs) == count
        for provider_config in page.provider_configs:
            self._assert_provider_config(provider_config, want_id='saml.provider{0}'.format(index))
            index += 1

        if next_page_token:
            assert page.next_page_token == next_page_token
            assert page.has_next_page is True
        else:
            assert page.next_page_token == ''
            assert page.has_next_page is False
            assert page.get_next_page() is None


def _create_list_response(sample_response, count=3):
    configs = []
    for idx in range(count):
        config = dict(sample_response)
        config['name'] += str(idx)
        configs.append(config)
    return configs
