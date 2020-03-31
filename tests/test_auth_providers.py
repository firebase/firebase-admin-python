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
SAML_PROVIDER_CONFIG_RESPONSE = testutils.resource('saml_provider_config.json')

CONFIG_NOT_FOUND_RESPONSE = """{
    "error": {
        "message": "CONFIGURATION_NOT_FOUND"
    }
}"""


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

    @pytest.mark.parametrize('provider_id', [
        None, True, False, 1, 0, list(), tuple(), dict(), '', 'oidc.provider'
    ])
    def test_invalid_provider_id(self, user_mgt_app, provider_id):
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

    def test_config_not_found(self, user_mgt_app):
        _instrument_provider_mgt(user_mgt_app, 500, CONFIG_NOT_FOUND_RESPONSE)

        with pytest.raises(auth.ConfigurationNotFoundError) as excinfo:
            auth.get_saml_provider_config('saml.provider', app=user_mgt_app)

        error_msg = 'No auth provider found for the given identifier (CONFIGURATION_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None

    def _assert_provider_config(self, provider_config):
        assert provider_config.provider_id == 'saml.provider'
        assert provider_config.display_name == 'samlProviderName'
        assert provider_config.enabled is True
        assert provider_config.idp_entity_id == 'IDP_ENTITY_ID'
        assert provider_config.sso_url == 'https://example.com/login'
        assert provider_config.x509_certificates == ['CERT1', 'CERT2']
        assert provider_config.rp_entity_id == 'RP_ENTITY_ID'
        assert provider_config.callback_url == 'https://projectId.firebaseapp.com/__/auth/handler'
