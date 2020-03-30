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

import requests

from firebase_admin import _auth_utils


class ProviderConfig:
    """Parent type for all authentication provider config types."""

    def __init__(self, data):
        self._data = data

    @property
    def provider_id(self):
        name = self._data['name']
        return name.split('/')[-1]

    @property
    def display_name(self):
        return self._data.get('displayName')

    @property
    def enabled(self):
        return self._data['enabled']


class SAMLProviderConfig(ProviderConfig):
    """Represents he SAML auth provider configuration.

    See http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html."""

    def __init__(self, data):
        super().__init__(data)

    @property
    def idp_entity_id(self):
        return self._data.get('idpConfig', {})['idpEntityId']

    @property
    def sso_url(self):
        return self._data.get('idpConfig', {})['ssoUrl']

    @property
    def x509_certificates(self):
        certs = self._data.get('idpConfig', {})['idpCertificates']
        return [c['x509Certificate'] for c in certs]

    @property
    def request_signing_enabled(self):
        return self._data.get('idpConfig', {})['signRequest']

    @property
    def callback_url(self):
        return self._data.get('spConfig', {})['callbackUri']

    @property
    def rp_entity_id(self):
        return self._data.get('spConfig', {})['spEntityId']


class ProviderConfigClient:
    """Client for managing Auth provider configurations."""

    PROVIDER_CONFIG_URL = 'https://identitytoolkit.googleapis.com/v2beta1'

    def __init__(self, http_client, project_id, tenant_id=None):
        self.http_client = http_client
        self.base_url = '{0}/projects/{1}'.format(self.PROVIDER_CONFIG_URL, project_id)
        if tenant_id:
            self.base_url += '/tenants/{0}'.format(tenant_id)

    def get_saml_provider_config(self, provider_id):
        if not isinstance(provider_id, str):
            raise ValueError(
                'Invalid SAML provider ID: {0}. Provider ID must be a non-empty string.'.format(
                    provider_id))
        if not provider_id.startswith('saml.'):
            raise ValueError('Invalid SAML provider ID: {0}.'.format(provider_id))

        body = self._make_request('get', '/inboundSamlConfigs/{0}'.format(provider_id))
        return SAMLProviderConfig(body)

    def _make_request(self, method, path, body=None):
        url = '{0}{1}'.format(self.base_url, path)
        try:
            return self.http_client.body(method, url, json=body)
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
