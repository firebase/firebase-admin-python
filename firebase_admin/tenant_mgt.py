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

"""Firebase tenant management module.

This module contains functions for creating and configuring authentication tenants within a
Google Cloud Identity Platform (GCIP) instance.
"""

import requests

import firebase_admin
from firebase_admin import _auth_utils
from firebase_admin import _http_client
from firebase_admin import _utils


_TENANT_MGT_ATTRIBUTE = '_tenant_mgt'


__all__ = [
    'Tenant',
    'TenantNotFoundError',

    'get_tenant',
]

TenantNotFoundError = _auth_utils.TenantNotFoundError


def get_tenant(tenant_id, app=None):
    """Gets the tenant corresponding to the given ``tenant_id``.

    Args:
        tenant_id: A tenant ID string.
        app: An App instance (optional).

    Returns:
        Tenant: A Tenant object.

    Raises:
        ValueError: If the tenant ID is None, empty or not a string.
        TenantNotFoundError: If no tenant exists by the given ID.
        FirebaseError: If an error occurs while retrieving the tenant.
    """
    tenant_mgt_service = _get_tenant_mgt_service(app)
    return tenant_mgt_service.get_tenant(tenant_id)


def _get_tenant_mgt_service(app):
    return _utils.get_app_service(app, _TENANT_MGT_ATTRIBUTE, _TenantManagementService)


class Tenant:
    """Represents a tenant in a multi-tenant application.

    Multi-tenancy support requires Google Cloud Identity Platform (GCIP). To learn more about
    GCIP including pricing and features, see https://cloud.google.com/identity-platform.

    Before multi-tenancy can be used in a Google Cloud Identity Platform project, tenants must be
    enabled in that project via the Cloud Console UI. A Tenant instance provides information
    such as the display name, tenant identifier and email authentication configuration.
    """

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument in Tenant constructor: {0}'.format(data))
        if not 'name' in data:
            raise ValueError('Tenant response missing required keys.')

        self._data = data

    @property
    def tenant_id(self):
        name = self._data['name']
        return name.split('/')[-1]

    @property
    def display_name(self):
        return self._data.get('displayName')

    @property
    def allow_password_sign_up(self):
        return self._data.get('allowPasswordSignup', False)

    @property
    def enable_email_link_sign_in(self):
        return self._data.get('enableEmailLinkSignin', False)


class _TenantManagementService:
    """Firebase tenant management service."""

    TENANT_MGT_URL = 'https://identitytoolkit.googleapis.com/v2beta1'

    def __init__(self, app):
        credential = app.credential.get_credential()
        version_header = 'Python/Admin/{0}'.format(firebase_admin.__version__)
        base_url = '{0}/projects/{1}'.format(self.TENANT_MGT_URL, app.project_id)
        self.client = _http_client.JsonHttpClient(
            credential=credential, base_url=base_url, headers={'X-Client-Version': version_header})

    def get_tenant(self, tenant_id):
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError(
                'Invalid tenant ID: {0}. Tenant ID must be a non-empty string.'.format(tenant_id))

        try:
            body = self.client.body('get', '/tenants/{0}'.format(tenant_id))
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
        else:
            return Tenant(body)
