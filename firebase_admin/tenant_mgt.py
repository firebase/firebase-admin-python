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

    'delete_tenant',
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


def create_tenant(
        display_name=None, allow_password_sign_up=None, enable_email_link_sign_in=None, app=None):
    """Creates a new tenant from the given options.

    Args:
        display_name: Display name string for the new tenant (optional).
        allow_password_sign_up: A boolean indicating whether to enable or disable the email sign-in
            provider.
        enable_email_link_sign_in: A boolean indicating whether to enable or disable email link
            sign-in. Disabling this makes the password required for email sign-in.
        app: An App instance (optional).

    Returns:
        Tenant: A Tenant object.

    Raises:
        ValueError: If any of the given arguments are invalid.
        FirebaseError: If an error occurs while creating the tenant.
    """
    tenant_mgt_service = _get_tenant_mgt_service(app)
    return tenant_mgt_service.create_tenant(
        display_name=display_name, allow_password_sign_up=allow_password_sign_up,
        enable_email_link_sign_in=enable_email_link_sign_in)


def delete_tenant(tenant_id, app=None):
    """Deletes the tenant corresponding to the given ``tenant_id``.

    Args:
        tenant_id: A tenant ID string.
        app: An App instance (optional).

    Raises:
        ValueError: If the tenant ID is None, empty or not a string.
        TenantNotFoundError: If no tenant exists by the given ID.
        FirebaseError: If an error occurs while retrieving the tenant.
    """
    tenant_mgt_service = _get_tenant_mgt_service(app)
    tenant_mgt_service.delete_tenant(tenant_id)


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
        """Gets the tenant corresponding to the given ``tenant_id``."""
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError(
                'Invalid tenant ID: {0}. Tenant ID must be a non-empty string.'.format(tenant_id))

        try:
            body = self.client.body('get', '/tenants/{0}'.format(tenant_id))
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
        else:
            return Tenant(body)

    def create_tenant(
            self, display_name=None, allow_password_sign_up=None, enable_email_link_sign_in=None):
        """Creates a new tenant from the given parameters."""
        payload = {}
        if display_name is not None:
            payload['displayName'] = _auth_utils.validate_display_name(display_name)
        if allow_password_sign_up is not None:
            payload['allowPasswordSignup'] = _auth_utils.validate_boolean(
                allow_password_sign_up, 'allowPasswordSignup')
        if enable_email_link_sign_in is not None:
            payload['enableEmailLinkSignin'] = _auth_utils.validate_boolean(
                enable_email_link_sign_in, 'enableEmailLinkSignin')

        try:
            body = self.client.body('post', '/tenants', data=payload)
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
        else:
            return Tenant(body)

    def delete_tenant(self, tenant_id):
        """Deletes the tenant corresponding to the given ``tenant_id``."""
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError(
                'Invalid tenant ID: {0}. Tenant ID must be a non-empty string.'.format(tenant_id))

        try:
            self.client.request('delete', '/tenants/{0}'.format(tenant_id))
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
