# Copyright 2023 Google Inc.
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
"""Firebase project configuration management module.

This module contains functions for managing various project-level configurations within a
Firebase project, such as multi-factor authentication (MFA) settings.
"""

import requests

import firebase_admin
from firebase_admin import _auth_utils
from firebase_admin import _http_client
from firebase_admin import _utils
from firebase_admin import multi_factor_config_mgt

_PROJECT_MGT_ATTRIBUTE = '_project_mgt'

__all__ = [
    'ProjectConfig',

    'get_project',
    'update_project',
]


def get_project(app=None):
    """Gets the project corresponding to the given project_id.

    Args:
        app: An App instance (optional).

    Returns:
        Project: A project object.

    Raises:
        ValueError: If the project ID is None, empty or not a string.
        ProjectNotFoundError: If no project exists by the given ID.
        FirebaseError: If an error occurs while retrieving the project.
    """
    project_mgt_service = _get_project_mgt_service(app)
    return project_mgt_service.get_project()


def update_project(mfa=None, app=None):
    """Update the Project with the given options.

    Args:
        mfa: Updated Multi Factor Authentication configuration
                    (optional)
        app: An App instance (optional).

    Returns:
        Project: The updated project object.

    Raises:
        ValueError: If any of the given arguments are invalid.
        ProjectNotFoundError: If no project exists by the given ID.
        FirebaseError: If an error occurs while updating the project.
    """
    project_mgt_service = _get_project_mgt_service(app)
    return project_mgt_service.update_project(mfa=mfa)


def _get_project_mgt_service(app):
    return _utils.get_app_service(app, _PROJECT_MGT_ATTRIBUTE, _ProjectConfigManagementService)


class ProjectConfig:
    """Represents a project config in an application.
    """

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError(
                'Invalid data argument in Project constructor: {0}'.format(data))
        self._data = data

    @property
    def mfa(self):
        data = self._data.get('multiFactorConfig')
        if data:
            return multi_factor_config_mgt.MultiFactorConfig(data)
        return None


class _ProjectConfigManagementService:
    """Firebase project management service."""

    PROJECT_CONFIG_MGT_URL = 'https://identitytoolkit.googleapis.com/v2/projects'

    def __init__(self, app):
        credential = app.credential.get_credential()
        version_header = 'Python/Admin/{0}'.format(firebase_admin.__version__)
        base_url = '{0}/{1}/config'.format(
            self.PROJECT_CONFIG_MGT_URL, app.project_id)
        self.app = app
        self.client = _http_client.JsonHttpClient(
            credential=credential, base_url=base_url, headers={'X-Client-Version': version_header})

    def get_project(self):
        """Gets the project corresponding to the given `project_id`."""
        try:
            body = self.client.body('get', url='')
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
        else:
            body = _auth_utils.convert_project_auth_payload_to_user(body)
            return ProjectConfig(body)

    def update_project(self, mfa=None):
        """Updates the specified project with the given parameters."""

        payload = {}
        if mfa is not None:
            payload['mfa'] = multi_factor_config_mgt.validate_mfa_config(
                multi_factor_config_mgt.MultiFactorConfig(mfa))

        if not payload:
            raise ValueError(
                'At least one parameter must be specified for update.')

        update_mask = ','.join(_auth_utils.build_update_mask(payload))
        params = 'updateMask={0}'.format(update_mask)
        try:
            body = self.client.body(
                'patch', url='', json=payload, params=params)
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
        else:
            body = _auth_utils.convert_project_auth_payload_to_user(body)
            return ProjectConfig(body)
