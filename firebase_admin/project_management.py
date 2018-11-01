# Copyright 2018 Google Inc.
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

"""Firebase Project Management module.

This module enables management of resources in Firebase projects, such as Android and iOS Apps.
"""

import requests
import six

from firebase_admin import _http_client
from firebase_admin import _utils


_PROJECT_MANAGEMENT_ATTRIBUTE = '_project_management'


def _get_project_management_service(app):
    return _utils.get_app_service(app, _PROJECT_MANAGEMENT_ATTRIBUTE, _ProjectManagementService)


def android_app(app_id, app=None):
    """Obtains a reference to an Android App in the associated Firebase Project.

    Args:
        app_id: The App ID that identifies this Android App.
        app: An App instance (optional).

    Returns:
        AndroidApp: An ``AndroidApp`` instance.
    """
    return AndroidApp(app_id=app_id, service=_get_project_management_service(app))


def _check_is_string(obj, field_name):
    if isinstance(obj, six.string_types):
        return obj
    raise ValueError('{0} must be a string.'.format(field_name))


def _check_is_nonempty_string(obj, field_name):
    if isinstance(obj, six.string_types) and obj:
        return obj
    raise ValueError('{0} must be a non-empty string.'.format(field_name))


class ApiCallError(Exception):
    """An error encountered while interacting with the Firebase Project Management Service."""

    def __init__(self, message, error):
        Exception.__init__(self, message)
        self.detail = error


class AndroidApp(object):
    """A reference to an Android App within a Firebase Project."""

    def __init__(self, app_id, service):
        self._app_id = app_id
        self._service = service

    @property
    def app_id(self):
        return self._app_id

    def get_metadata(self):
        """Retrieves detailed information about this Android App.

        Note: this method makes an RPC.

        Returns:
            AndroidAppMetadata: An ``AndroidAppMetadata`` instance.

        Raises:
            ApiCallError: If an error occurs while communicating with the Firebase Project
                Management Service.
        """
        return self._service.get_android_app_metadata(self._app_id)


class AppMetadata(object):
    """Detailed information about a Firebase App."""

    def __init__(self, name, app_id, display_name, project_id):
        self._name = _check_is_nonempty_string(name, 'name')
        self._app_id = _check_is_nonempty_string(app_id, 'app_id')
        self._display_name = _check_is_string(display_name, 'display_name')
        self._project_id = _check_is_nonempty_string(project_id, 'project_id')

    @property
    def name(self):
        """The fully qualified resource name of this Android App."""
        return self._name

    @property
    def app_id(self):
        """The globally unique, Firebase-assigned identifier of this Android App.

        This ID is unique even across Apps of different platforms, such as iOS Apps.
        """
        return self._app_id

    @property
    def display_name(self):
        """The user-assigned display name of this Android App."""
        return self._display_name

    @property
    def project_id(self):
        """The permanent, globally unique, user-assigned ID of the parent Firebase Project."""
        return self._project_id


class AndroidAppMetadata(AppMetadata):
    """Android-specific information about an Android Firebase App."""

    def __init__(self, name, app_id, display_name, project_id, package_name):
        super(AndroidAppMetadata, self).__init__(name, app_id, display_name, project_id)
        self._package_name = _check_is_nonempty_string(package_name, 'package_name')

    @property
    def package_name(self):
        """The canonical package name of this Android App as it would appear in the Play Store."""
        return self._package_name


class _ProjectManagementService(object):
    """Provides methods for interacting with the Firebase Project Management Service."""

    _base_url = 'https://firebase.googleapis.com/v1beta1'

    _error_codes = {
        401: 'Request not authorized.',
        403: 'Client does not have sufficient privileges.',
        404: 'Failed to find the App.',
        429: 'Request throttled out by the backend server.',
        500: 'Internal server error.',
        503: 'Backend servers are over capacity. Try again later.'
    }

    def __init__(self, app):
        project_id = app.project_id
        if not project_id:
            raise ValueError(
                'Project ID is required to access the Firebase Project Management Service. Either '
                'set the projectId option, or use service account credentials. Alternatively, set '
                'the GOOGLE_CLOUD_PROJECT environment variable.')
        self._project_id = project_id
        self._client = _http_client.JsonHttpClient(
            credential=app.credential.get_credential(),
            base_url=_ProjectManagementService._base_url)
        self._timeout = app.options.get('httpTimeout')

    def get_android_app_metadata(self, app_id):
        if not isinstance(app_id, six.string_types) or not app_id:
            raise ValueError('App ID must be a non-empty string.')
        path = '/projects/-/androidApps/{0}'.format(app_id)
        try:
            response = self._client.body('get', url=path, timeout=self._timeout)
        except requests.exceptions.RequestException as error:
            raise ApiCallError(self._extract_message(app_id, error), error)
        return AndroidAppMetadata(
            name=response['name'],
            app_id=response['appId'],
            display_name=response['displayName'],
            project_id=response['projectId'],
            package_name=response['packageName'])

    def _extract_message(self, app_id, error):
        if error.response is None:
            return str(error)
        status = error.response.status_code
        message = self._error_codes.get(status)
        if message:
            return 'App ID "{0}": {1}'.format(app_id, message)
