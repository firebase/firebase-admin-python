# Copyright 2017 Google Inc.
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

"""Firebase Instance ID module.

This module enables deleting instance IDs associated with Firebase projects.
"""

import requests
import six

from firebase_admin import _http_client
from firebase_admin import _utils


_IID_SERVICE_URL = 'https://console.firebase.google.com/v1/'
_IID_ATTRIBUTE = '_iid'


def _get_iid_service(app):
    return _utils.get_app_service(app, _IID_ATTRIBUTE, _InstanceIdService)


def delete_instance_id(instance_id, app=None):
    """Deletes the specified instance ID from Firebase.

    This can be used to delete an instance ID and associated user data from a Firebase project,
    pursuant to the General Data Protection Regulation (GDPR).

    Args:
      instance_id: A non-empty instance ID string.
      app: An App instance (optional).

    Raises:
      InstanceIdError: If an error occurs while invoking the backend instance ID service.
      ValueError: If the specified instance ID or app is invalid.
    """
    _get_iid_service(app).delete_instance_id(instance_id)


class ApiCallError(Exception):
    """Represents an Exception encountered while invoking the Firebase instance ID service."""

    def __init__(self, message, error):
        Exception.__init__(self, message)
        self.detail = error


class _InstanceIdService(object):
    """Provides methods for interacting with the remote instance ID service."""

    error_codes = {
        400: 'Malformed instance ID argument.',
        401: 'Request not authorized.',
        403: 'Project does not match instance ID or the client does not have '
             'sufficient privileges.',
        404: 'Failed to find the instance ID.',
        409: 'Already deleted.',
        429: 'Request throttled out by the backend server.',
        500: 'Internal server error.',
        503: 'Backend servers are over capacity. Try again later.'
    }

    def __init__(self, app):
        project_id = app.project_id
        if not project_id:
            raise ValueError(
                'Project ID is required to access Instance ID service. Either set the projectId '
                'option, or use service account credentials. Alternatively, set the '
                'GOOGLE_CLOUD_PROJECT environment variable.')
        self._project_id = project_id
        self._client = _http_client.JsonHttpClient(
            credential=app.credential.get_credential(), base_url=_IID_SERVICE_URL)

    def delete_instance_id(self, instance_id):
        if not isinstance(instance_id, six.string_types) or not instance_id:
            raise ValueError('Instance ID must be a non-empty string.')
        path = 'project/{0}/instanceId/{1}'.format(self._project_id, instance_id)
        try:
            self._client.request('delete', path)
        except requests.exceptions.RequestException as error:
            raise ApiCallError(self._extract_message(instance_id, error), error)

    def _extract_message(self, instance_id, error):
        if error.response is None:
            return str(error)
        status = error.response.status_code
        msg = self.error_codes.get(status)
        if msg:
            return 'Instance ID "{0}": {1}'.format(instance_id, msg)
        else:
            return str(error)
