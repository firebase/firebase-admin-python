# Copyright 2019 Google Inc.
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

"""Firebase ML Kit module.

This module contains functions for creating, updating, getting, listing,
deleting, publishing and unpublishing Firebase ML Kit models.
"""

import re
import requests
import six

from firebase_admin import _http_client
from firebase_admin import _utils


_MLKIT_ATTRIBUTE = '_mlkit'


def _get_mlkit_service(app):
    """ Returns an _MLKitService instance for an App.

    Args:
      app: A Firebase App instance (or None to use the default App).

    Returns:
      _MLKitService: An _MLKitService for the specified App instance.

    Raises:
      ValueError: If the app argument is invalid.
    """
    return _utils.get_app_service(app, _MLKIT_ATTRIBUTE, _MLKitService)


def get_model(model_id, app=None):
    mlkit_service = _get_mlkit_service(app)
    return Model(mlkit_service.get_model(model_id))


def delete_model(model_id, app=None):
    mlkit_service = _get_mlkit_service(app)
    mlkit_service.delete_model(model_id)


class Model(object):
    """A Firebase ML Kit Model object."""
    def __init__(self, data):
        """Created from a data dictionary."""
        self._data = data

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self._data == other._data # pylint: disable=protected-access
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    #TODO(ifielker): define the Model properties etc


def _validate_model_id(model_id):
    if not isinstance(model_id, six.string_types):
        raise TypeError('Model ID must be a string.')
    if not re.match(r'^[A-Za-z0-9_-]{1,60}$', model_id):
        raise ValueError('Model ID format is invalid.')


class _MLKitService(object):
    """Firebase MLKit service."""

    PROJECT_URL = 'https://mlkit.googleapis.com/v1beta1/projects/{0}/'

    def __init__(self, app):
        project_id = app.project_id
        if not project_id:
            raise ValueError(
                'Project ID is required to access MLKit service. Either set the '
                'projectId option, or use service account credentials.')
        self._project_url = _MLKitService.PROJECT_URL.format(project_id)
        self._client = _http_client.JsonHttpClient(
            credential=app.credential.get_credential(),
            base_url=self._project_url)

    def get_model(self, model_id):
        _validate_model_id(model_id)
        try:
            return self._client.body('get', url='models/{0}'.format(model_id))
        except requests.exceptions.RequestException as error:
            raise _utils.handle_platform_error_from_requests(error)

    def delete_model(self, model_id):
        _validate_model_id(model_id)
        try:
            self._client.body('delete', url='models/{0}'.format(model_id))
        except requests.exceptions.RequestException as error:
            raise _utils.handle_platform_error_from_requests(error)
