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
_MAX_PAGE_SIZE = 100


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


def list_models(list_filter=None, page_size=None, page_token=None, app=None):
    mlkit_service = _get_mlkit_service(app)
    return ListModelsPage(
        mlkit_service.list_models, list_filter, page_size, page_token)


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

    @property
    def name(self):
        return self._data['name']

    @property
    def display_name(self):
        return self._data['displayName']

    #TODO(ifielker): define the rest of the Model properties etc


class ListModelsPage(object):
    """Represents a page of models in a firebase project.

    Provides methods for traversing the models included in this page, as well as
    retrieving subsequent pages of models. The iterator returned by
    ``iterate_all()`` can be used to iterate through all the models in the
    Firebase project starting from this page.
    """
    def __init__(self, list_models_func, list_filter, page_size, page_token):
        self._list_models_func = list_models_func
        self._list_filter = list_filter
        self._page_size = page_size
        self._page_token = page_token
        self._list_response = list_models_func(list_filter, page_size, page_token)

    @property
    def models(self):
        """A list of Models from this page."""
        return [Model(model) for model in self._list_response.get('models', [])]

    @property
    def list_filter(self):
        """The filter string used to filter the models."""
        return self._list_filter

    @property
    def next_page_token(self):
        return self._list_response.get('nextPageToken', '')

    @property
    def has_next_page(self):
        """A boolean indicating whether more pages are available."""
        return bool(self.next_page_token)

    def get_next_page(self):
        """Retrieves the next page of models if available.

        Returns:
            ListModelsPage: Next page of models, or None if this is the last page.
        """
        if self.has_next_page:
            return ListModelsPage(
                self._list_models_func,
                self._list_filter,
                self._page_size,
                self.next_page_token)
        return None

    def iterate_all(self):
        """Retrieves an iterator for Models.

        Returned iterator will iterate through all the models in the Firebase
        project starting from this page. The iterator will never buffer more than
        one page of models in memory at a time.

        Returns:
            iterator: An iterator of Model instances.
        """
        return _ModelIterator(self)


class _ModelIterator(object):
    """An iterator that allows iterating over models, one at a time.

    This implementation loads a page of models into memory, and iterates on them.
    When the whole page has been traversed, it loads another page. This class
    never keeps more than one page of entries in memory.
    """
    def __init__(self, current_page):
        if not isinstance(current_page, ListModelsPage):
            raise TypeError('Current page must be a ListModelsPage')
        self._current_page = current_page
        self._index = 0

    def next(self):
        if self._index == len(self._current_page.models):
            if self._current_page.has_next_page:
                self._current_page = self._current_page.get_next_page()
                self._index = 0
        if self._index < len(self._current_page.models):
            result = self._current_page.models[self._index]
            self._index += 1
            return result
        raise StopIteration

    def __next__(self):
        return self.next()

    def __iter__(self):
        return self


def _validate_model_id(model_id):
    if not isinstance(model_id, six.string_types):
        raise TypeError('Model ID must be a string.')
    if not re.match(r'^[A-Za-z0-9_-]{1,60}$', model_id):
        raise ValueError('Model ID format is invalid.')


def _validate_list_filter(list_filter):
    if list_filter is not None:
        if not isinstance(list_filter, six.string_types):
            raise TypeError('List filter must be a string or None.')


def _validate_page_size(page_size):
    if page_size is not None:
        if type(page_size) is not int: # pylint: disable=unidiomatic-typecheck
            # Specifically type() to disallow boolean which is a subtype of int
            raise TypeError('Page size must be a number or None.')
        if page_size < 1 or page_size > _MAX_PAGE_SIZE:
            raise ValueError('Page size must be a positive integer between '
                             '1 and {0}'.format(_MAX_PAGE_SIZE))


def _validate_page_token(page_token):
    if page_token is not None:
        if not isinstance(page_token, six.string_types):
            raise TypeError('Page token must be a string or None.')


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

    def list_models(self, list_filter, page_size, page_token):
        """ lists Firebase ML Kit models."""
        _validate_list_filter(list_filter)
        _validate_page_size(page_size)
        _validate_page_token(page_token)
        payload = {}
        if list_filter:
            payload['list_filter'] = list_filter
        if page_size:
            payload['page_size'] = page_size
        if page_token:
            payload['page_token'] = page_token
        try:
            return self._client.body('get', url='models', json=payload)
        except requests.exceptions.RequestException as error:
            raise _utils.handle_platform_error_from_requests(error)

    def delete_model(self, model_id):
        _validate_model_id(model_id)
        try:
            self._client.body('delete', url='models/{0}'.format(model_id))
        except requests.exceptions.RequestException as error:
            raise _utils.handle_platform_error_from_requests(error)
