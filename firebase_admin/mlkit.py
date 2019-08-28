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

import datetime
import numbers
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
    return Model(**mlkit_service.get_model(model_id))


def list_models(list_filter=None, page_size=None, page_token=None, app=None):
    mlkit_service = _get_mlkit_service(app)
    return ListModelsPage(
        mlkit_service.list_models, list_filter, page_size, page_token)


def delete_model(model_id, app=None):
    mlkit_service = _get_mlkit_service(app)
    mlkit_service.delete_model(model_id)


class Model(object):
    """A Firebase ML Kit Model object."""
    def __init__(self, display_name=None, tags=None, model_format=None, **kwargs):
        self._data = kwargs
        if display_name is not None:
            self._data['displayName'] = _validate_display_name(display_name)
        if tags is not None:
            self._data['tags'] = _validate_tags(tags)
        if model_format is not None:
            _validate_model_format(model_format)
            if isinstance(model_format, TFLiteFormat):
                self._data['tfliteModel'] = model_format.get_json()
            else:
                raise TypeError('Unsupported model format type.')


    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self._data == other._data # pylint: disable=protected-access
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def model_id(self):
        if not self._data.get('name'):
            return None
        _, model_id = _validate_and_parse_name(self._data.get('name'))
        return model_id

    @property
    def display_name(self):
        return self._data.get('displayName')

    @display_name.setter
    def display_name(self, display_name):
        self._data['displayName'] = _validate_display_name(display_name)
        return self

    @property
    def create_time(self):
        create_time = self._data.get('createTime')
        if not create_time:
            return None

        seconds = create_time.get('seconds')
        if not seconds:
            return None
        if not isinstance(seconds, numbers.Number):
            return None

        return datetime.datetime.fromtimestamp(float(seconds))

    @property
    def update_time(self):
        update_time = self._data.get('updateTime')
        if not update_time:
            return None

        seconds = update_time.get('seconds')
        if not seconds:
            return None
        if not isinstance(seconds, numbers.Number):
            return None

        return datetime.datetime.fromtimestamp(float(seconds))

    @property
    def validation_error(self):
        return self._data.get('state') and \
               self._data.get('state').get('validationError') and \
               self._data.get('state').get('validationError').get('message')

    @property
    def published(self):
        return bool(self._data.get('state') and
                    self._data.get('state').get('published'))

    @property
    def etag(self):
        return self._data.get('etag')

    @property
    def model_hash(self):
        return self._data.get('modelHash')

    @property
    def tags(self):
        return self._data.get('tags')

    @tags.setter
    def tags(self, tags):
        self._data['tags'] = _validate_tags(tags)
        return self

    @property
    def locked(self):
        return bool(self._data.get('activeOperations') and
                    len(self._data.get('activeOperations')) > 0)

    @property
    def model_format(self):
        if self._data.get('tfliteModel'):
            return TFLiteFormat(**self._data.get('tfliteModel'))
        return None

    @model_format.setter
    def model_format(self, model_format):
        if not isinstance(model_format, TFLiteFormat):
            raise TypeError('Unsupported model format type.')
        self._data['tfliteModel'] = model_format.get_json()
        return self

    def get_json(self):
        return self._data


class ModelFormat(object):
    """Abstract base class representing a Model Format such as TFLite."""
    def get_json(self):
        raise NotImplementedError


class TFLiteFormat(ModelFormat):
    """Model format representing a TFLite model."""
    def __init__(self, model_source=None, **kwargs):
        self._data = kwargs
        if model_source is not None:
            # Check for correct base type
            if not isinstance(model_source, TFLiteModelSource):
                raise TypeError('Model source must be a ModelSource object.')
            # Set based on specific sub type
            if isinstance(model_source, TFLiteGCSModelSource):
                self._data['gcsTfliteUri'] = model_source.get_json()
            else:
                raise TypeError('Unsupported model source type.')

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self._data == other._data # pylint: disable=protected-access
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def model_source(self):
        if self._data.get('gcsTfliteUri'):
            return TFLiteGCSModelSource(self._data.get('gcsTfliteUri'))
        return None

    @model_source.setter
    def model_source(self, model_source):
        if model_source is not None:
            if isinstance(model_source, TFLiteGCSModelSource):
                self._data['gcsTfliteUri'] = model_source.get_json()
            else:
                raise TypeError('Unsupported model source type.')

    @property
    def size_bytes(self):
        return self._data.get('sizeBytes')

    def get_json(self):
        return self._data


class TFLiteModelSource(object):
    """Abstract base class representing a model source for TFLite format models."""
    def get_json(self):
        raise NotImplementedError


class TFLiteGCSModelSource(TFLiteModelSource):
    """TFLite model source representing a tflite model file stored in GCS."""
    def __init__(self, gcs_tflite_uri):
        self._gcs_tflite_uri = _validate_gcs_tflite_uri(gcs_tflite_uri)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self._gcs_tflite_uri == other._gcs_tflite_uri # pylint: disable=protected-access
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def gcs_tflite_uri(self):
        return self._gcs_tflite_uri

    @gcs_tflite_uri.setter
    def gcs_tflite_uri(self, gcs_tflite_uri):
        self._gcs_tflite_uri = _validate_gcs_tflite_uri(gcs_tflite_uri)

    def get_json(self):
        return self._gcs_tflite_uri

    #TODO(ifielker): implement from_saved_model etc.


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
        return [Model(**model) for model in self._list_response.get('models', [])]

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


def _validate_and_parse_name(name):
    # The resource name is added automatically from API call responses.
    # The only way it could be invalid is if someone tries to
    # create a model from a dictionary manually and does it incorrectly.
    if not isinstance(name, six.string_types):
        raise TypeError('Model resource name must be a string.')
    matcher = re.match(
        r'^projects/(?P<project_id>[^/]+)/models/(?P<model_id>[A-Za-z0-9_-]{1,60})$',
        name)
    if not matcher:
        raise ValueError('Model resource name format is invalid.')
    return matcher.group('project_id'), matcher.group('model_id')


def _validate_model_id(model_id):
    if not isinstance(model_id, six.string_types):
        raise TypeError('Model ID must be a string.')
    if not re.match(r'^[A-Za-z0-9_-]{1,60}$', model_id):
        raise ValueError('Model ID format is invalid.')


def _validate_display_name(display_name):
    if not re.match(r'^[A-Za-z0-9_-]{1,60}$', display_name):
        raise ValueError('Display name format is invalid.')
    return display_name


def _validate_tags(tags):
    if not isinstance(tags, list) or not \
        all(isinstance(tag, six.string_types) for tag in tags):
        raise TypeError('Tags must be a list of strings.')
    if not all(re.match(r'^[A-Za-z0-9_-]{1,60}$', tag) for tag in tags):
        raise ValueError('Tag format is invalid.')
    return tags


def _validate_gcs_tflite_uri(uri):
    # GCS Bucket naming rules are complex. The regex is not comprehensive.
    # See https://cloud.google.com/storage/docs/naming for full details.
    if not re.match(r'^gs://[a-z0-9_.-]{3,63}/.+', uri):
        raise ValueError('GCS TFLite URI format is invalid.')
    return uri

def _validate_model_format(model_format):
    if model_format is not None:
        if not isinstance(model_format, ModelFormat):
            raise TypeError('Model format must be a ModelFormat object.')
    return model_format

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
