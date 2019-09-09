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
import time
import requests
import six


from firebase_admin import _http_client
from firebase_admin import _utils
from firebase_admin import exceptions


_MLKIT_ATTRIBUTE = '_mlkit'
_MAX_PAGE_SIZE = 100
_MODEL_ID_PATTERN = re.compile(r'^[A-Za-z0-9_-]{1,60}$')
_DISPLAY_NAME_PATTERN = re.compile(r'^[A-Za-z0-9_-]{1,60}$')
_TAG_PATTERN = re.compile(r'^[A-Za-z0-9_-]{1,60}$')
_GCS_TFLITE_URI_PATTERN = re.compile(r'^gs://[a-z0-9_.-]{3,63}/.+')
_RESOURCE_NAME_PATTERN = re.compile(
    r'^projects/(?P<project_id>[^/]+)/models/(?P<model_id>[A-Za-z0-9_-]{1,60})$')
_OPERATION_NAME_PATTERN = re.compile(
    r'^operations/project/(?P<project_id>[^/]+)/model/(?P<model_id>[A-Za-z0-9_-]{1,60})' +
    r'/operation/[^/]+$')


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


def create_model(model, app=None):
    """Creates a model in Firebase ML Kit.

    Args:
        model: An mlkit.Model to create.
        app: A Firebase app instance (or None to use the default app).

    Returns:
        Model: The model that was created in Firebase ML Kit.
    """
    mlkit_service = _get_mlkit_service(app)
    return Model.from_dict(mlkit_service.create_model(model), app=app)


def get_model(model_id, app=None):
    """Gets a model from Firebase ML Kit.

    Args:
        model_id: The id of the model to get.
        app: A Firebase app instance (or None to use the default app).

    Returns:
     Model: The requested model.
    """
    mlkit_service = _get_mlkit_service(app)
    return Model.from_dict(mlkit_service.get_model(model_id), app=app)


def list_models(list_filter=None, page_size=None, page_token=None, app=None):
    """Lists models from Firebase ML Kit.

    Args:
        list_filter: a list filter string such as "tags:'tag_1'". None will return all models.
        page_size: A number between 1 and 100 inclusive that specifies the maximum
            number of models to return per page. None for default.
        page_token: A next page token returned from a previous page of results. None
            for first page of results.
        app: A Firebase app instance (or None to use the default app).

    Returns:
        ListModelsPage: A (filtered) list of models.
    """
    mlkit_service = _get_mlkit_service(app)
    return ListModelsPage(
        mlkit_service.list_models, list_filter, page_size, page_token, app=app)


def delete_model(model_id, app=None):
    """Deletes a model from Firebase ML Kit.

    Args:
        model_id: The id of the model you wish to delete.
        app: A Firebase app instance (or None to use the default app).
    """
    mlkit_service = _get_mlkit_service(app)
    mlkit_service.delete_model(model_id)


class Model(object):
    """A Firebase ML Kit Model object.

    Args:
        display_name: The display name of your model - used to identify your model in code.
        tags: Optional list of strings associated with your model. Can be used in list queries.
        model_format: A subclass of ModelFormat. (e.g. TFLiteFormat) Specifies the model details.
    """
    def __init__(self, display_name=None, tags=None, model_format=None):
        self._app = None  # Only needed for wait_for_unlo
        self._data = {}
        self._model_format = None

        if display_name is not None:
            self.display_name = display_name
        if tags is not None:
            self.tags = tags
        if model_format is not None:
            self.model_format = model_format

    @classmethod
    def from_dict(cls, data, app=None):
        data_copy = dict(data)
        tflite_format = None
        tflite_format_data = data_copy.pop('tfliteModel', None)
        if tflite_format_data:
            tflite_format = TFLiteFormat.from_dict(tflite_format_data)
        model = Model(model_format=tflite_format)
        model._data = data_copy  # pylint: disable=protected-access
        model._app = app # pylint: disable=protected-access
        return model

    def _update_from_dict(self, data):
        data_copy = dict(data)
        tflite_format = None
        tflite_format_data = data_copy.pop('tfliteModel', None)
        if tflite_format_data:
            tflite_format = TFLiteFormat.from_dict(tflite_format_data)
        self.model_format = tflite_format
        self._data = data_copy

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            # pylint: disable=protected-access
            return self._data == other._data and self._model_format == other._model_format
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
        """Returns the creation timestamp"""
        seconds = self._data.get('createTime', {}).get('seconds')
        if not isinstance(seconds, numbers.Number):
            return None

        return datetime.datetime.fromtimestamp(float(seconds))

    @property
    def update_time(self):
        """Returns the last update timestamp"""
        seconds = self._data.get('updateTime', {}).get('seconds')
        if not isinstance(seconds, numbers.Number):
            return None

        return datetime.datetime.fromtimestamp(float(seconds))

    @property
    def validation_error(self):
        return self._data.get('state', {}).get('validationError', {}).get('message')

    @property
    def published(self):
        return bool(self._data.get('state', {}).get('published'))

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

    def wait_for_unlocked(self, max_time_seconds=None):
        if self.locked:
            mlkit_service = _get_mlkit_service(self._app)
            op_name = self._data.get('activeOperations')[0].get('name')
            model_dict = mlkit_service.handle_operation(
                mlkit_service.get_operation(op_name),
                max_time_seconds=max_time_seconds)
            self._update_from_dict(model_dict)

    @property
    def model_format(self):
        return self._model_format

    @model_format.setter
    def model_format(self, model_format):
        if model_format is not None:
            _validate_model_format(model_format)
        self._model_format = model_format  #Can be None
        return self

    def as_dict(self):
        copy = dict(self._data)
        if self._model_format:
            copy.update(self._model_format.as_dict())
        return copy


class ModelFormat(object):
    """Abstract base class representing a Model Format such as TFLite."""
    def as_dict(self):
        raise NotImplementedError


class TFLiteFormat(ModelFormat):
    """Model format representing a TFLite model.

    Args:
        model_source: A TFLiteModelSource sub class. Specifies the details of the model source.
    """
    def __init__(self, model_source=None):
        self._data = {}
        self._model_source = None

        if model_source is not None:
            self.model_source = model_source

    @classmethod
    def from_dict(cls, data):
        data_copy = dict(data)
        model_source = None
        gcs_tflite_uri = data_copy.pop('gcsTfliteUri', None)
        if gcs_tflite_uri:
            model_source = TFLiteGCSModelSource(gcs_tflite_uri=gcs_tflite_uri)
        tflite_format = TFLiteFormat(model_source=model_source)
        tflite_format._data = data_copy # pylint: disable=protected-access
        return tflite_format


    def __eq__(self, other):
        if isinstance(other, self.__class__):
            # pylint: disable=protected-access
            return self._data == other._data and self._model_source == other._model_source
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def model_source(self):
        return self._model_source

    @model_source.setter
    def model_source(self, model_source):
        if model_source is not None:
            if not isinstance(model_source, TFLiteModelSource):
                raise TypeError('Model source must be a TFLiteModelSource object.')
        self._model_source = model_source # Can be None

    @property
    def size_bytes(self):
        return self._data.get('sizeBytes')

    def as_dict(self):
        copy = dict(self._data)
        if self._model_source:
            copy.update(self._model_source.as_dict())
        return {'tfliteModel': copy}


class TFLiteModelSource(object):
    """Abstract base class representing a model source for TFLite format models."""
    def as_dict(self):
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

    def as_dict(self):
        return {"gcsTfliteUri": self._gcs_tflite_uri}

    #TODO(ifielker): implement from_saved_model etc.


class ListModelsPage(object):
    """Represents a page of models in a firebase project.

    Provides methods for traversing the models included in this page, as well as
    retrieving subsequent pages of models. The iterator returned by
    ``iterate_all()`` can be used to iterate through all the models in the
    Firebase project starting from this page.
    """
    def __init__(self, list_models_func, list_filter, page_size, page_token, app):
        self._list_models_func = list_models_func
        self._list_filter = list_filter
        self._page_size = page_size
        self._page_token = page_token
        self._app = app
        self._list_response = list_models_func(list_filter, page_size, page_token)

    @property
    def models(self):
        """A list of Models from this page."""
        return [
            Model.from_dict(model, app=self._app) for model in self._list_response.get('models', [])
        ]

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
                self.next_page_token,
                self._app)
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
    matcher = _RESOURCE_NAME_PATTERN.match(name)
    if not matcher:
        raise ValueError('Model resource name format is invalid.')
    return matcher.group('project_id'), matcher.group('model_id')


def _validate_model(model):
    if not isinstance(model, Model):
        raise TypeError('Model must be an mlkit.Model.')
    if not model.display_name:
        raise ValueError('Model must have a display name.')


def _validate_model_id(model_id):
    if not _MODEL_ID_PATTERN.match(model_id):
        raise ValueError('Model ID format is invalid.')


def _validate_and_parse_operation_name(op_name):
    matcher = _OPERATION_NAME_PATTERN.match(op_name)
    if not matcher:
        raise ValueError('Operation name format is invalid.')
    return matcher.group('project_id'), matcher.group('model_id')


def _validate_display_name(display_name):
    if not _DISPLAY_NAME_PATTERN.match(display_name):
        raise ValueError('Display name format is invalid.')
    return display_name


def _validate_tags(tags):
    if not isinstance(tags, list) or not \
        all(isinstance(tag, six.string_types) for tag in tags):
        raise TypeError('Tags must be a list of strings.')
    if not all(_TAG_PATTERN.match(tag) for tag in tags):
        raise ValueError('Tag format is invalid.')
    return tags


def _validate_gcs_tflite_uri(uri):
    # GCS Bucket naming rules are complex. The regex is not comprehensive.
    # See https://cloud.google.com/storage/docs/naming for full details.
    if not _GCS_TFLITE_URI_PATTERN.match(uri):
        raise ValueError('GCS TFLite URI format is invalid.')
    return uri


def _validate_model_format(model_format):
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
    OPERATION_URL = 'https://mlkit.googleapis.com/v1beta1/'
    POLL_EXPONENTIAL_BACKOFF_FACTOR = 1.5
    POLL_BASE_WAIT_TIME_SECONDS = 3

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
        self._operation_client = _http_client.JsonHttpClient(
            credential=app.credential.get_credential(),
            base_url=_MLKitService.OPERATION_URL)

    def get_operation(self, op_name):
        _validate_and_parse_operation_name(op_name)
        try:
            return self._operation_client.body('get', url=op_name)
        except requests.exceptions.RequestException as error:
            raise _utils.handle_platform_error_from_requests(error)

    def handle_operation(self, operation, max_polling_attempts=None, max_time_seconds=None,
                         always_return_model=False):
        """Handles long running operations.

        Args:
            operation: The operation to handle.
            max_polling_attempts: The maximum number of polling requests to make.
                (None for no limit)
            max_time_seconds: The maximum seconds to try polling for operation complete.
                (None for no limit)
            always_return_model: If true, returns a locked Model instead of raising deadline
                exceeded exceptions.

        Returns:
            dict: A dictionary of the returned model properties.

        Raises:
            TypeError: if the operation is not a dictionary.
            ValueError: If the operation is malformed.
        """
        if not isinstance(operation, dict):
            raise TypeError('Operation must be a dictionary.')
        op_name = operation.get('name')
        _, model_id = _validate_and_parse_operation_name(op_name)

        current_attempt = 0
        start_time = datetime.datetime.now()
        stop_time = (None if max_time_seconds is None else
                     start_time + datetime.timedelta(seconds=max_time_seconds))
        while True:
            if operation.get('done'):
                if operation.get('response'):
                    return operation.get('response')
                elif operation.get('error'):
                    raise _utils.handle_operation_error(operation.get('error'))
                else:
                    # A 'done' operation must have either a response or an error.
                    raise ValueError('Operation is malformed.')
            else:
                # We just got this operation. Wait before getting another
                # so we don't exceed the GetOperation maximum request rate.
                if max_polling_attempts is not None and current_attempt >= max_polling_attempts:
                    if always_return_model:
                        return get_model(model_id).as_dict()
                    raise exceptions.DeadlineExceededError('Polling max attempts exceeded.')
                delay_factor = pow(
                    _MLKitService.POLL_EXPONENTIAL_BACKOFF_FACTOR, current_attempt)
                wait_time_seconds = delay_factor * _MLKitService.POLL_BASE_WAIT_TIME_SECONDS
                after_sleep_time = (datetime.datetime.now() +
                                    datetime.timedelta(seconds=wait_time_seconds))
                if stop_time is not None and after_sleep_time > stop_time:
                    if always_return_model:
                        return get_model(model_id).as_dict()
                    raise exceptions.DeadlineExceededError('Polling max time exceeded.')
                time.sleep(wait_time_seconds)
                operation = self.get_operation(op_name)
                current_attempt += 1


    def create_model(self, model):
        _validate_model(model)
        try:
            return self.handle_operation(
                self._client.body('post', url='models', json=model.as_dict()),
                max_polling_attempts=1,
                always_return_model=True)
        except requests.exceptions.RequestException as error:
            raise _utils.handle_platform_error_from_requests(error)

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
