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

"""Test cases for the firebase_admin.mlkit module."""

import datetime
import json
import pytest

import firebase_admin
from firebase_admin import exceptions
from firebase_admin import mlkit
from tests import testutils

BASE_URL = 'https://mlkit.googleapis.com/v1beta1/'

PROJECT_ID = 'myProject1'
PAGE_TOKEN = 'pageToken'
NEXT_PAGE_TOKEN = 'nextPageToken'
CREATE_TIME_SECONDS = 1566426374
CREATE_TIME_JSON = {
    'seconds': CREATE_TIME_SECONDS
}
CREATE_TIME_DATETIME = datetime.datetime.fromtimestamp(CREATE_TIME_SECONDS)

UPDATE_TIME_SECONDS = 1566426678
UPDATE_TIME_JSON = {
    'seconds': UPDATE_TIME_SECONDS
}
UPDATE_TIME_DATETIME = datetime.datetime.fromtimestamp(UPDATE_TIME_SECONDS)
ETAG = '33a64df551425fcc55e4d42a148795d9f25f89d4'
MODEL_HASH = '987987a98b98798d098098e09809fc0893897'
TAG_1 = 'Tag1'
TAG_2 = 'Tag2'
TAG_3 = 'Tag3'
TAGS = [TAG_1, TAG_2]
TAGS_2 = [TAG_1, TAG_3]

MODEL_ID_1 = 'modelId1'
MODEL_NAME_1 = 'projects/{0}/models/{1}'.format(PROJECT_ID, MODEL_ID_1)
DISPLAY_NAME_1 = 'displayName1'
MODEL_JSON_1 = {
    'name': MODEL_NAME_1,
    'displayName': DISPLAY_NAME_1
}
MODEL_1 = mlkit.Model(**MODEL_JSON_1)

MODEL_ID_2 = 'modelId2'
MODEL_NAME_2 = 'projects/{0}/models/{1}'.format(PROJECT_ID, MODEL_ID_2)
DISPLAY_NAME_2 = 'displayName2'
MODEL_JSON_2 = {
    'name': MODEL_NAME_2,
    'displayName': DISPLAY_NAME_2
}
MODEL_2 = mlkit.Model(**MODEL_JSON_2)

MODEL_ID_3 = 'modelId3'
MODEL_NAME_3 = 'projects/{0}/models/{1}'.format(PROJECT_ID, MODEL_ID_3)
DISPLAY_NAME_3 = 'displayName3'
MODEL_JSON_3 = {
    'name': MODEL_NAME_3,
    'displayName': DISPLAY_NAME_3
}
MODEL_3 = mlkit.Model(**MODEL_JSON_3)

MODEL_STATE_PUBLISHED_JSON = {
    'published': True
}
VALIDATION_ERROR_CODE = 400
VALIDATION_ERROR_MSG = 'No model format found for {0}.'.format(MODEL_ID_1)
MODEL_STATE_ERROR_JSON = {
    'validationError': {
        'code': VALIDATION_ERROR_CODE,
        'message': VALIDATION_ERROR_MSG,
    }
}

OPERATION_NOT_DONE_JSON_1 = {
    'name': 'operations/project/{0}/model/{1}/operation/123'.format(PROJECT_ID, MODEL_ID_1),
    'metadata': {
        '@type': 'type.googleapis.com/google.firebase.ml.v1beta1.ModelOperationMetadata',
        'name': 'projects/{0}/models/{1}'.format(PROJECT_ID, MODEL_ID_1),
        'basic_operation_status': 'BASIC_OPERATION_STATUS_UPLOADING'
    }
}

GCS_TFLITE_URI = 'gs://my_bucket/mymodel.tflite'
GCS_TFLITE_MODEL_SOURCE = mlkit.TFLiteGCSModelSource(GCS_TFLITE_URI)
TFLITE_FORMAT_JSON = {
    'gcsTfliteUri': GCS_TFLITE_URI,
    'sizeBytes': '1234567'
}
TFLITE_FORMAT = mlkit.TFLiteFormat(**TFLITE_FORMAT_JSON)

GCS_TFLITE_URI_2 = 'gs://my_bucket/mymodel2.tflite'
GCS_TFLITE_MODEL_SOURCE_2 = mlkit.TFLiteGCSModelSource(GCS_TFLITE_URI_2)
TFLITE_FORMAT_JSON_2 = {
    'gcsTfliteUri': GCS_TFLITE_URI_2,
    'sizeBytes': '2345678'
}
TFLITE_FORMAT_2 = mlkit.TFLiteFormat(**TFLITE_FORMAT_JSON_2)

FULL_MODEL_ERR_STATE_LRO_JSON = {
    'name': MODEL_NAME_1,
    'displayName': DISPLAY_NAME_1,
    'createTime': CREATE_TIME_JSON,
    'updateTime': UPDATE_TIME_JSON,
    'state': MODEL_STATE_ERROR_JSON,
    'etag': ETAG,
    'modelHash': MODEL_HASH,
    'tags': TAGS,
    'activeOperations': [OPERATION_NOT_DONE_JSON_1],
}
FULL_MODEL_PUBLISHED_JSON = {
    'name': MODEL_NAME_1,
    'displayName': DISPLAY_NAME_1,
    'createTime': CREATE_TIME_JSON,
    'updateTime': UPDATE_TIME_JSON,
    'state': MODEL_STATE_PUBLISHED_JSON,
    'etag': ETAG,
    'modelHash': MODEL_HASH,
    'tags': TAGS,
    'tfliteModel': TFLITE_FORMAT_JSON
}

EMPTY_RESPONSE = json.dumps({})
DEFAULT_GET_RESPONSE = json.dumps(MODEL_JSON_1)
NO_MODELS_LIST_RESPONSE = json.dumps({})
DEFAULT_LIST_RESPONSE = json.dumps({
    'models': [MODEL_JSON_1, MODEL_JSON_2],
    'nextPageToken': NEXT_PAGE_TOKEN
})
LAST_PAGE_LIST_RESPONSE = json.dumps({
    'models': [MODEL_JSON_3]
})
ONE_PAGE_LIST_RESPONSE = json.dumps({
    'models': [MODEL_JSON_1, MODEL_JSON_2, MODEL_JSON_3],
})

ERROR_CODE_NOT_FOUND = 404
ERROR_MSG_NOT_FOUND = 'The resource was not found'
ERROR_STATUS_NOT_FOUND = 'NOT_FOUND'
ERROR_JSON_NOT_FOUND = {
    'error': {
        'code': ERROR_CODE_NOT_FOUND,
        'message': ERROR_MSG_NOT_FOUND,
        'status': ERROR_STATUS_NOT_FOUND
    }
}
ERROR_RESPONSE_NOT_FOUND = json.dumps(ERROR_JSON_NOT_FOUND)

ERROR_CODE_BAD_REQUEST = 400
ERROR_MSG_BAD_REQUEST = 'Invalid Argument'
ERROR_STATUS_BAD_REQUEST = 'INVALID_ARGUMENT'
ERROR_JSON_BAD_REQUEST = {
    'error': {
        'code': ERROR_CODE_BAD_REQUEST,
        'message': ERROR_MSG_BAD_REQUEST,
        'status': ERROR_STATUS_BAD_REQUEST
    }
}
ERROR_RESPONSE_BAD_REQUEST = json.dumps(ERROR_JSON_BAD_REQUEST)

invalid_display_name_args = [
    ('', ValueError, 'Display name format is invalid.'),
    ('&_*#@:/?', ValueError, 'Display name format is invalid.'),
    (12345, TypeError, 'expected string or buffer')
]
invalid_tags_args = [
    ('tag1', TypeError, 'Tags must be a list of strings.'),
    (123, TypeError, 'Tags must be a list of strings.'),
    (['tag1', 123, 'tag2'], TypeError, 'Tags must be a list of strings.'),
    (['tag1', '@#$%^&'], ValueError, 'Tag format is invalid.'),
    (['', 'tag2'], ValueError, 'Tag format is invalid.'),
    (['sixty-one_characters_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
      'tag2'], ValueError, 'Tag format is invalid.')
]
invalid_model_format_args = [
    (123, 'Model format must be a ModelFormat object.'),
    (mlkit.ModelFormat(), 'Unsupported model format type.')
]
invalid_model_source_args = [
    (123, 'Model source must be a ModelSource object.'),
    (mlkit.TFLiteModelSource(), 'Unsupported model source type.'),

]
GCS_TFLITE_VALUE_ERR_MSG = 'GCS TFLite URI format is invalid.'
invalid_gcs_tflite_uri_args = [
    (123, TypeError, 'expected string or buffer'),
    ('abc', ValueError, GCS_TFLITE_VALUE_ERR_MSG),
    ('gs://NO_CAPITALS', ValueError, GCS_TFLITE_VALUE_ERR_MSG),
    ('gs://abc/', ValueError, GCS_TFLITE_VALUE_ERR_MSG),
    ('gs://aa/model.tflite', ValueError, GCS_TFLITE_VALUE_ERR_MSG),
    ('gs://@#$%/model.tflite', ValueError, GCS_TFLITE_VALUE_ERR_MSG),
    ('gs://invalid space/model.tflite', ValueError, GCS_TFLITE_VALUE_ERR_MSG),
    ('gs://sixty-four-characters_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/model.tflite',
     ValueError, GCS_TFLITE_VALUE_ERR_MSG)
]
invalid_model_id_args = [
    ('', ValueError, 'Model ID format is invalid.'),
    ('&_*#@:/?', ValueError, 'Model ID format is invalid.'),
    (None, TypeError, 'Model ID must be a string.'),
    (12345, TypeError, 'Model ID must be a string.'),
]
PAGE_SIZE_VALUE_ERROR_MSG = 'Page size must be a positive integer between ' \
                            '1 and {0}'.format(mlkit._MAX_PAGE_SIZE)
invalid_page_size_args = [
    ('abc', TypeError, 'Page size must be a number or None.'),
    (4.2, TypeError, 'Page size must be a number or None.'),
    (list(), TypeError, 'Page size must be a number or None.'),
    (dict(), TypeError, 'Page size must be a number or None.'),
    (True, TypeError, 'Page size must be a number or None.'),
    (-1, ValueError, PAGE_SIZE_VALUE_ERROR_MSG),
    (0, ValueError, PAGE_SIZE_VALUE_ERROR_MSG),
    (mlkit._MAX_PAGE_SIZE + 1, ValueError, PAGE_SIZE_VALUE_ERROR_MSG)
]
invalid_string_or_none_args = [0, -1, 4.2, 0x10, False, list(), dict()]


def check_error(err, err_type, msg):
    assert isinstance(err, err_type)
    assert str(err) == msg


def check_firebase_error(err, code, status, msg):
    assert isinstance(err, exceptions.FirebaseError)
    assert err.code == code
    assert err.http_response is not None
    assert err.http_response.status_code == status
    assert str(err) == msg


def instrument_mlkit_service(app=None, status=200, payload=None):
    if not app:
        app = firebase_admin.get_app()
    mlkit_service = mlkit._get_mlkit_service(app)
    recorder = []
    mlkit_service._client.session.mount(
        'https://mlkit.googleapis.com',
        testutils.MockAdapter(payload, status, recorder)
    )
    return recorder


class TestModel(object):
    """Tests mlkit.Model class."""

    def test_model_success_err_state_lro(self):
        model = mlkit.Model(**FULL_MODEL_ERR_STATE_LRO_JSON)
        assert model.model_id == MODEL_ID_1
        assert model.display_name == DISPLAY_NAME_1
        assert model.create_time == CREATE_TIME_DATETIME
        assert model.update_time == UPDATE_TIME_DATETIME
        assert model.validation_error == VALIDATION_ERROR_MSG
        assert model.published is False
        assert model.etag == ETAG
        assert model.model_hash == MODEL_HASH
        assert model.tags == TAGS
        assert model.locked is True
        assert model.model_format is None
        assert model.get_json() == FULL_MODEL_ERR_STATE_LRO_JSON

    def test_model_success_published(self):
        model = mlkit.Model(**FULL_MODEL_PUBLISHED_JSON)
        assert model.model_id == MODEL_ID_1
        assert model.display_name == DISPLAY_NAME_1
        assert model.create_time == CREATE_TIME_DATETIME
        assert model.update_time == UPDATE_TIME_DATETIME
        assert model.validation_error is None
        assert model.published is True
        assert model.etag == ETAG
        assert model.model_hash == MODEL_HASH
        assert model.tags == TAGS
        assert model.locked is False
        assert model.model_format == TFLITE_FORMAT
        assert model.get_json() == FULL_MODEL_PUBLISHED_JSON

    def test_model_keyword_based_creation_and_setters(self):
        model = mlkit.Model(display_name=DISPLAY_NAME_1, tags=TAGS, model_format=TFLITE_FORMAT)
        assert model.display_name == DISPLAY_NAME_1
        assert model.tags == TAGS
        assert model.model_format == TFLITE_FORMAT
        assert model.get_json() == {
            'displayName': DISPLAY_NAME_1,
            'tags': TAGS,
            'tfliteModel': TFLITE_FORMAT_JSON
        }

        model.display_name = DISPLAY_NAME_2
        model.tags = TAGS_2
        model.model_format = TFLITE_FORMAT_2
        assert model.get_json() == {
            'displayName': DISPLAY_NAME_2,
            'tags': TAGS_2,
            'tfliteModel': TFLITE_FORMAT_JSON_2
        }

    def test_model_format_source_creation(self):
        model_source = mlkit.TFLiteGCSModelSource(gcs_tflite_uri=GCS_TFLITE_URI)
        model_format = mlkit.TFLiteFormat(model_source=model_source)
        model = mlkit.Model(display_name=DISPLAY_NAME_1, model_format=model_format)
        assert model.get_json() == {
            'displayName': DISPLAY_NAME_1,
            'tfliteModel': {
                'gcsTfliteUri': GCS_TFLITE_URI
            }
        }

    def test_model_source_setters(self):
        model_source = mlkit.TFLiteGCSModelSource(GCS_TFLITE_URI)
        model_source.gcs_tflite_uri = GCS_TFLITE_URI_2
        assert model_source.gcs_tflite_uri == GCS_TFLITE_URI_2
        assert model_source.get_json() == GCS_TFLITE_URI_2

    def test_model_format_setters(self):
        model_format = mlkit.TFLiteFormat(model_source=GCS_TFLITE_MODEL_SOURCE)
        model_format.model_source = GCS_TFLITE_MODEL_SOURCE_2
        assert model_format.model_source == GCS_TFLITE_MODEL_SOURCE_2
        assert model_format.get_json() == {
            'gcsTfliteUri': GCS_TFLITE_URI_2
        }

    @pytest.mark.parametrize('display_name, exc_type, error_message', invalid_display_name_args)
    def test_model_display_name_validation_errors(self, display_name, exc_type, error_message):
        with pytest.raises(exc_type) as err:
            mlkit.Model(display_name=display_name)
        check_error(err.value, exc_type, error_message)

    @pytest.mark.parametrize('tags, exc_type, error_message', invalid_tags_args)
    def test_model_tags_validation_errors(self, tags, exc_type, error_message):
        with pytest.raises(exc_type) as err:
            mlkit.Model(tags=tags)
        check_error(err.value, exc_type, error_message)

    @pytest.mark.parametrize('model_format, error_message', invalid_model_format_args)
    def test_model_format_validation_errors(self, model_format, error_message):
        with pytest.raises(TypeError) as err:
            mlkit.Model(model_format=model_format)
        check_error(err.value, TypeError, error_message)

    @pytest.mark.parametrize('model_source, error_message', invalid_model_source_args)
    def test_model_source_validation_errors(self, model_source, error_message):
        with pytest.raises(TypeError) as err:
            mlkit.TFLiteFormat(model_source=model_source)
        check_error(err.value, TypeError, error_message)

    @pytest.mark.parametrize('uri, exc_type, error_message', invalid_gcs_tflite_uri_args)
    def test_gcs_tflite_source_validation_errors(self, uri, exc_type, error_message):
        with pytest.raises(exc_type) as err:
            mlkit.TFLiteGCSModelSource(gcs_tflite_uri=uri)
        check_error(err.value, exc_type, error_message)

class TestGetModel(object):
    """Tests mlkit.get_model."""
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    @staticmethod
    def _url(project_id, model_id):
        return BASE_URL + 'projects/{0}/models/{1}'.format(project_id, model_id)

    def test_get_model(self):
        recorder = instrument_mlkit_service(status=200, payload=DEFAULT_GET_RESPONSE)
        model = mlkit.get_model(MODEL_ID_1)
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == TestGetModel._url(PROJECT_ID, MODEL_ID_1)
        assert model == MODEL_1
        assert model.model_id == MODEL_ID_1
        assert model.display_name == DISPLAY_NAME_1

    @pytest.mark.parametrize('model_id, exc_type, error_message', invalid_model_id_args)
    def test_get_model_validation_errors(self, model_id, exc_type, error_message):
        with pytest.raises(exc_type) as err:
            mlkit.get_model(model_id)
        check_error(err.value, exc_type, error_message)

    def test_get_model_error(self):
        recorder = instrument_mlkit_service(status=404, payload=ERROR_RESPONSE_NOT_FOUND)
        with pytest.raises(exceptions.NotFoundError) as err:
            mlkit.get_model(MODEL_ID_1)
        check_firebase_error(
            err.value,
            ERROR_STATUS_NOT_FOUND,
            ERROR_CODE_NOT_FOUND,
            ERROR_MSG_NOT_FOUND
        )
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == TestGetModel._url(PROJECT_ID, MODEL_ID_1)

    def test_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
            with pytest.raises(ValueError):
                mlkit.get_model(MODEL_ID_1, app)
        testutils.run_without_project_id(evaluate)


class TestDeleteModel(object):
    """Tests mlkit.delete_model."""
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    @staticmethod
    def _url(project_id, model_id):
        return BASE_URL + 'projects/{0}/models/{1}'.format(project_id, model_id)

    def test_delete_model(self):
        recorder = instrument_mlkit_service(status=200, payload=EMPTY_RESPONSE)
        mlkit.delete_model(MODEL_ID_1) # no response for delete
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == TestDeleteModel._url(PROJECT_ID, MODEL_ID_1)

    @pytest.mark.parametrize('model_id, exc_type, error_message', invalid_model_id_args)
    def test_delete_model_validation_errors(self, model_id, exc_type, error_message):
        with pytest.raises(exc_type) as err:
            mlkit.delete_model(model_id)
        check_error(err.value, exc_type, error_message)

    def test_delete_model_error(self):
        recorder = instrument_mlkit_service(status=404, payload=ERROR_RESPONSE_NOT_FOUND)
        with pytest.raises(exceptions.NotFoundError) as err:
            mlkit.delete_model(MODEL_ID_1)
        check_firebase_error(
            err.value,
            ERROR_STATUS_NOT_FOUND,
            ERROR_CODE_NOT_FOUND,
            ERROR_MSG_NOT_FOUND
        )
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == self._url(PROJECT_ID, MODEL_ID_1)

    def test_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
            with pytest.raises(ValueError):
                mlkit.delete_model(MODEL_ID_1, app)
        testutils.run_without_project_id(evaluate)


class TestListModels(object):
    """Tests mlkit.list_models."""
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    @staticmethod
    def _url(project_id):
        return BASE_URL + 'projects/{0}/models'.format(project_id)

    @staticmethod
    def _check_page(page, model_count):
        assert isinstance(page, mlkit.ListModelsPage)
        assert len(page.models) == model_count
        for model in page.models:
            assert isinstance(model, mlkit.Model)

    def test_list_models_no_args(self):
        recorder = instrument_mlkit_service(status=200, payload=DEFAULT_LIST_RESPONSE)
        models_page = mlkit.list_models()
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == TestListModels._url(PROJECT_ID)
        TestListModels._check_page(models_page, 2)
        assert models_page.has_next_page
        assert models_page.next_page_token == NEXT_PAGE_TOKEN
        assert models_page.models[0] == MODEL_1
        assert models_page.models[1] == MODEL_2

    def test_list_models_with_all_args(self):
        recorder = instrument_mlkit_service(status=200, payload=LAST_PAGE_LIST_RESPONSE)
        models_page = mlkit.list_models(
            'display_name=displayName3',
            page_size=10,
            page_token=PAGE_TOKEN)
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == TestListModels._url(PROJECT_ID)
        assert json.loads(recorder[0].body.decode()) == {
            'list_filter': 'display_name=displayName3',
            'page_size': 10,
            'page_token': PAGE_TOKEN
        }
        assert isinstance(models_page, mlkit.ListModelsPage)
        assert len(models_page.models) == 1
        assert models_page.models[0] == MODEL_3
        assert not models_page.has_next_page

    @pytest.mark.parametrize('list_filter', invalid_string_or_none_args)
    def test_list_models_list_filter_validation(self, list_filter):
        with pytest.raises(TypeError) as err:
            mlkit.list_models(list_filter=list_filter)
        check_error(err.value, TypeError, 'List filter must be a string or None.')

    @pytest.mark.parametrize('page_size, exc_type, error_message', invalid_page_size_args)
    def test_list_models_page_size_validation(self, page_size, exc_type, error_message):
        with pytest.raises(exc_type) as err:
            mlkit.list_models(page_size=page_size)
        check_error(err.value, exc_type, error_message)

    @pytest.mark.parametrize('page_token', invalid_string_or_none_args)
    def test_list_models_page_token_validation(self, page_token):
        with pytest.raises(TypeError) as err:
            mlkit.list_models(page_token=page_token)
        check_error(err.value, TypeError, 'Page token must be a string or None.')

    def test_list_models_error(self):
        recorder = instrument_mlkit_service(status=400, payload=ERROR_RESPONSE_BAD_REQUEST)
        with pytest.raises(exceptions.InvalidArgumentError) as err:
            mlkit.list_models()
        check_firebase_error(
            err.value,
            ERROR_STATUS_BAD_REQUEST,
            ERROR_CODE_BAD_REQUEST,
            ERROR_MSG_BAD_REQUEST
        )
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == TestListModels._url(PROJECT_ID)

    def test_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
            with pytest.raises(ValueError):
                mlkit.list_models(app=app)
        testutils.run_without_project_id(evaluate)

    def test_list_single_page(self):
        recorder = instrument_mlkit_service(status=200, payload=LAST_PAGE_LIST_RESPONSE)
        models_page = mlkit.list_models()
        assert len(recorder) == 1
        assert models_page.next_page_token == ''
        assert models_page.has_next_page is False
        assert models_page.get_next_page() is None
        models = [model for model in models_page.iterate_all()]
        assert len(models) == 1

    def test_list_multiple_pages(self):
        # Page 1
        recorder = instrument_mlkit_service(status=200, payload=DEFAULT_LIST_RESPONSE)
        page = mlkit.list_models()
        assert len(recorder) == 1
        assert len(page.models) == 2
        assert page.next_page_token == NEXT_PAGE_TOKEN
        assert page.has_next_page is True

        # Page 2
        recorder = instrument_mlkit_service(status=200, payload=LAST_PAGE_LIST_RESPONSE)
        page_2 = page.get_next_page()
        assert len(recorder) == 1
        assert len(page_2.models) == 1
        assert page_2.next_page_token == ''
        assert page_2.has_next_page is False
        assert page_2.get_next_page() is None

    def test_list_models_paged_iteration(self):
        # Page 1
        recorder = instrument_mlkit_service(status=200, payload=DEFAULT_LIST_RESPONSE)
        page = mlkit.list_models()
        assert page.next_page_token == NEXT_PAGE_TOKEN
        assert page.has_next_page is True
        iterator = page.iterate_all()
        for index in range(2):
            model = next(iterator)
            assert model.display_name == 'displayName{0}'.format(index+1)
        assert len(recorder) == 1

        # Page 2
        recorder = instrument_mlkit_service(status=200, payload=LAST_PAGE_LIST_RESPONSE)
        model = next(iterator)
        assert model.display_name == DISPLAY_NAME_3
        with pytest.raises(StopIteration):
            next(iterator)

    def test_list_models_stop_iteration(self):
        recorder = instrument_mlkit_service(status=200, payload=ONE_PAGE_LIST_RESPONSE)
        page = mlkit.list_models()
        assert len(recorder) == 1
        assert len(page.models) == 3
        iterator = page.iterate_all()
        models = [model for model in iterator]
        assert len(page.models) == 3
        with pytest.raises(StopIteration):
            next(iterator)
        assert len(models) == 3

    def test_list_models_no_models(self):
        recorder = instrument_mlkit_service(status=200, payload=NO_MODELS_LIST_RESPONSE)
        page = mlkit.list_models()
        assert len(recorder) == 1
        assert len(page.models) == 0
        models = [model for model in page.iterate_all()]
        assert len(models) == 0
