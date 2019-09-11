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
CREATE_TIME_SECONDS_2 = 1566426385
CREATE_TIME_JSON = {
    'seconds': CREATE_TIME_SECONDS
}
CREATE_TIME_DATETIME = datetime.datetime.fromtimestamp(CREATE_TIME_SECONDS)
CREATE_TIME_JSON_2 = {
    'seconds': CREATE_TIME_SECONDS_2
}

UPDATE_TIME_SECONDS = 1566426678
UPDATE_TIME_SECONDS_2 = 1566426691
UPDATE_TIME_JSON = {
    'seconds': UPDATE_TIME_SECONDS
}
UPDATE_TIME_DATETIME = datetime.datetime.fromtimestamp(UPDATE_TIME_SECONDS)
UPDATE_TIME_JSON_2 = {
    'seconds': UPDATE_TIME_SECONDS_2
}
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
MODEL_1 = mlkit.Model.from_dict(MODEL_JSON_1)

MODEL_ID_2 = 'modelId2'
MODEL_NAME_2 = 'projects/{0}/models/{1}'.format(PROJECT_ID, MODEL_ID_2)
DISPLAY_NAME_2 = 'displayName2'
MODEL_JSON_2 = {
    'name': MODEL_NAME_2,
    'displayName': DISPLAY_NAME_2
}
MODEL_2 = mlkit.Model.from_dict(MODEL_JSON_2)

MODEL_ID_3 = 'modelId3'
MODEL_NAME_3 = 'projects/{0}/models/{1}'.format(PROJECT_ID, MODEL_ID_3)
DISPLAY_NAME_3 = 'displayName3'
MODEL_JSON_3 = {
    'name': MODEL_NAME_3,
    'displayName': DISPLAY_NAME_3
}
MODEL_3 = mlkit.Model.from_dict(MODEL_JSON_3)

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

OPERATION_NAME_1 = 'operations/project/{0}/model/{1}/operation/123'.format(PROJECT_ID, MODEL_ID_1)
OPERATION_NOT_DONE_JSON_1 = {
    'name': OPERATION_NAME_1,
    'metadata': {
        '@type': 'type.googleapis.com/google.firebase.ml.v1beta1.ModelOperationMetadata',
        'name': 'projects/{0}/models/{1}'.format(PROJECT_ID, MODEL_ID_1),
        'basic_operation_status': 'BASIC_OPERATION_STATUS_UPLOADING'
    }
}

GCS_TFLITE_URI = 'gs://my_bucket/mymodel.tflite'
GCS_TFLITE_URI_JSON = {'gcsTfliteUri': GCS_TFLITE_URI}
GCS_TFLITE_MODEL_SOURCE = mlkit.TFLiteGCSModelSource(GCS_TFLITE_URI)
TFLITE_FORMAT_JSON = {
    'gcsTfliteUri': GCS_TFLITE_URI,
    'sizeBytes': '1234567'
}
TFLITE_FORMAT = mlkit.TFLiteFormat.from_dict(TFLITE_FORMAT_JSON)

GCS_TFLITE_URI_2 = 'gs://my_bucket/mymodel2.tflite'
GCS_TFLITE_URI_JSON_2 = {'gcsTfliteUri': GCS_TFLITE_URI_2}
GCS_TFLITE_MODEL_SOURCE_2 = mlkit.TFLiteGCSModelSource(GCS_TFLITE_URI_2)
TFLITE_FORMAT_JSON_2 = {
    'gcsTfliteUri': GCS_TFLITE_URI_2,
    'sizeBytes': '2345678'
}
TFLITE_FORMAT_2 = mlkit.TFLiteFormat.from_dict(TFLITE_FORMAT_JSON_2)

CREATED_UPDATED_MODEL_JSON_1 = {
    'name': MODEL_NAME_1,
    'displayName': DISPLAY_NAME_1,
    'createTime': CREATE_TIME_JSON,
    'updateTime': UPDATE_TIME_JSON,
    'state': MODEL_STATE_ERROR_JSON,
    'etag': ETAG,
    'modelHash': MODEL_HASH,
    'tags': TAGS,
}
CREATED_UPDATED_MODEL_1 = mlkit.Model.from_dict(CREATED_UPDATED_MODEL_JSON_1)

LOCKED_MODEL_JSON_1 = {
    'name': MODEL_NAME_1,
    'displayName': DISPLAY_NAME_1,
    'createTime': CREATE_TIME_JSON,
    'updateTime': UPDATE_TIME_JSON,
    'tags': TAGS,
    'activeOperations': [OPERATION_NOT_DONE_JSON_1]
}

LOCKED_MODEL_JSON_2 = {
    'name': MODEL_NAME_1,
    'displayName': DISPLAY_NAME_2,
    'createTime': CREATE_TIME_JSON_2,
    'updateTime': UPDATE_TIME_JSON_2,
    'tags': TAGS_2,
    'activeOperations': [OPERATION_NOT_DONE_JSON_1]
}

OPERATION_DONE_MODEL_JSON_1 = {
    'name': OPERATION_NAME_1,
    'done': True,
    'response': CREATED_UPDATED_MODEL_JSON_1
}
OPERATION_MALFORMED_JSON_1 = {
    'name': OPERATION_NAME_1,
    'done': True,
    # if done is true then either response or error should be populated
}
OPERATION_MISSING_NAME = {
    'done': False
}
OPERATION_ERROR_CODE = 400
OPERATION_ERROR_MSG = "Invalid argument"
OPERATION_ERROR_EXPECTED_STATUS = 'INVALID_ARGUMENT'
OPERATION_ERROR_JSON_1 = {
    'name': OPERATION_NAME_1,
    'done': True,
    'error': {
        'code': OPERATION_ERROR_CODE,
        'message': OPERATION_ERROR_MSG,
    }
}

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
FULL_MODEL_PUBLISHED = mlkit.Model.from_dict(FULL_MODEL_PUBLISHED_JSON)
OPERATION_DONE_FULL_MODEL_PUBLISHED_JSON = {
    'name': OPERATION_NAME_1,
    'done': True,
    'response': FULL_MODEL_PUBLISHED_JSON
}

EMPTY_RESPONSE = json.dumps({})
OPERATION_NOT_DONE_RESPONSE = json.dumps(OPERATION_NOT_DONE_JSON_1)
OPERATION_DONE_RESPONSE = json.dumps(OPERATION_DONE_MODEL_JSON_1)
OPERATION_DONE_PUBLISHED_RESPONSE = json.dumps(OPERATION_DONE_FULL_MODEL_PUBLISHED_JSON)
OPERATION_ERROR_RESPONSE = json.dumps(OPERATION_ERROR_JSON_1)
OPERATION_MALFORMED_RESPONSE = json.dumps(OPERATION_MALFORMED_JSON_1)
OPERATION_MISSING_NAME_RESPONSE = json.dumps(OPERATION_MISSING_NAME)
DEFAULT_GET_RESPONSE = json.dumps(MODEL_JSON_1)
LOCKED_MODEL_2_RESPONSE = json.dumps(LOCKED_MODEL_JSON_2)
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

INVALID_MODEL_ID_ARGS = [
    ('', ValueError),
    ('&_*#@:/?', ValueError),
    (None, TypeError),
    (12345, TypeError),
]
INVALID_MODEL_ARGS = [
    'abc',
    4.2,
    list(),
    dict(),
    True,
    -1,
    0,
    None
]
INVALID_OP_NAME_ARGS = [
    'abc',
    '123',
    'projects/operations/project/1234/model/abc/operation/123',
    'operations/project/model/abc/operation/123',
    'operations/project/123/model/$#@/operation/123',
    'operations/project/1234/model/abc/operation/123/extrathing',
]
PAGE_SIZE_VALUE_ERROR_MSG = 'Page size must be a positive integer between ' \
                            '1 and {0}'.format(mlkit._MAX_PAGE_SIZE)
INVALID_STRING_OR_NONE_ARGS = [0, -1, 4.2, 0x10, False, list(), dict()]
PUBLISH_AND_UNPUBLISH_VALUE_ARGS = [
    (mlkit.publish_model, True),
    (mlkit.unpublish_model, False)
]
PUBLISH_AND_UNPUBLISH_ARGS = [mlkit.publish_model, mlkit.unpublish_model]

# For validation type errors
def check_error(excinfo, err_type, msg=None):
    err = excinfo.value
    assert isinstance(err, err_type)
    if msg:
        assert str(err) == msg


# For errors that are returned in an operation
def check_operation_error(excinfo, code, msg):
    err = excinfo.value
    assert isinstance(err, exceptions.FirebaseError)
    assert err.code == code
    assert str(err) == msg


# For rpc errors
def check_firebase_error(excinfo, code, status, msg):
    err = excinfo.value
    assert isinstance(err, exceptions.FirebaseError)
    assert err.code == code
    assert err.http_response is not None
    assert err.http_response.status_code == status
    assert str(err) == msg


def instrument_mlkit_service(status=200, payload=None, operations=False, app=None):
    if not app:
        app = firebase_admin.get_app()
    mlkit_service = mlkit._get_mlkit_service(app)
    recorder = []
    session_url = 'https://mlkit.googleapis.com/v1beta1/'

    if isinstance(status, list):
        adapter = testutils.MockMultiRequestAdapter
    else:
        adapter = testutils.MockAdapter

    if operations:
        mlkit_service._operation_client.session.mount(
            session_url, adapter(payload, status, recorder))
    else:
        mlkit_service._client.session.mount(
            session_url, adapter(payload, status, recorder))
    return recorder


class TestModel(object):
    """Tests mlkit.Model class."""
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})
        mlkit._MLKitService.POLL_BASE_WAIT_TIME_SECONDS = 0.1  # shorter for test

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    @staticmethod
    def _op_url(project_id, model_id):
        return BASE_URL + \
            'operations/project/{0}/model/{1}/operation/123'.format(project_id, model_id)

    def test_model_success_err_state_lro(self):
        model = mlkit.Model.from_dict(FULL_MODEL_ERR_STATE_LRO_JSON)
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
        assert model.as_dict() == FULL_MODEL_ERR_STATE_LRO_JSON

    def test_model_success_published(self):
        model = mlkit.Model.from_dict(FULL_MODEL_PUBLISHED_JSON)
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
        assert model.as_dict() == FULL_MODEL_PUBLISHED_JSON

    def test_model_keyword_based_creation_and_setters(self):
        model = mlkit.Model(display_name=DISPLAY_NAME_1, tags=TAGS, model_format=TFLITE_FORMAT)
        assert model.display_name == DISPLAY_NAME_1
        assert model.tags == TAGS
        assert model.model_format == TFLITE_FORMAT
        assert model.as_dict() == {
            'displayName': DISPLAY_NAME_1,
            'tags': TAGS,
            'tfliteModel': TFLITE_FORMAT_JSON
        }

        model.display_name = DISPLAY_NAME_2
        model.tags = TAGS_2
        model.model_format = TFLITE_FORMAT_2
        assert model.as_dict() == {
            'displayName': DISPLAY_NAME_2,
            'tags': TAGS_2,
            'tfliteModel': TFLITE_FORMAT_JSON_2
        }

    def test_model_format_source_creation(self):
        model_source = mlkit.TFLiteGCSModelSource(gcs_tflite_uri=GCS_TFLITE_URI)
        model_format = mlkit.TFLiteFormat(model_source=model_source)
        model = mlkit.Model(display_name=DISPLAY_NAME_1, model_format=model_format)
        assert model.as_dict() == {
            'displayName': DISPLAY_NAME_1,
            'tfliteModel': {
                'gcsTfliteUri': GCS_TFLITE_URI
            }
        }

    def test_model_source_setters(self):
        model_source = mlkit.TFLiteGCSModelSource(GCS_TFLITE_URI)
        model_source.gcs_tflite_uri = GCS_TFLITE_URI_2
        assert model_source.gcs_tflite_uri == GCS_TFLITE_URI_2
        assert model_source.as_dict() == GCS_TFLITE_URI_JSON_2

    def test_model_format_setters(self):
        model_format = mlkit.TFLiteFormat(model_source=GCS_TFLITE_MODEL_SOURCE)
        model_format.model_source = GCS_TFLITE_MODEL_SOURCE_2
        assert model_format.model_source == GCS_TFLITE_MODEL_SOURCE_2
        assert model_format.as_dict() == {
            'tfliteModel': {
                'gcsTfliteUri': GCS_TFLITE_URI_2
            }
        }

    @pytest.mark.parametrize('display_name, exc_type', [
        ('', ValueError),
        ('&_*#@:/?', ValueError),
        (12345, TypeError)
    ])
    def test_model_display_name_validation_errors(self, display_name, exc_type):
        with pytest.raises(exc_type) as excinfo:
            mlkit.Model(display_name=display_name)
        check_error(excinfo, exc_type)

    @pytest.mark.parametrize('tags, exc_type, error_message', [
        ('tag1', TypeError, 'Tags must be a list of strings.'),
        (123, TypeError, 'Tags must be a list of strings.'),
        (['tag1', 123, 'tag2'], TypeError, 'Tags must be a list of strings.'),
        (['tag1', '@#$%^&'], ValueError, 'Tag format is invalid.'),
        (['', 'tag2'], ValueError, 'Tag format is invalid.'),
        (['sixty-one_characters_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
          'tag2'], ValueError, 'Tag format is invalid.')
    ])
    def test_model_tags_validation_errors(self, tags, exc_type, error_message):
        with pytest.raises(exc_type) as excinfo:
            mlkit.Model(tags=tags)
        check_error(excinfo, exc_type, error_message)

    @pytest.mark.parametrize('model_format', [
        123,
        "abc",
        {},
        [],
        True
    ])
    def test_model_format_validation_errors(self, model_format):
        with pytest.raises(TypeError) as excinfo:
            mlkit.Model(model_format=model_format)
        check_error(excinfo, TypeError, 'Model format must be a ModelFormat object.')

    @pytest.mark.parametrize('model_source', [
        123,
        "abc",
        {},
        [],
        True
    ])
    def test_model_source_validation_errors(self, model_source):
        with pytest.raises(TypeError) as excinfo:
            mlkit.TFLiteFormat(model_source=model_source)
        check_error(excinfo, TypeError, 'Model source must be a TFLiteModelSource object.')

    @pytest.mark.parametrize('uri, exc_type', [
        (123, TypeError),
        ('abc', ValueError),
        ('gs://NO_CAPITALS', ValueError),
        ('gs://abc/', ValueError),
        ('gs://aa/model.tflite', ValueError),
        ('gs://@#$%/model.tflite', ValueError),
        ('gs://invalid space/model.tflite', ValueError),
        ('gs://sixty-four-characters_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/model.tflite',
         ValueError)
    ])
    def test_gcs_tflite_source_validation_errors(self, uri, exc_type):
        with pytest.raises(exc_type) as excinfo:
            mlkit.TFLiteGCSModelSource(gcs_tflite_uri=uri)
        check_error(excinfo, exc_type)

    def test_wait_for_unlocked_not_locked(self):
        model = mlkit.Model(display_name="not_locked")
        model.wait_for_unlocked()

    def test_wait_for_unlocked(self):
        recorder = instrument_mlkit_service(status=200,
                                            operations=True,
                                            payload=OPERATION_DONE_PUBLISHED_RESPONSE)
        model = mlkit.Model.from_dict(LOCKED_MODEL_JSON_1)
        model.wait_for_unlocked()
        assert model == FULL_MODEL_PUBLISHED
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == TestModel._op_url(PROJECT_ID, MODEL_ID_1)

    def test_wait_for_unlocked_timeout(self):
        recorder = instrument_mlkit_service(
            status=200, operations=True, payload=OPERATION_NOT_DONE_RESPONSE)
        mlkit._MLKitService.POLL_BASE_WAIT_TIME_SECONDS = 3 # longer so timeout applies immediately
        model = mlkit.Model.from_dict(LOCKED_MODEL_JSON_1)
        with pytest.raises(Exception) as excinfo:
            model.wait_for_unlocked(max_time_seconds=0.1)
        check_error(excinfo, exceptions.DeadlineExceededError, 'Polling max time exceeded.')
        assert len(recorder) == 1


class TestCreateModel(object):
    """Tests mlkit.create_model."""
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})
        mlkit._MLKitService.POLL_BASE_WAIT_TIME_SECONDS = 0.1  # shorter for test

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    @staticmethod
    def _url(project_id):
        return BASE_URL + 'projects/{0}/models'.format(project_id)

    @staticmethod
    def _op_url(project_id, model_id):
        return BASE_URL + \
            'operations/project/{0}/model/{1}/operation/123'.format(project_id, model_id)

    @staticmethod
    def _get_url(project_id, model_id):
        return BASE_URL + 'projects/{0}/models/{1}'.format(project_id, model_id)

    def test_immediate_done(self):
        instrument_mlkit_service(status=200, payload=OPERATION_DONE_RESPONSE)
        model = mlkit.create_model(MODEL_1)
        assert model == CREATED_UPDATED_MODEL_1

    def test_returns_locked(self):
        recorder = instrument_mlkit_service(
            status=[200, 200],
            payload=[OPERATION_NOT_DONE_RESPONSE, LOCKED_MODEL_2_RESPONSE])
        expected_model = mlkit.Model.from_dict(LOCKED_MODEL_JSON_2)
        model = mlkit.create_model(MODEL_1)

        assert model == expected_model
        assert len(recorder) == 2
        assert recorder[0].method == 'POST'
        assert recorder[0].url == TestCreateModel._url(PROJECT_ID)
        assert recorder[1].method == 'GET'
        assert recorder[1].url == TestCreateModel._get_url(PROJECT_ID, MODEL_ID_1)

    def test_operation_error(self):
        instrument_mlkit_service(status=200, payload=OPERATION_ERROR_RESPONSE)
        with pytest.raises(Exception) as excinfo:
            mlkit.create_model(MODEL_1)
        # The http request succeeded, the operation returned contains a create failure
        check_operation_error(excinfo, OPERATION_ERROR_EXPECTED_STATUS, OPERATION_ERROR_MSG)

    def test_malformed_operation(self):
        recorder = instrument_mlkit_service(
            status=[200, 200],
            payload=[OPERATION_MALFORMED_RESPONSE, LOCKED_MODEL_2_RESPONSE])
        expected_model = mlkit.Model.from_dict(LOCKED_MODEL_JSON_2)
        model = mlkit.create_model(MODEL_1)
        assert model == expected_model
        assert len(recorder) == 2
        assert recorder[0].method == 'POST'
        assert recorder[0].url == TestCreateModel._url(PROJECT_ID)
        assert recorder[1].method == 'GET'
        assert recorder[1].url == TestCreateModel._get_url(PROJECT_ID, MODEL_ID_1)

    def test_rpc_error_create(self):
        create_recorder = instrument_mlkit_service(
            status=400, payload=ERROR_RESPONSE_BAD_REQUEST)
        with pytest.raises(Exception) as excinfo:
            mlkit.create_model(MODEL_1)
        check_firebase_error(
            excinfo,
            ERROR_STATUS_BAD_REQUEST,
            ERROR_CODE_BAD_REQUEST,
            ERROR_MSG_BAD_REQUEST
        )
        assert len(create_recorder) == 1

    @pytest.mark.parametrize('model', INVALID_MODEL_ARGS)
    def test_not_model(self, model):
        with pytest.raises(Exception) as excinfo:
            mlkit.create_model(model)
        check_error(excinfo, TypeError, 'Model must be an mlkit.Model.')

    def test_missing_display_name(self):
        with pytest.raises(Exception) as excinfo:
            mlkit.create_model(mlkit.Model.from_dict({}))
        check_error(excinfo, ValueError, 'Model must have a display name.')

    def test_missing_op_name(self):
        instrument_mlkit_service(status=200, payload=OPERATION_MISSING_NAME_RESPONSE)
        with pytest.raises(Exception) as excinfo:
            mlkit.create_model(MODEL_1)
        check_error(excinfo, TypeError)

    @pytest.mark.parametrize('op_name', INVALID_OP_NAME_ARGS)
    def test_invalid_op_name(self, op_name):
        payload = json.dumps({'name': op_name})
        instrument_mlkit_service(status=200, payload=payload)
        with pytest.raises(Exception) as excinfo:
            mlkit.create_model(MODEL_1)
        check_error(excinfo, ValueError, 'Operation name format is invalid.')


class TestUpdateModel(object):
    """Tests mlkit.update_model."""
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})
        mlkit._MLKitService.POLL_BASE_WAIT_TIME_SECONDS = 0.1  # shorter for test

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    @staticmethod
    def _url(project_id, model_id):
        return BASE_URL + 'projects/{0}/models/{1}'.format(project_id, model_id)

    @staticmethod
    def _op_url(project_id, model_id):
        return BASE_URL + \
            'operations/project/{0}/model/{1}/operation/123'.format(project_id, model_id)

    def test_immediate_done(self):
        instrument_mlkit_service(status=200, payload=OPERATION_DONE_RESPONSE)
        model = mlkit.update_model(MODEL_1)
        assert model == CREATED_UPDATED_MODEL_1

    def test_returns_locked(self):
        recorder = instrument_mlkit_service(
            status=[200, 200],
            payload=[OPERATION_NOT_DONE_RESPONSE, LOCKED_MODEL_2_RESPONSE])
        expected_model = mlkit.Model.from_dict(LOCKED_MODEL_JSON_2)
        model = mlkit.update_model(MODEL_1)

        assert model == expected_model
        assert len(recorder) == 2
        assert recorder[0].method == 'PATCH'
        assert recorder[0].url == TestUpdateModel._url(PROJECT_ID, MODEL_ID_1)
        assert recorder[1].method == 'GET'
        assert recorder[1].url == TestUpdateModel._url(PROJECT_ID, MODEL_ID_1)

    def test_operation_error(self):
        instrument_mlkit_service(status=200, payload=OPERATION_ERROR_RESPONSE)
        with pytest.raises(Exception) as excinfo:
            mlkit.update_model(MODEL_1)
        # The http request succeeded, the operation returned contains an update failure
        check_operation_error(excinfo, OPERATION_ERROR_EXPECTED_STATUS, OPERATION_ERROR_MSG)

    def test_malformed_operation(self):
        recorder = instrument_mlkit_service(
            status=[200, 200],
            payload=[OPERATION_MALFORMED_RESPONSE, LOCKED_MODEL_2_RESPONSE])
        expected_model = mlkit.Model.from_dict(LOCKED_MODEL_JSON_2)
        model = mlkit.update_model(MODEL_1)
        assert model == expected_model
        assert len(recorder) == 2
        assert recorder[0].method == 'PATCH'
        assert recorder[0].url == TestUpdateModel._url(PROJECT_ID, MODEL_ID_1)
        assert recorder[1].method == 'GET'
        assert recorder[1].url == TestUpdateModel._url(PROJECT_ID, MODEL_ID_1)

    def test_rpc_error(self):
        create_recorder = instrument_mlkit_service(
            status=400, payload=ERROR_RESPONSE_BAD_REQUEST)
        with pytest.raises(Exception) as excinfo:
            mlkit.update_model(MODEL_1)
        check_firebase_error(
            excinfo,
            ERROR_STATUS_BAD_REQUEST,
            ERROR_CODE_BAD_REQUEST,
            ERROR_MSG_BAD_REQUEST
        )
        assert len(create_recorder) == 1

    @pytest.mark.parametrize('model', INVALID_MODEL_ARGS)
    def test_not_model(self, model):
        with pytest.raises(Exception) as excinfo:
            mlkit.update_model(model)
        check_error(excinfo, TypeError, 'Model must be an mlkit.Model.')

    def test_missing_display_name(self):
        with pytest.raises(Exception) as excinfo:
            mlkit.update_model(mlkit.Model.from_dict({}))
        check_error(excinfo, ValueError, 'Model must have a display name.')

    def test_missing_op_name(self):
        instrument_mlkit_service(status=200, payload=OPERATION_MISSING_NAME_RESPONSE)
        with pytest.raises(Exception) as excinfo:
            mlkit.update_model(MODEL_1)
        check_error(excinfo, TypeError)

    @pytest.mark.parametrize('op_name', INVALID_OP_NAME_ARGS)
    def test_invalid_op_name(self, op_name):
        payload = json.dumps({'name': op_name})
        instrument_mlkit_service(status=200, payload=payload)
        with pytest.raises(Exception) as excinfo:
            mlkit.update_model(MODEL_1)
        check_error(excinfo, ValueError, 'Operation name format is invalid.')


class TestPublishUnpublish(object):
    """Tests mlkit.publish_model and mlkit.unpublish_model."""
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})
        mlkit._MLKitService.POLL_BASE_WAIT_TIME_SECONDS = 0.1  # shorter for test

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    @staticmethod
    def _url(project_id, model_id):
        return BASE_URL + 'projects/{0}/models/{1}'.format(project_id, model_id)

    @staticmethod
    def _op_url(project_id, model_id):
        return BASE_URL + \
            'operations/project/{0}/model/{1}/operation/123'.format(project_id, model_id)

    @pytest.mark.parametrize('publish_function, published', PUBLISH_AND_UNPUBLISH_VALUE_ARGS)
    def test_immediate_done(self, publish_function, published):
        recorder = instrument_mlkit_service(status=200, payload=OPERATION_DONE_RESPONSE)
        model = publish_function(MODEL_ID_1)
        assert model == CREATED_UPDATED_MODEL_1
        assert len(recorder) == 1
        assert recorder[0].method == 'PATCH'
        assert recorder[0].url == TestPublishUnpublish._url(PROJECT_ID, MODEL_ID_1)
        body = json.loads(recorder[0].body.decode())
        assert body.get('model', {}).get('state', {}).get('published', None) is published
        assert body.get('updateMask', {}) == 'state.published'

    @pytest.mark.parametrize('publish_function', PUBLISH_AND_UNPUBLISH_ARGS)
    def test_returns_locked(self, publish_function):
        recorder = instrument_mlkit_service(
            status=[200, 200],
            payload=[OPERATION_NOT_DONE_RESPONSE, LOCKED_MODEL_2_RESPONSE])
        expected_model = mlkit.Model.from_dict(LOCKED_MODEL_JSON_2)
        model = publish_function(MODEL_ID_1)

        assert model == expected_model
        assert len(recorder) == 2
        assert recorder[0].method == 'PATCH'
        assert recorder[0].url == TestPublishUnpublish._url(PROJECT_ID, MODEL_ID_1)
        assert recorder[1].method == 'GET'
        assert recorder[1].url == TestPublishUnpublish._url(PROJECT_ID, MODEL_ID_1)

    @pytest.mark.parametrize('publish_function', PUBLISH_AND_UNPUBLISH_ARGS)
    def test_operation_error(self, publish_function):
        instrument_mlkit_service(status=200, payload=OPERATION_ERROR_RESPONSE)
        with pytest.raises(Exception) as excinfo:
            publish_function(MODEL_ID_1)
        # The http request succeeded, the operation returned contains an update failure
        check_operation_error(excinfo, OPERATION_ERROR_EXPECTED_STATUS, OPERATION_ERROR_MSG)

    @pytest.mark.parametrize('publish_function', PUBLISH_AND_UNPUBLISH_ARGS)
    def test_malformed_operation(self, publish_function):
        recorder = instrument_mlkit_service(
            status=[200, 200],
            payload=[OPERATION_MALFORMED_RESPONSE, LOCKED_MODEL_2_RESPONSE])
        expected_model = mlkit.Model.from_dict(LOCKED_MODEL_JSON_2)
        model = publish_function(MODEL_ID_1)
        assert model == expected_model
        assert len(recorder) == 2
        assert recorder[0].method == 'PATCH'
        assert recorder[0].url == TestPublishUnpublish._url(PROJECT_ID, MODEL_ID_1)
        assert recorder[1].method == 'GET'
        assert recorder[1].url == TestPublishUnpublish._url(PROJECT_ID, MODEL_ID_1)

    @pytest.mark.parametrize('publish_function', PUBLISH_AND_UNPUBLISH_ARGS)
    def test_rpc_error(self, publish_function):
        create_recorder = instrument_mlkit_service(
            status=400, payload=ERROR_RESPONSE_BAD_REQUEST)
        with pytest.raises(Exception) as excinfo:
            publish_function(MODEL_ID_1)
        check_firebase_error(
            excinfo,
            ERROR_STATUS_BAD_REQUEST,
            ERROR_CODE_BAD_REQUEST,
            ERROR_MSG_BAD_REQUEST
        )
        assert len(create_recorder) == 1

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

    @pytest.mark.parametrize('model_id, exc_type', INVALID_MODEL_ID_ARGS)
    def test_get_model_validation_errors(self, model_id, exc_type):
        with pytest.raises(exc_type) as excinfo:
            mlkit.get_model(model_id)
        check_error(excinfo, exc_type)

    def test_get_model_error(self):
        recorder = instrument_mlkit_service(status=404, payload=ERROR_RESPONSE_NOT_FOUND)
        with pytest.raises(exceptions.NotFoundError) as excinfo:
            mlkit.get_model(MODEL_ID_1)
        check_firebase_error(
            excinfo,
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

    @pytest.mark.parametrize('model_id, exc_type', INVALID_MODEL_ID_ARGS)
    def test_delete_model_validation_errors(self, model_id, exc_type):
        with pytest.raises(exc_type) as excinfo:
            mlkit.delete_model(model_id)
        check_error(excinfo, exc_type)

    def test_delete_model_error(self):
        recorder = instrument_mlkit_service(status=404, payload=ERROR_RESPONSE_NOT_FOUND)
        with pytest.raises(exceptions.NotFoundError) as excinfo:
            mlkit.delete_model(MODEL_ID_1)
        check_firebase_error(
            excinfo,
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

    @pytest.mark.parametrize('list_filter', INVALID_STRING_OR_NONE_ARGS)
    def test_list_models_list_filter_validation(self, list_filter):
        with pytest.raises(TypeError) as excinfo:
            mlkit.list_models(list_filter=list_filter)
        check_error(excinfo, TypeError, 'List filter must be a string or None.')

    @pytest.mark.parametrize('page_size, exc_type, error_message', [
        ('abc', TypeError, 'Page size must be a number or None.'),
        (4.2, TypeError, 'Page size must be a number or None.'),
        (list(), TypeError, 'Page size must be a number or None.'),
        (dict(), TypeError, 'Page size must be a number or None.'),
        (True, TypeError, 'Page size must be a number or None.'),
        (-1, ValueError, PAGE_SIZE_VALUE_ERROR_MSG),
        (0, ValueError, PAGE_SIZE_VALUE_ERROR_MSG),
        (mlkit._MAX_PAGE_SIZE + 1, ValueError, PAGE_SIZE_VALUE_ERROR_MSG)
    ])
    def test_list_models_page_size_validation(self, page_size, exc_type, error_message):
        with pytest.raises(exc_type) as excinfo:
            mlkit.list_models(page_size=page_size)
        check_error(excinfo, exc_type, error_message)

    @pytest.mark.parametrize('page_token', INVALID_STRING_OR_NONE_ARGS)
    def test_list_models_page_token_validation(self, page_token):
        with pytest.raises(TypeError) as excinfo:
            mlkit.list_models(page_token=page_token)
        check_error(excinfo, TypeError, 'Page token must be a string or None.')

    def test_list_models_error(self):
        recorder = instrument_mlkit_service(status=400, payload=ERROR_RESPONSE_BAD_REQUEST)
        with pytest.raises(exceptions.InvalidArgumentError) as excinfo:
            mlkit.list_models()
        check_firebase_error(
            excinfo,
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
