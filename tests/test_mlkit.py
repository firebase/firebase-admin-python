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

import json
import pytest

import firebase_admin
from firebase_admin import exceptions
from firebase_admin import mlkit
from tests import testutils

BASE_URL = 'https://mlkit.googleapis.com/v1beta1/'

PROJECT_ID = 'myProject1'
MODEL_ID_1 = 'modelId1'
MODEL_NAME_1 = 'projects/{0}/models/{1}'.format(PROJECT_ID, MODEL_ID_1)
DISPLAY_NAME_1 = 'displayName1'
MODEL_JSON_1 = {
    'name': MODEL_NAME_1,
    'displayName': DISPLAY_NAME_1
}
MODEL_1 = mlkit.Model(MODEL_JSON_1)
_DEFAULT_GET_RESPONSE = json.dumps(MODEL_JSON_1)
_EMPTY_RESPONSE = json.dumps({})

ERROR_CODE = 404
ERROR_MSG = 'The resource was not found'
ERROR_STATUS = 'NOT_FOUND'
ERROR_JSON = {
    'error': {
        'code': ERROR_CODE,
        'message': ERROR_MSG,
        'status': ERROR_STATUS
    }
}
_ERROR_RESPONSE = json.dumps(ERROR_JSON)

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
        recorder = instrument_mlkit_service(status=200, payload=_DEFAULT_GET_RESPONSE)
        model = mlkit.get_model(MODEL_ID_1)
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == TestGetModel._url(PROJECT_ID, MODEL_ID_1)
        assert model == MODEL_1
        assert model._data['name'] == MODEL_NAME_1
        assert model._data['displayName'] == DISPLAY_NAME_1

    def test_get_model_validation_errors(self):
        #Empty model-id
        with pytest.raises(ValueError) as err:
            mlkit.get_model('')
        check_error(err.value, ValueError, 'Model ID format is invalid.')

        #None model-id
        with pytest.raises(TypeError) as err:
            mlkit.get_model(None)
        check_error(err.value, TypeError, 'Model ID must be a string.')

        #Wrong type
        with pytest.raises(TypeError) as err:
            mlkit.get_model(12345)
        check_error(err.value, TypeError, 'Model ID must be a string.')

        #Invalid characters
        with pytest.raises(ValueError) as err:
            mlkit.get_model('&_*#@:/?')
        check_error(err.value, ValueError, 'Model ID format is invalid.')

    def test_get_model_error(self):
        recorder = instrument_mlkit_service(status=404, payload=_ERROR_RESPONSE)
        with pytest.raises(exceptions.NotFoundError) as err:
            mlkit.get_model(MODEL_ID_1)
        check_firebase_error(err.value, ERROR_STATUS, ERROR_CODE, ERROR_MSG)
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == self._url(PROJECT_ID, MODEL_ID_1)

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
        recorder = instrument_mlkit_service(status=200, payload=_EMPTY_RESPONSE)
        mlkit.delete_model(MODEL_ID_1) # no response for delete
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == TestDeleteModel._url(PROJECT_ID, MODEL_ID_1)

    def test_delete_model_validation_errors(self):
        #Empty model-id
        with pytest.raises(ValueError) as err:
            mlkit.delete_model('')
        check_error(err.value, ValueError, 'Model ID format is invalid.')

        #None model-id
        with pytest.raises(TypeError) as err:
            mlkit.delete_model(None)
        check_error(err.value, TypeError, 'Model ID must be a string.')

        #Wrong type
        with pytest.raises(TypeError) as err:
            mlkit.delete_model(12345)
        check_error(err.value, TypeError, 'Model ID must be a string.')

        #Invalid characters
        with pytest.raises(ValueError) as err:
            mlkit.delete_model('&_*#@:/?')
        check_error(err.value, ValueError, 'Model ID format is invalid.')

    def test_delete_model_error(self):
        recorder = instrument_mlkit_service(status=404, payload=_ERROR_RESPONSE)
        with pytest.raises(exceptions.NotFoundError) as err:
            mlkit.delete_model(MODEL_ID_1)
        check_firebase_error(err.value, ERROR_STATUS, ERROR_CODE, ERROR_MSG)
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == self._url(PROJECT_ID, MODEL_ID_1)

    def test_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
            with pytest.raises(ValueError):
                mlkit.delete_model(MODEL_ID_1, app)
        testutils.run_without_project_id(evaluate)
