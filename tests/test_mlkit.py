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
import six

import firebase_admin
from firebase_admin import exceptions
from firebase_admin import mlkit
from tests import testutils

PROJECT_ID = 'myProject1'
MODEL_ID_1 = 'modelId1'
DISPLAY_NAME_1 = 'displayName1'
MODEL_JSON_1 = {
    'name:': 'projects/{0}/models/{1}'.format(PROJECT_ID, MODEL_ID_1),
    'displayName': DISPLAY_NAME_1
}
MODEL_1 = mlkit.Model(MODEL_JSON_1)
_DEFAULT_RESPONSE = json.dumps(MODEL_JSON_1)


class TestGetModel(object):
    """Tests mlkit.get_model."""
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def _get_url(self, project_id, model_id):
        return mlkit._MLKitService.BASE_URL + 'projects/{0}/models/{1}'.format(project_id, model_id)

    def _instrument_mlkit_service(self, app=None, status=200, payload=_DEFAULT_RESPONSE):
        if not app:
            app = firebase_admin.get_app()
        mlkit_service = mlkit._get_mlkit_service(app)
        recorder = []
        mlkit_service._client.session.mount(
            'https://mlkit.googleapis.com',
            testutils.MockAdapter(payload, status, recorder)
        )
        return mlkit_service, recorder

    def test_get_model(self):
        _, recorder = self._instrument_mlkit_service()
        model = mlkit.get_model(MODEL_ID_1)
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == self._get_url(PROJECT_ID, MODEL_ID_1)
        #assert json.loads(recorder[0].body.decode()) == MODEL_JSON_1

    #TODO(ifielker): test_get_model_error, test_get_model_no_project_id etc



