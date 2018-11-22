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

"""Tests for firebase_admin.project_management."""

import json

import pytest

import firebase_admin
from firebase_admin import project_management
from tests import testutils

BASE_URL = 'https://firebase.googleapis.com'

TEST_PROJECT_ID = 'test-project-id'
TEST_ANDROID_APP_ID = '1:12345678:android:deadbeef'
TEST_ANDROID_APP_NAME = 'projects/{0}/androidApps/{1}'.format(TEST_PROJECT_ID, TEST_ANDROID_APP_ID)
TEST_ANDROID_APP_DISPLAY_NAME = 'My Android App'
TEST_ANDROID_APP_PACKAGE_NAME = 'com.hello.world.android'
TEST_ANDROID_APP = {
    'name': TEST_ANDROID_APP_NAME,
    'appId': TEST_ANDROID_APP_ID,
    'displayName': TEST_ANDROID_APP_DISPLAY_NAME,
    'projectId': TEST_PROJECT_ID,
    'packageName': TEST_ANDROID_APP_PACKAGE_NAME,
}
TEST_ANDROID_APP_NO_DISPLAY_NAME = {
    'name': TEST_ANDROID_APP_NAME,
    'appId': TEST_ANDROID_APP_ID,
    'projectId': TEST_PROJECT_ID,
    'packageName': TEST_ANDROID_APP_PACKAGE_NAME,
}

TEST_IOS_APP_ID = '1:12345678:ios:ca5cade5'
TEST_IOS_APP_NAME = 'projects/{0}/iosApps/{1}'.format(TEST_PROJECT_ID, TEST_IOS_APP_ID)
TEST_IOS_APP_DISPLAY_NAME = 'My iOS App'
TEST_IOS_APP_BUNDLE_ID = 'com.hello.world.ios'
TEST_IOS_APP = {
    'name': TEST_IOS_APP_NAME,
    'appId': TEST_IOS_APP_ID,
    'displayName': TEST_IOS_APP_DISPLAY_NAME,
    'projectId': TEST_PROJECT_ID,
    'bundleId': TEST_IOS_APP_BUNDLE_ID,
}
TEST_IOS_APP_NO_DISPLAY_NAME = {
    'name': TEST_IOS_APP_NAME,
    'appId': TEST_IOS_APP_ID,
    'projectId': TEST_PROJECT_ID,
    'bundleId': TEST_IOS_APP_BUNDLE_ID,
}

OPERATION_NAME = 'operations/abcdefg'
OPERATION_IN_PROGRESS_RESPONSE = json.dumps({
    'name': OPERATION_NAME,
    'done': False
})
OPERATION_FAILED_RESPONSE = json.dumps({
    'name': OPERATION_NAME,
    'done': True,
    'error': 'some error',
})
ANDROID_APP_OPERATION_SUCCESSFUL_RESPONSE = json.dumps({
    'name': OPERATION_NAME,
    'done': True,
    'response': TEST_ANDROID_APP,
})
ANDROID_APP_NO_DISPLAY_NAME_OPERATION_SUCCESSFUL_RESPONSE = json.dumps({
    'name': OPERATION_NAME,
    'done': True,
    'response': TEST_ANDROID_APP_NO_DISPLAY_NAME,
})
IOS_APP_OPERATION_SUCCESSFUL_RESPONSE = json.dumps({
    'name': OPERATION_NAME,
    'done': True,
    'response': TEST_IOS_APP,
})
IOS_APP_NO_DISPLAY_NAME_OPERATION_SUCCESSFUL_RESPONSE = json.dumps({
    'name': OPERATION_NAME,
    'done': True,
    'response': TEST_IOS_APP_NO_DISPLAY_NAME,
})

ERROR_RESPONSE = 'some error'

class TestCreateAndroidApp(object):
    _CREATION_URL = '{0}/v1beta1/projects/{1}/{2}'.format(BASE_URL, TEST_PROJECT_ID, 'androidApps')
    _POLLING_URL = '{0}/v1/{1}'.format(BASE_URL, OPERATION_NAME)

    @classmethod
    def setup_class(cls):
        firebase_admin.initialize_app(
            testutils.MockCredential(), {'projectId': TEST_PROJECT_ID})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def _instrument_service(self, statuses, responses, app=None):
        if not app:
            app = firebase_admin.get_app()
        project_management_service = project_management._get_project_management_service(app)
        recorder = []
        project_management_service._client.session.mount(
            'https://firebase.googleapis.com',
            testutils.MockMultiRequestAdapter(responses, statuses, recorder))
        return recorder

    def test_create_android_app_without_display_name(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                ANDROID_APP_NO_DISPLAY_NAME_OPERATION_SUCCESSFUL_RESPONSE,  # Operation completed.
            ])

        android_app = project_management.create_android_app(
            package_name=TEST_ANDROID_APP_PACKAGE_NAME)

        assert android_app.app_id == TEST_ANDROID_APP_ID
        assert len(recorder) == 3
        assert recorder[0].method == 'POST'
        assert recorder[0].url == TestCreateAndroidApp._CREATION_URL
        body = {'packageName': TEST_ANDROID_APP_PACKAGE_NAME}
        assert json.loads(recorder[0].body.decode()) == body
        assert recorder[1].method == 'GET'
        assert recorder[1].url == TestCreateAndroidApp._POLLING_URL
        assert not recorder[1].body
        assert recorder[2].method == 'GET'
        assert recorder[2].url == TestCreateAndroidApp._POLLING_URL
        assert not recorder[2].body

    def test_create_android_app(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                ANDROID_APP_OPERATION_SUCCESSFUL_RESPONSE,  # Creation operation completed.
            ])

        android_app = project_management.create_android_app(
            package_name=TEST_ANDROID_APP_PACKAGE_NAME,
            display_name=TEST_ANDROID_APP_DISPLAY_NAME)

        assert android_app.app_id == TEST_ANDROID_APP_ID
        assert len(recorder) == 3
        assert recorder[0].method == 'POST'
        assert recorder[0].url == TestCreateAndroidApp._CREATION_URL
        body = {
            'packageName': TEST_ANDROID_APP_PACKAGE_NAME,
            'displayName': TEST_ANDROID_APP_DISPLAY_NAME,
        }
        assert json.loads(recorder[0].body.decode()) == body
        assert recorder[1].method == 'GET'
        assert recorder[1].url == TestCreateAndroidApp._POLLING_URL
        assert not recorder[1].body
        assert recorder[2].method == 'GET'
        assert recorder[2].url == TestCreateAndroidApp._POLLING_URL
        assert not recorder[2].body

    def test_create_android_app_already_exists(self):
        recorder = self._instrument_service(statuses=[409], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_android_app(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME,
                display_name=TEST_ANDROID_APP_DISPLAY_NAME)

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_create_android_app_polling_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 503],  # Error 503 means that backend servers are over capacity.
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                ERROR_RESPONSE,  # Error 503.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_android_app(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME,
                display_name=TEST_ANDROID_APP_DISPLAY_NAME)

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 3

    def test_create_android_app_polling_failure(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                OPERATION_FAILED_RESPONSE,  # Operation is finished, but terminated with an error.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_android_app(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME,
                display_name=TEST_ANDROID_APP_DISPLAY_NAME)

        assert 'Polling finished, but the operation terminated in an error' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 3
