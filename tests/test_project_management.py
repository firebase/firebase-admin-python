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

import base64
import json

import pytest

import firebase_admin
from firebase_admin import project_management
from tests import testutils

OPERATION_IN_PROGRESS_RESPONSE = json.dumps({
    'name': 'operations/abcdefg',
    'done': False
})
OPERATION_FAILED_RESPONSE = json.dumps({
    'name': 'operations/abcdefg',
    'done': True,
    'error': 'some error',
})
ANDROID_APP_OPERATION_SUCCESSFUL_RESPONSE = json.dumps({
    'name': 'operations/abcdefg',
    'done': True,
    'response': {
        'name': 'projects/test-project-id/androidApps/1:12345678:android:deadbeef',
        'appId': '1:12345678:android:deadbeef',
        'displayName': 'My Android App',
        'projectId': 'test-project-id',
        'packageName': 'com.hello.world.android',
    },
})
ANDROID_APP_NO_DISPLAY_NAME_OPERATION_SUCCESSFUL_RESPONSE = json.dumps({
    'name': 'operations/abcdefg',
    'done': True,
    'response': {
        'name': 'projects/test-project-id/androidApps/1:12345678:android:deadbeef',
        'appId': '1:12345678:android:deadbeef',
        'projectId': 'test-project-id',
        'packageName': 'com.hello.world.android',
    },
})
ANDROID_APP_METADATA_RESPONSE = json.dumps({
    'name': 'projects/test-project-id/androidApps/1:12345678:android:deadbeef',
    'appId': '1:12345678:android:deadbeef',
    'displayName': 'My Android App',
    'projectId': 'test-project-id',
    'packageName': 'com.hello.world.android',
})
ANDROID_APP_NO_DISPLAY_NAME_METADATA_RESPONSE = json.dumps({
    'name': 'projects/test-project-id/androidApps/1:12345678:android:deadbeef',
    'appId': '1:12345678:android:deadbeef',
    'projectId': 'test-project-id',
    'packageName': 'com.hello.world.android',
})
IOS_APP_OPERATION_SUCCESSFUL_RESPONSE = json.dumps({
    'name': 'operations/abcdefg',
    'done': True,
    'response': {
        'name': 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
        'appId': '1:12345678:ios:ca5cade5',
        'displayName': 'My iOS App',
        'projectId': 'test-project-id',
        'bundleId': 'com.hello.world.ios',
    },
})
IOS_APP_NO_DISPLAY_NAME_OPERATION_SUCCESSFUL_RESPONSE = json.dumps({
    'name': 'operations/abcdefg',
    'done': True,
    'response': {
        'name': 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
        'appId': '1:12345678:ios:ca5cade5',
        'projectId': 'test-project-id',
        'bundleId': 'com.hello.world.ios',
    },
})
IOS_APP_METADATA_RESPONSE = json.dumps({
    'name': 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
    'appId': '1:12345678:ios:ca5cade5',
    'displayName': 'My iOS App',
    'projectId': 'test-project-id',
    'bundleId': 'com.hello.world.ios',
})
IOS_APP_NO_DISPLAY_NAME_METADATA_RESPONSE = json.dumps({
    'name': 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
    'appId': '1:12345678:ios:ca5cade5',
    'projectId': 'test-project-id',
    'bundleId': 'com.hello.world.ios',
})

LIST_ANDROID_APPS_RESPONSE = json.dumps({'apps': [
    {
        'name': 'projects/test-project-id/androidApps/1:12345678:android:deadbeef',
        'appId': '1:12345678:android:deadbeef',
        'displayName': 'My Android App',
        'projectId': 'test-project-id',
        'packageName': 'com.hello.world.android',
    },
    {
        'name': 'projects/test-project-id/androidApps/1:12345678:android:deadbeefcafe',
        'appId': '1:12345678:android:deadbeefcafe',
        'projectId': 'test-project-id',
        'packageName': 'com.hello.world.android2',
    }]})
LIST_ANDROID_APPS_PAGE_1_RESPONSE = json.dumps({
    'apps': [{
        'name': 'projects/test-project-id/androidApps/1:12345678:android:deadbeef',
        'appId': '1:12345678:android:deadbeef',
        'displayName': 'My Android App',
        'projectId': 'test-project-id',
        'packageName': 'com.hello.world.android',
    }],
    'nextPageToken': 'nextpagetoken',
})
LIST_ANDROID_APPS_PAGE_2_RESPONSE = json.dumps({
    'apps': [{
        'name': 'projects/test-project-id/androidApps/1:12345678:android:deadbeefcafe',
        'appId': '1:12345678:android:deadbeefcafe',
        'projectId': 'test-project-id',
        'packageName': 'com.hello.world.android2',
    }]})
LIST_IOS_APPS_RESPONSE = json.dumps({'apps': [
    {
        'name': 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
        'appId': '1:12345678:ios:ca5cade5',
        'displayName': 'My iOS App',
        'projectId': 'test-project-id',
        'bundleId': 'com.hello.world.ios',
    },
    {
        'name': 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5cafe',
        'appId': '1:12345678:ios:ca5cade5cafe',
        'projectId': 'test-project-id',
        'bundleId': 'com.hello.world.ios2',
    }]})
LIST_IOS_APPS_PAGE_1_RESPONSE = json.dumps({
    'apps': [{
        'name': 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
        'appId': '1:12345678:ios:ca5cade5',
        'displayName': 'My iOS App',
        'projectId': 'test-project-id',
        'bundleId': 'com.hello.world.ios',
    }],
    'nextPageToken': 'nextpagetoken',
})
LIST_IOS_APPS_PAGE_2_RESPONSE = json.dumps({
    'apps': [{
        'name': 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5cafe',
        'appId': '1:12345678:ios:ca5cade5cafe',
        'projectId': 'test-project-id',
        'bundleId': 'com.hello.world.ios2',
    }]})

# In Python 2.7, the base64 module works with strings, while in Python 3, it works with bytes
# objects. This line works in both versions.
TEST_APP_ENCODED_CONFIG = base64.standard_b64encode('hello world'.encode('utf-8')).decode('utf-8')
TEST_APP_CONFIG_RESPONSE = json.dumps({
    'configFilename': 'hello',
    'configFileContents': TEST_APP_ENCODED_CONFIG,
})

SHA_1_HASH = '123456789a123456789a123456789a123456789a'
SHA_256_HASH = '123456789a123456789a123456789a123456789a123456789a123456789a1234'
SHA_1_NAME = 'projects/-/androidApps/1:12345678:android:deadbeef/sha/name1'
SHA_256_NAME = 'projects/-/androidApps/1:12345678:android:deadbeef/sha/name256'

SHA_1_CERTIFICATE = project_management.ShaCertificate(SHA_1_HASH, SHA_1_NAME)
SHA_256_CERTIFICATE = project_management.ShaCertificate(SHA_256_HASH, SHA_256_NAME)
ALL_CERTS = [SHA_1_CERTIFICATE, SHA_256_CERTIFICATE]
GET_SHA_CERTIFICATES_RESPONSE = json.dumps({'certificates': [
    {'name': cert.name, 'shaHash': cert.sha_hash, 'certType': cert.cert_type} for cert in ALL_CERTS
]})


class BaseProjectManagementTest(object):
    @classmethod
    def setup_class(cls):
        project_management._ProjectManagementService.POLL_BASE_WAIT_TIME_SECONDS = 0.01
        firebase_admin.initialize_app(
            testutils.MockCredential(), {'projectId': 'test-project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()
        project_management._ProjectManagementService.POLL_BASE_WAIT_TIME_SECONDS = 0.5

    def _instrument_service(self, statuses, responses, app=None):
        if not app:
            app = firebase_admin.get_app()
        project_management_service = project_management._get_project_management_service(app)
        recorder = []
        project_management_service._client.session.mount(
            'https://firebase.googleapis.com',
            testutils.MockMultiRequestAdapter(responses, statuses, recorder))
        return recorder

    def _assert_request_is_correct(
            self, request, expected_method, expected_url, expected_body=None):
        assert request.method == expected_method
        assert request.url == expected_url
        if expected_body is None:
            assert not request.body
        else:
            assert json.loads(request.body.decode()) == expected_body


class TestCreateAndroidApp(BaseProjectManagementTest):
    _CREATION_URL = 'https://firebase.googleapis.com/v1beta1/projects/test-project-id/androidApps'

    def test_create_android_app_without_display_name(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                ANDROID_APP_NO_DISPLAY_NAME_OPERATION_SUCCESSFUL_RESPONSE,  # Operation completed.
            ])

        android_app = project_management.create_android_app(
            package_name='com.hello.world.android')

        assert android_app.app_id == '1:12345678:android:deadbeef'
        assert len(recorder) == 3
        body = {'packageName': 'com.hello.world.android'}
        self._assert_request_is_correct(
            recorder[0], 'POST', TestCreateAndroidApp._CREATION_URL, body)
        self._assert_request_is_correct(
            recorder[1], 'GET', 'https://firebase.googleapis.com/v1/operations/abcdefg')
        self._assert_request_is_correct(
            recorder[2], 'GET', 'https://firebase.googleapis.com/v1/operations/abcdefg')

    def test_create_android_app(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                ANDROID_APP_OPERATION_SUCCESSFUL_RESPONSE,  # Creation operation completed.
            ])

        android_app = project_management.create_android_app(
            package_name='com.hello.world.android',
            display_name='My Android App')

        assert android_app.app_id == '1:12345678:android:deadbeef'
        assert len(recorder) == 3
        body = {
            'packageName': 'com.hello.world.android',
            'displayName': 'My Android App',
        }
        self._assert_request_is_correct(
            recorder[0], 'POST', TestCreateAndroidApp._CREATION_URL, body)
        self._assert_request_is_correct(
            recorder[1], 'GET', 'https://firebase.googleapis.com/v1/operations/abcdefg')
        self._assert_request_is_correct(
            recorder[2], 'GET', 'https://firebase.googleapis.com/v1/operations/abcdefg')

    def test_create_android_app_already_exists(self):
        recorder = self._instrument_service(statuses=[409], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_android_app(
                package_name='com.hello.world.android',
                display_name='My Android App')

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_create_android_app_polling_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 503],  # Error 503 means that backend servers are over capacity.
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                'some error response',  # Error 503.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_android_app(
                package_name='com.hello.world.android',
                display_name='My Android App')

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
                package_name='com.hello.world.android',
                display_name='My Android App')

        assert 'Polling finished, but the operation terminated in an error' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 3


class TestCreateIosApp(BaseProjectManagementTest):
    _CREATION_URL = 'https://firebase.googleapis.com/v1beta1/projects/test-project-id/iosApps'

    def test_create_ios_app_without_display_name(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                IOS_APP_NO_DISPLAY_NAME_OPERATION_SUCCESSFUL_RESPONSE,  # Operation completed.
            ])

        ios_app = project_management.create_ios_app(
            bundle_id='com.hello.world.ios')

        assert ios_app.app_id == '1:12345678:ios:ca5cade5'
        assert len(recorder) == 3
        body = {'bundleId': 'com.hello.world.ios'}
        self._assert_request_is_correct(recorder[0], 'POST', TestCreateIosApp._CREATION_URL, body)
        self._assert_request_is_correct(
            recorder[1], 'GET', 'https://firebase.googleapis.com/v1/operations/abcdefg')
        self._assert_request_is_correct(
            recorder[2], 'GET', 'https://firebase.googleapis.com/v1/operations/abcdefg')

    def test_create_ios_app(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                IOS_APP_OPERATION_SUCCESSFUL_RESPONSE,  # Creation operation completed.
            ])

        ios_app = project_management.create_ios_app(
            bundle_id='com.hello.world.ios',
            display_name='My iOS App')

        assert ios_app.app_id == '1:12345678:ios:ca5cade5'
        assert len(recorder) == 3
        body = {
            'bundleId': 'com.hello.world.ios',
            'displayName': 'My iOS App',
        }
        self._assert_request_is_correct(recorder[0], 'POST', TestCreateIosApp._CREATION_URL, body)
        self._assert_request_is_correct(
            recorder[1], 'GET', 'https://firebase.googleapis.com/v1/operations/abcdefg')
        self._assert_request_is_correct(
            recorder[2], 'GET', 'https://firebase.googleapis.com/v1/operations/abcdefg')

    def test_create_ios_app_already_exists(self):
        recorder = self._instrument_service(statuses=[409], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_ios_app(
                bundle_id='com.hello.world.ios',
                display_name='My iOS App')

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_create_ios_app_polling_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 503],  # Error 503 means that backend servers are over capacity.
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                'some error response',  # Error 503.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_ios_app(
                bundle_id='com.hello.world.ios',
                display_name='My iOS App')

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 3

    def test_create_ios_app_polling_failure(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                OPERATION_FAILED_RESPONSE,  # Operation is finished, but terminated with an error.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_ios_app(
                bundle_id='com.hello.world.ios',
                display_name='My iOS App')

        assert 'Polling finished, but the operation terminated in an error' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 3


class TestListAndroidApps(BaseProjectManagementTest):
    _LISTING_URL = ('https://firebase.googleapis.com/v1beta1/projects/test-project-id/'
                    'androidApps?pageSize=100')
    _LISTING_PAGE_2_URL = ('https://firebase.googleapis.com/v1beta1/projects/test-project-id/'
                           'androidApps?pageToken=nextpagetoken&pageSize=100')

    def test_list_android_apps(self):
        recorder = self._instrument_service(statuses=[200], responses=[LIST_ANDROID_APPS_RESPONSE])

        android_apps = project_management.list_android_apps()

        expected_app_ids = set(['1:12345678:android:deadbeef', '1:12345678:android:deadbeefcafe'])
        assert set(app.app_id for app in android_apps) == expected_app_ids
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestListAndroidApps._LISTING_URL)

    def test_list_android_apps_rpc_error(self):
        recorder = self._instrument_service(statuses=[503], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_android_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_list_android_apps_multiple_pages(self):
        recorder = self._instrument_service(
            statuses=[200, 200],
            responses=[LIST_ANDROID_APPS_PAGE_1_RESPONSE, LIST_ANDROID_APPS_PAGE_2_RESPONSE])

        android_apps = project_management.list_android_apps()

        expected_app_ids = set(['1:12345678:android:deadbeef', '1:12345678:android:deadbeefcafe'])
        assert set(app.app_id for app in android_apps) == expected_app_ids
        assert len(recorder) == 2
        self._assert_request_is_correct(recorder[0], 'GET', TestListAndroidApps._LISTING_URL)
        self._assert_request_is_correct(recorder[1], 'GET', TestListAndroidApps._LISTING_PAGE_2_URL)

    def test_list_android_apps_multiple_pages_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 503],
            responses=[LIST_ANDROID_APPS_PAGE_1_RESPONSE, 'some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_android_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 2


class TestListIosApps(BaseProjectManagementTest):
    _LISTING_URL = ('https://firebase.googleapis.com/v1beta1/projects/test-project-id/'
                    'iosApps?pageSize=100')
    _LISTING_PAGE_2_URL = ('https://firebase.googleapis.com/v1beta1/projects/test-project-id/'
                           'iosApps?pageToken=nextpagetoken&pageSize=100')

    def test_list_ios_apps(self):
        recorder = self._instrument_service(statuses=[200], responses=[LIST_IOS_APPS_RESPONSE])

        ios_apps = project_management.list_ios_apps()

        expected_app_ids = set(['1:12345678:ios:ca5cade5', '1:12345678:ios:ca5cade5cafe'])
        assert set(app.app_id for app in ios_apps) == expected_app_ids
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestListIosApps._LISTING_URL)

    def test_list_ios_apps_rpc_error(self):
        recorder = self._instrument_service(statuses=[503], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_ios_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_list_ios_apps_multiple_pages(self):
        recorder = self._instrument_service(
            statuses=[200, 200],
            responses=[LIST_IOS_APPS_PAGE_1_RESPONSE, LIST_IOS_APPS_PAGE_2_RESPONSE])

        ios_apps = project_management.list_ios_apps()

        expected_app_ids = set(['1:12345678:ios:ca5cade5', '1:12345678:ios:ca5cade5cafe'])
        assert set(app.app_id for app in ios_apps) == expected_app_ids
        assert len(recorder) == 2
        self._assert_request_is_correct(recorder[0], 'GET', TestListIosApps._LISTING_URL)
        self._assert_request_is_correct(recorder[1], 'GET', TestListIosApps._LISTING_PAGE_2_URL)

    def test_list_ios_apps_multiple_pages_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 503],
            responses=[LIST_IOS_APPS_PAGE_1_RESPONSE, 'some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_ios_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 2


class TestAndroidApp(BaseProjectManagementTest):
    _GET_METADATA_URL = ('https://firebase.googleapis.com/v1beta1/projects/-/androidApps/'
                         '1:12345678:android:deadbeef')
    _SET_DISPLAY_NAME_URL = ('https://firebase.googleapis.com/v1beta1/projects/-/androidApps/'
                             '1:12345678:android:deadbeef?updateMask=displayName')
    _GET_CONFIG_URL = ('https://firebase.googleapis.com/v1beta1/projects/-/androidApps/'
                       '1:12345678:android:deadbeef/config')
    _ADD_CERT_URL = ('https://firebase.googleapis.com/v1beta1/projects/-/androidApps/'
                     '1:12345678:android:deadbeef/sha')
    _LIST_CERTS_URL = ('https://firebase.googleapis.com/v1beta1/projects/-/androidApps/'
                       '1:12345678:android:deadbeef/sha')
    _DELETE_SHA_1_CERT_URL = 'https://firebase.googleapis.com/v1beta1/{0}'.format(SHA_1_NAME)
    _DELETE_SHA_256_CERT_URL = 'https://firebase.googleapis.com/v1beta1/{0}'.format(SHA_256_NAME)

    @pytest.fixture
    def android_app(self):
        return project_management.android_app('1:12345678:android:deadbeef')

    def test_get_metadata_no_display_name(self, android_app):
        recorder = self._instrument_service(
            statuses=[200], responses=[ANDROID_APP_NO_DISPLAY_NAME_METADATA_RESPONSE])

        metadata = android_app.get_metadata()

        assert metadata.name == 'projects/test-project-id/androidApps/1:12345678:android:deadbeef'
        assert metadata.app_id == '1:12345678:android:deadbeef'
        assert metadata.display_name == ''
        assert metadata.project_id == 'test-project-id'
        assert metadata.package_name == 'com.hello.world.android'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._GET_METADATA_URL)

    def test_get_metadata(self, android_app):
        recorder = self._instrument_service(
            statuses=[200], responses=[ANDROID_APP_METADATA_RESPONSE])

        metadata = android_app.get_metadata()

        assert metadata.name == 'projects/test-project-id/androidApps/1:12345678:android:deadbeef'
        assert metadata.app_id == '1:12345678:android:deadbeef'
        assert metadata.display_name == 'My Android App'
        assert metadata.project_id == 'test-project-id'
        assert metadata.package_name == 'com.hello.world.android'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._GET_METADATA_URL)

    def test_get_metadata_not_found(self, android_app):
        recorder = self._instrument_service(statuses=[404], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.get_metadata()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_set_display_name(self, android_app):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps({})])
        new_display_name = 'A new display name!'

        android_app.set_display_name(new_display_name)

        assert len(recorder) == 1
        body = {'displayName': new_display_name}
        self._assert_request_is_correct(
            recorder[0], 'PATCH', TestAndroidApp._SET_DISPLAY_NAME_URL, body)

    def test_set_display_name_not_found(self, android_app):
        recorder = self._instrument_service(statuses=[404], responses=['some error response'])
        new_display_name = 'A new display name!'

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.set_display_name(new_display_name)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_get_config(self, android_app):
        recorder = self._instrument_service(statuses=[200], responses=[TEST_APP_CONFIG_RESPONSE])

        config = android_app.get_config()

        assert config == 'hello world'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._GET_CONFIG_URL)

    def test_get_config_not_found(self, android_app):
        recorder = self._instrument_service(statuses=[404], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.get_config()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_get_sha_certificates(self, android_app):
        recorder = self._instrument_service(
            statuses=[200], responses=[GET_SHA_CERTIFICATES_RESPONSE])

        certs = android_app.get_sha_certificates()

        assert set(certs) == set(ALL_CERTS)
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._LIST_CERTS_URL)

    def test_get_sha_certificates_not_found(self, android_app):
        recorder = self._instrument_service(statuses=[404], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.get_sha_certificates()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_add_sha_1_certificate(self, android_app):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps({})])

        android_app.add_sha_certificate(project_management.ShaCertificate(SHA_1_HASH))

        assert len(recorder) == 1
        body = {'shaHash': SHA_1_HASH, 'certType': 'SHA_1'}
        self._assert_request_is_correct(recorder[0], 'POST', TestAndroidApp._ADD_CERT_URL, body)

    def test_add_sha_256_certificate(self, android_app):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps({})])

        android_app.add_sha_certificate(project_management.ShaCertificate(SHA_256_HASH))

        assert len(recorder) == 1
        body = {'shaHash': SHA_256_HASH, 'certType': 'SHA_256'}
        self._assert_request_is_correct(recorder[0], 'POST', TestAndroidApp._ADD_CERT_URL, body)

    def test_add_sha_certificates_already_exists(self, android_app):
        recorder = self._instrument_service(statuses=[409], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.add_sha_certificate(project_management.ShaCertificate(SHA_1_HASH))

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_delete_sha_1_certificate(self, android_app):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps({})])

        android_app.delete_sha_certificate(SHA_1_CERTIFICATE)

        assert len(recorder) == 1
        self._assert_request_is_correct(
            recorder[0], 'DELETE', TestAndroidApp._DELETE_SHA_1_CERT_URL)

    def test_delete_sha_256_certificate(self, android_app):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps({})])

        android_app.delete_sha_certificate(SHA_256_CERTIFICATE)

        assert len(recorder) == 1
        self._assert_request_is_correct(
            recorder[0], 'DELETE', TestAndroidApp._DELETE_SHA_256_CERT_URL)

    def test_delete_sha_certificates_not_found(self, android_app):
        recorder = self._instrument_service(statuses=[404], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.delete_sha_certificate(SHA_1_CERTIFICATE)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1


class TestIosApp(BaseProjectManagementTest):
    _GET_METADATA_URL = ('https://firebase.googleapis.com/v1beta1/projects/-/iosApps/'
                         '1:12345678:ios:ca5cade5')
    _SET_DISPLAY_NAME_URL = ('https://firebase.googleapis.com/v1beta1/projects/-/iosApps/'
                             '1:12345678:ios:ca5cade5?updateMask=displayName')
    _GET_CONFIG_URL = ('https://firebase.googleapis.com/v1beta1/projects/-/iosApps/'
                       '1:12345678:ios:ca5cade5/config')

    @pytest.fixture
    def ios_app(self):
        return project_management.ios_app('1:12345678:ios:ca5cade5')

    def test_get_metadata_no_display_name(self, ios_app):
        recorder = self._instrument_service(
            statuses=[200], responses=[IOS_APP_NO_DISPLAY_NAME_METADATA_RESPONSE])

        metadata = ios_app.get_metadata()

        assert metadata.name == 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5'
        assert metadata.app_id == '1:12345678:ios:ca5cade5'
        assert metadata.display_name == ''
        assert metadata.project_id == 'test-project-id'
        assert metadata.bundle_id == 'com.hello.world.ios'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestIosApp._GET_METADATA_URL)

    def test_get_metadata(self, ios_app):
        recorder = self._instrument_service(statuses=[200], responses=[IOS_APP_METADATA_RESPONSE])

        metadata = ios_app.get_metadata()

        assert metadata.name == 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5'
        assert metadata.app_id == '1:12345678:ios:ca5cade5'
        assert metadata.display_name == 'My iOS App'
        assert metadata.project_id == 'test-project-id'
        assert metadata.bundle_id == 'com.hello.world.ios'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestIosApp._GET_METADATA_URL)

    def test_get_metadata_not_found(self, ios_app):
        recorder = self._instrument_service(statuses=[404], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            ios_app.get_metadata()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_set_display_name(self, ios_app):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps({})])
        new_display_name = 'A new display name!'

        ios_app.set_display_name(new_display_name)

        assert len(recorder) == 1
        body = {'displayName': new_display_name}
        self._assert_request_is_correct(
            recorder[0], 'PATCH', TestIosApp._SET_DISPLAY_NAME_URL, body)

    def test_set_display_name_not_found(self, ios_app):
        recorder = self._instrument_service(statuses=[404], responses=['some error response'])
        new_display_name = 'A new display name!'

        with pytest.raises(project_management.ApiCallError) as excinfo:
            ios_app.set_display_name(new_display_name)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_get_config(self, ios_app):
        recorder = self._instrument_service(statuses=[200], responses=[TEST_APP_CONFIG_RESPONSE])

        config = ios_app.get_config()

        assert config == 'hello world'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestIosApp._GET_CONFIG_URL)

    def test_get_config_not_found(self, ios_app):
        recorder = self._instrument_service(statuses=[404], responses=['some error response'])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            ios_app.get_config()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1
