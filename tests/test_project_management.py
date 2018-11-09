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

BASE_URL = 'https://firebase.googleapis.com'

TEST_PROJECT_ID = 'hello-world'
TEST_ANDROID_APP_ID = '1:12345678:android:deadbeef'
TEST_ANDROID_APP_NAME = 'projects/{0}/androidApps/{1}'.format(TEST_PROJECT_ID, TEST_ANDROID_APP_ID)
TEST_ANDROID_APP_DISPLAY_NAME = "My Android App"
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
TEST_IOS_APP_DISPLAY_NAME = "My iOS App"
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
POLLING_URL = BASE_URL + '/v1/{0}'.format(OPERATION_NAME)
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

LIST_APPS_NEXT_PAGE_TOKEN = 'nextpagetoken'
TEST_ANDROID_APP_2 = {
    'name': TEST_ANDROID_APP_NAME + 'cafe',
    'appId': TEST_ANDROID_APP_ID + 'cafe',
    'projectId': TEST_PROJECT_ID,
    'packageName': TEST_ANDROID_APP_PACKAGE_NAME + '2',
}
LIST_ANDROID_APPS_RESPONSE = json.dumps({'apps': [TEST_ANDROID_APP, TEST_ANDROID_APP_2]})
LIST_ANDROID_APPS_PAGE_1_RESPONSE = json.dumps({
    'apps': [TEST_ANDROID_APP],
    'nextPageToken': LIST_APPS_NEXT_PAGE_TOKEN,
})
LIST_ANDROID_APPS_PAGE_2_RESPONSE = json.dumps({'apps': [TEST_ANDROID_APP_2]})
TEST_IOS_APP_2 = {
    'name': TEST_IOS_APP_NAME + 'cafe',
    'appId': TEST_IOS_APP_ID + 'cafe',
    'projectId': TEST_PROJECT_ID,
    'bundleId': TEST_IOS_APP_BUNDLE_ID + '2',
}
LIST_IOS_APPS_RESPONSE = json.dumps({'apps': [TEST_IOS_APP, TEST_IOS_APP_2]})
LIST_IOS_APPS_PAGE_1_RESPONSE = json.dumps({
    'apps': [TEST_IOS_APP],
    'nextPageToken': LIST_APPS_NEXT_PAGE_TOKEN,
})
LIST_IOS_APPS_PAGE_2_RESPONSE = json.dumps({'apps': [TEST_IOS_APP_2]})

TEST_APP_CONFIG = 'hello world'
TEST_APP_CONFIG_RESPONSE = json.dumps({
    'configFilename': 'hello',
    'configFileContents': base64.standard_b64encode(TEST_APP_CONFIG),
})

SHA_1_HASH = '123456789a123456789a123456789a123456789a'
SHA_256_HASH = '123456789a123456789a123456789a123456789a123456789a123456789a1234'
SHA_1_NAME = 'projects/-/androidApps/{0}/sha/name1'.format(TEST_ANDROID_APP_ID)
SHA_256_NAME = 'projects/-/androidApps/{0}/sha/name256'.format(TEST_ANDROID_APP_ID)

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
            testutils.MockCredential(), {'projectId': TEST_PROJECT_ID})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()
        project_management._ProjectManagementService.POLL_BASE_WAIT_TIME_SECONDS = 0.5

    def _set_up_mock_responses_and_request_captor_for_project_management_service(
            self, statuses, responses, app=None):
        if not app:
            app = firebase_admin.get_app()
        project_management_service = project_management._get_project_management_service(app)
        captor = []
        project_management_service._client.session.mount(
            'https://firebase.googleapis.com',
            testutils.MockMultiRequestAdapter(responses, statuses, captor))
        return captor

    def _assert_request_is_correct(
            self, request, expected_method, expected_url, expected_body=None):
        assert request.method == expected_method
        assert request.url == expected_url
        if expected_body is None:
            assert not request.body
        else:
            assert json.loads(request.body.decode()) == expected_body


class TestCreateAndroidApp(BaseProjectManagementTest):
    _CREATION_URL = '{0}/v1beta1/projects/{1}/{2}'.format(BASE_URL, TEST_PROJECT_ID, "androidApps")

    def test_create_android_app_without_display_name(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
                ANDROID_APP_NO_DISPLAY_NAME_OPERATION_SUCCESSFUL_RESPONSE,  # Operation completed.
            ])

        android_app = project_management.create_android_app(
            package_name=TEST_ANDROID_APP_PACKAGE_NAME)

        assert android_app.app_id == TEST_ANDROID_APP_ID
        assert len(captor) == 3
        body = {'packageName': TEST_ANDROID_APP_PACKAGE_NAME}
        self._assert_request_is_correct(captor[0], 'POST', TestCreateAndroidApp._CREATION_URL, body)
        self._assert_request_is_correct(captor[1], 'GET', POLLING_URL)
        self._assert_request_is_correct(captor[2], 'GET', POLLING_URL)

    def test_create_android_app(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
                ANDROID_APP_OPERATION_SUCCESSFUL_RESPONSE,  # Creation Operation completed.
            ])

        android_app = project_management.create_android_app(
            package_name=TEST_ANDROID_APP_PACKAGE_NAME,
            display_name=TEST_ANDROID_APP_DISPLAY_NAME)

        assert android_app.app_id == TEST_ANDROID_APP_ID
        assert len(captor) == 3
        body = {
            'packageName': TEST_ANDROID_APP_PACKAGE_NAME,
            'displayName': TEST_ANDROID_APP_DISPLAY_NAME,
        }
        self._assert_request_is_correct(captor[0], 'POST', TestCreateAndroidApp._CREATION_URL, body)
        self._assert_request_is_correct(captor[1], 'GET', POLLING_URL)
        self._assert_request_is_correct(captor[2], 'GET', POLLING_URL)

    def test_create_android_app_already_exists(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[409], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_android_app(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME,
                display_name=TEST_ANDROID_APP_DISPLAY_NAME)

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_create_android_app_polling_rpc_error(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 200, 503],  # Error 503 means that backend servers are over capacity.
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
                ERROR_RESPONSE,  # Error 503.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_android_app(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME,
                display_name=TEST_ANDROID_APP_DISPLAY_NAME)

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 3

    def test_create_android_app_polling_failure(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
                OPERATION_FAILED_RESPONSE,  # Operation is finished, but terminated with an error.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_android_app(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME,
                display_name=TEST_ANDROID_APP_DISPLAY_NAME)

        assert 'Polling finished, but the Operation terminated in an error' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 3


class TestCreateIosApp(BaseProjectManagementTest):
    _CREATION_URL = BASE_URL + '/v1beta1/projects/{0}/{1}'.format(TEST_PROJECT_ID, "iosApps")

    def test_create_ios_app_without_display_name(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
                IOS_APP_NO_DISPLAY_NAME_OPERATION_SUCCESSFUL_RESPONSE,  # Operation completed.
            ])

        ios_app = project_management.create_ios_app(
            bundle_id=TEST_IOS_APP_BUNDLE_ID)

        assert ios_app.app_id == TEST_IOS_APP_ID
        assert len(captor) == 3
        body = {'bundleId': TEST_IOS_APP_BUNDLE_ID}
        self._assert_request_is_correct(captor[0], 'POST', TestCreateIosApp._CREATION_URL, body)
        self._assert_request_is_correct(captor[1], 'GET', POLLING_URL)
        self._assert_request_is_correct(captor[2], 'GET', POLLING_URL)

    def test_create_ios_app(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
                IOS_APP_OPERATION_SUCCESSFUL_RESPONSE,  # Creation Operation completed.
            ])

        ios_app = project_management.create_ios_app(
            bundle_id=TEST_IOS_APP_BUNDLE_ID,
            display_name=TEST_IOS_APP_DISPLAY_NAME)

        assert ios_app.app_id == TEST_IOS_APP_ID
        assert len(captor) == 3
        body = {
            'bundleId': TEST_IOS_APP_BUNDLE_ID,
            'displayName': TEST_IOS_APP_DISPLAY_NAME,
        }
        self._assert_request_is_correct(captor[0], 'POST', TestCreateIosApp._CREATION_URL, body)
        self._assert_request_is_correct(captor[1], 'GET', POLLING_URL)
        self._assert_request_is_correct(captor[2], 'GET', POLLING_URL)

    def test_create_ios_app_already_exists(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[409], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_ios_app(
                bundle_id=TEST_IOS_APP_BUNDLE_ID,
                display_name=TEST_IOS_APP_DISPLAY_NAME)

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_create_ios_app_polling_rpc_error(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 200, 503],  # Error 503 means that backend servers are over capacity.
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
                ERROR_RESPONSE,  # Error 503.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_ios_app(
                bundle_id=TEST_IOS_APP_BUNDLE_ID,
                display_name=TEST_IOS_APP_DISPLAY_NAME)

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 3

    def test_create_ios_app_polling_failure(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
                OPERATION_FAILED_RESPONSE,  # Operation is finished, but terminated with an error.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_ios_app(
                bundle_id=TEST_IOS_APP_BUNDLE_ID,
                display_name=TEST_IOS_APP_DISPLAY_NAME)

        assert 'Polling finished, but the Operation terminated in an error' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 3


class TestListAndroidApps(BaseProjectManagementTest):
    _LISTING_URL = '{0}/v1beta1/projects/{1}/androidApps?pageSize=100'.format(
        BASE_URL, TEST_PROJECT_ID)
    _LISTING_PAGE_2_URL = '{0}/v1beta1/projects/{1}/androidApps?pageToken={2}&pageSize=100'.format(
        BASE_URL, TEST_PROJECT_ID, LIST_APPS_NEXT_PAGE_TOKEN)

    def test_list_android_apps(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[LIST_ANDROID_APPS_RESPONSE])

        android_apps = project_management.list_android_apps()

        expected_app_ids = set([TEST_ANDROID_APP_ID, TEST_ANDROID_APP_ID + 'cafe'])
        assert set(app.app_id for app in android_apps) == expected_app_ids
        assert len(captor) == 1
        self._assert_request_is_correct(captor[0], 'GET', TestListAndroidApps._LISTING_URL)

    def test_list_android_apps_rpc_error(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[503], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_android_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_list_android_apps_multiple_pages(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 200],
            responses=[LIST_ANDROID_APPS_PAGE_1_RESPONSE, LIST_ANDROID_APPS_PAGE_2_RESPONSE])

        android_apps = project_management.list_android_apps()

        expected_app_ids = set([TEST_ANDROID_APP_ID, TEST_ANDROID_APP_ID + 'cafe'])
        assert set(app.app_id for app in android_apps) == expected_app_ids
        assert len(captor) == 2
        self._assert_request_is_correct(captor[0], 'GET', TestListAndroidApps._LISTING_URL)
        self._assert_request_is_correct(captor[1], 'GET', TestListAndroidApps._LISTING_PAGE_2_URL)

    def test_list_android_apps_multiple_pages_rpc_error(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 503],
            responses=[LIST_ANDROID_APPS_PAGE_1_RESPONSE, ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_android_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 2


class TestListIosApps(BaseProjectManagementTest):
    _LISTING_URL = '{0}/v1beta1/projects/{1}/iosApps?pageSize=100'.format(
        BASE_URL, TEST_PROJECT_ID)
    _LISTING_PAGE_2_URL = '{0}/v1beta1/projects/{1}/iosApps?pageToken={2}&pageSize=100'.format(
        BASE_URL, TEST_PROJECT_ID, LIST_APPS_NEXT_PAGE_TOKEN)

    def test_list_ios_apps(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[LIST_IOS_APPS_RESPONSE])

        ios_apps = project_management.list_ios_apps()

        expected_app_ids = set([TEST_IOS_APP_ID, TEST_IOS_APP_ID + 'cafe'])
        assert set(app.app_id for app in ios_apps) == expected_app_ids
        assert len(captor) == 1
        self._assert_request_is_correct(captor[0], 'GET', TestListIosApps._LISTING_URL)

    def test_list_ios_apps_rpc_error(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[503], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_ios_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_list_ios_apps_multiple_pages(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 200],
            responses=[LIST_IOS_APPS_PAGE_1_RESPONSE, LIST_IOS_APPS_PAGE_2_RESPONSE])

        ios_apps = project_management.list_ios_apps()

        expected_app_ids = set([TEST_IOS_APP_ID, TEST_IOS_APP_ID + 'cafe'])
        assert set(app.app_id for app in ios_apps) == expected_app_ids
        assert len(captor) == 2
        self._assert_request_is_correct(captor[0], 'GET', TestListIosApps._LISTING_URL)
        self._assert_request_is_correct(captor[1], 'GET', TestListIosApps._LISTING_PAGE_2_URL)

    def test_list_ios_apps_multiple_pages_rpc_error(self):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200, 503],
            responses=[LIST_IOS_APPS_PAGE_1_RESPONSE, ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_ios_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 2


class TestAndroidApp(BaseProjectManagementTest):
    _GET_METADATA_URL = '{0}/v1beta1/projects/-/androidApps/{1}'.format(
        BASE_URL, TEST_ANDROID_APP_ID)
    _SET_DISPLAY_NAME_URL = '{0}/v1beta1/projects/-/androidApps/{1}?updateMask=displayName'.format(
        BASE_URL, TEST_ANDROID_APP_ID)
    _GET_CONFIG_URL = '{0}/v1beta1/projects/-/androidApps/{1}/config'.format(
        BASE_URL, TEST_ANDROID_APP_ID)
    _ADD_CERT_URL = '{0}/v1beta1/projects/-/androidApps/{1}/sha'.format(
        BASE_URL, TEST_ANDROID_APP_ID)
    _LIST_CERTS_URL = '{0}/v1beta1/projects/-/androidApps/{1}/sha'.format(
        BASE_URL, TEST_ANDROID_APP_ID)
    _DELETE_SHA_1_CERT_URL = '{0}/v1beta1/{1}'.format(BASE_URL, SHA_1_NAME)
    _DELETE_SHA_256_CERT_URL = '{0}/v1beta1/{1}'.format(BASE_URL, SHA_256_NAME)

    @pytest.fixture
    def android_app(self):
        return project_management.android_app(TEST_ANDROID_APP_ID)

    def test_get_metadata_no_display_name(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[json.dumps(TEST_ANDROID_APP_NO_DISPLAY_NAME)])

        metadata = android_app.get_metadata()

        assert metadata.name == TEST_ANDROID_APP_NAME
        assert metadata.app_id == TEST_ANDROID_APP_ID
        assert metadata.display_name == ''
        assert metadata.project_id == TEST_PROJECT_ID
        assert metadata.package_name == TEST_ANDROID_APP_PACKAGE_NAME
        assert len(captor) == 1
        self._assert_request_is_correct(captor[0], 'GET', TestAndroidApp._GET_METADATA_URL)

    def test_get_metadata(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[json.dumps(TEST_ANDROID_APP)])

        metadata = android_app.get_metadata()

        assert metadata.name == TEST_ANDROID_APP_NAME
        assert metadata.app_id == TEST_ANDROID_APP_ID
        assert metadata.display_name == TEST_ANDROID_APP_DISPLAY_NAME
        assert metadata.project_id == TEST_PROJECT_ID
        assert metadata.package_name == TEST_ANDROID_APP_PACKAGE_NAME
        assert len(captor) == 1
        self._assert_request_is_correct(captor[0], 'GET', TestAndroidApp._GET_METADATA_URL)

    def test_get_metadata_not_found(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[404], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.get_metadata()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_set_display_name(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[json.dumps({})])
        new_display_name = 'A new display name!'

        android_app.set_display_name(new_display_name)

        assert len(captor) == 1
        body = {'displayName': new_display_name}
        self._assert_request_is_correct(
            captor[0], 'PATCH', TestAndroidApp._SET_DISPLAY_NAME_URL, body)

    def test_set_display_name_not_found(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[404], responses=[ERROR_RESPONSE])
        new_display_name = 'A new display name!'

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.set_display_name(new_display_name)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_get_config(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[TEST_APP_CONFIG_RESPONSE])

        config = android_app.get_config()

        assert config == TEST_APP_CONFIG
        assert len(captor) == 1
        self._assert_request_is_correct(captor[0], 'GET', TestAndroidApp._GET_CONFIG_URL)

    def test_get_config_not_found(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[404], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.get_config()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_get_sha_certificates(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[GET_SHA_CERTIFICATES_RESPONSE])

        certs = android_app.get_sha_certificates()

        assert set(certs) == set(ALL_CERTS)
        assert len(captor) == 1
        self._assert_request_is_correct(captor[0], 'GET', TestAndroidApp._LIST_CERTS_URL)

    def test_get_sha_certificates_not_found(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[404], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.get_sha_certificates()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_add_sha_1_certificate(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[json.dumps({})])

        android_app.add_sha_certificate(project_management.ShaCertificate(SHA_1_HASH))

        assert len(captor) == 1
        body = {'shaHash': SHA_1_HASH, 'certType': 'SHA_1'}
        self._assert_request_is_correct(captor[0], 'POST', TestAndroidApp._ADD_CERT_URL, body)

    def test_add_sha_256_certificate(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[json.dumps({})])

        android_app.add_sha_certificate(project_management.ShaCertificate(SHA_256_HASH))

        assert len(captor) == 1
        body = {'shaHash': SHA_256_HASH, 'certType': 'SHA_256'}
        self._assert_request_is_correct(captor[0], 'POST', TestAndroidApp._ADD_CERT_URL, body)

    def test_add_sha_certificates_already_exists(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[409], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.add_sha_certificate(project_management.ShaCertificate(SHA_1_HASH))

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_delete_sha_1_certificate(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[json.dumps({})])

        android_app.delete_sha_certificate(SHA_1_CERTIFICATE)

        assert len(captor) == 1
        self._assert_request_is_correct(captor[0], 'DELETE', TestAndroidApp._DELETE_SHA_1_CERT_URL)

    def test_delete_sha_256_certificate(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[json.dumps({})])

        android_app.delete_sha_certificate(SHA_256_CERTIFICATE)

        assert len(captor) == 1
        self._assert_request_is_correct(
            captor[0], 'DELETE', TestAndroidApp._DELETE_SHA_256_CERT_URL)

    def test_delete_sha_certificates_not_found(self, android_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[404], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.delete_sha_certificate(SHA_1_CERTIFICATE)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1


class TestIosApp(BaseProjectManagementTest):
    _GET_METADATA_URL = '{0}/v1beta1/projects/-/iosApps/{1}'.format(
        BASE_URL, TEST_IOS_APP_ID)
    _SET_DISPLAY_NAME_URL = '{0}/v1beta1/projects/-/iosApps/{1}?updateMask=displayName'.format(
        BASE_URL, TEST_IOS_APP_ID)
    _GET_CONFIG_URL = '{0}/v1beta1/projects/-/iosApps/{1}/config'.format(
        BASE_URL, TEST_IOS_APP_ID)

    @pytest.fixture
    def ios_app(self):
        return project_management.ios_app(TEST_IOS_APP_ID)

    def test_get_metadata_no_display_name(self, ios_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[json.dumps(TEST_IOS_APP_NO_DISPLAY_NAME)])

        metadata = ios_app.get_metadata()

        assert metadata.name == TEST_IOS_APP_NAME
        assert metadata.app_id == TEST_IOS_APP_ID
        assert metadata.display_name == ''
        assert metadata.project_id == TEST_PROJECT_ID
        assert metadata.bundle_id == TEST_IOS_APP_BUNDLE_ID
        assert len(captor) == 1
        self._assert_request_is_correct(captor[0], 'GET', TestIosApp._GET_METADATA_URL)

    def test_get_metadata(self, ios_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[json.dumps(TEST_IOS_APP)])

        metadata = ios_app.get_metadata()

        assert metadata.name == TEST_IOS_APP_NAME
        assert metadata.app_id == TEST_IOS_APP_ID
        assert metadata.display_name == TEST_IOS_APP_DISPLAY_NAME
        assert metadata.project_id == TEST_PROJECT_ID
        assert metadata.bundle_id == TEST_IOS_APP_BUNDLE_ID
        assert len(captor) == 1
        self._assert_request_is_correct(captor[0], 'GET', TestIosApp._GET_METADATA_URL)

    def test_get_metadata_not_found(self, ios_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[404], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            ios_app.get_metadata()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_set_display_name(self, ios_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[json.dumps({})])
        new_display_name = 'A new display name!'

        ios_app.set_display_name(new_display_name)

        assert len(captor) == 1
        body = {'displayName': new_display_name}
        self._assert_request_is_correct(captor[0], 'PATCH', TestIosApp._SET_DISPLAY_NAME_URL, body)

    def test_set_display_name_not_found(self, ios_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[404], responses=[ERROR_RESPONSE])
        new_display_name = 'A new display name!'

        with pytest.raises(project_management.ApiCallError) as excinfo:
            ios_app.set_display_name(new_display_name)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1

    def test_get_config(self, ios_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[200], responses=[TEST_APP_CONFIG_RESPONSE])

        config = ios_app.get_config()

        assert config == TEST_APP_CONFIG
        assert len(captor) == 1
        self._assert_request_is_correct(captor[0], 'GET', TestIosApp._GET_CONFIG_URL)

    def test_get_config_not_found(self, ios_app):
        captor = self._set_up_mock_responses_and_request_captor_for_project_management_service(
            statuses=[404], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            ios_app.get_config()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(captor) == 1
