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

LIST_APPS_EMPTY_RESPONSE = json.dumps(dict())
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
# In Python 2.7, the base64 module works with strings, while in Python 3, it works with bytes
# objects. This line works in both versions.
TEST_APP_ENCODED_CONFIG = base64.standard_b64encode(TEST_APP_CONFIG.encode('utf-8')).decode('utf-8')
TEST_APP_CONFIG_RESPONSE = json.dumps({
    'configFilename': 'hello',
    'configFileContents': TEST_APP_ENCODED_CONFIG,
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


class TestShaCertificate(object):
    def test_create_sha_certificate_errors(self):
        # sha_hash cannot be None.
        with pytest.raises(ValueError):
            project_management.ShaCertificate(sha_hash=None)
        # sha_hash must be a string.
        with pytest.raises(ValueError):
            project_management.ShaCertificate(sha_hash=0x123456789a123456789a123456789a123456789a)
        # sha_hash must be a valid SHA-1 or SHA-256 hash.
        with pytest.raises(ValueError):
            project_management.ShaCertificate(sha_hash='123456789a123456789')
        with pytest.raises(ValueError):
            project_management.ShaCertificate(sha_hash='123456789a123456789a123456789a123456oops')

    def test_sha_certificate_eq(self):
        sha_cert_1 = project_management.ShaCertificate(SHA_1_HASH, SHA_1_NAME)
        # sha_hash is different from sha_cert_1, but name is the same.
        sha_cert_2 = project_management.ShaCertificate(
            '0000000000000000000000000000000000000000', SHA_1_NAME)
        # name is different from sha_cert_1, but sha_hash is the same.
        sha_cert_3 = project_management.ShaCertificate(SHA_1_HASH, None)
        # name is different from sha_cert_1, but sha_hash is the same.
        sha_cert_4 = project_management.ShaCertificate(
            SHA_1_HASH, 'projects/-/androidApps/{0}/sha/notname1')
        # sha_hash and cert_type are different from sha_cert_1, but name is the same.
        sha_cert_5 = project_management.ShaCertificate(
            SHA_256_HASH, 'projects/-/androidApps/{0}/sha/name1')
        # Exactly the same as sha_cert_1.
        sha_cert_6 = project_management.ShaCertificate(SHA_1_HASH, SHA_1_NAME)
        not_a_sha_cert = {'name': SHA_1_NAME, 'sha_hash': SHA_1_HASH, 'cert_type': 'SHA_1'}

        assert sha_cert_1 == sha_cert_1
        assert sha_cert_1 != sha_cert_2
        assert sha_cert_1 != sha_cert_3
        assert sha_cert_1 != sha_cert_4
        assert sha_cert_1 != sha_cert_5
        assert sha_cert_1 == sha_cert_6
        assert sha_cert_1 != not_a_sha_cert

    def test_sha_certificate_name(self):
        assert SHA_1_CERTIFICATE.name == SHA_1_NAME
        assert SHA_256_CERTIFICATE.name == SHA_256_NAME

    def test_sha_certificate_sha_hash(self):
        assert SHA_1_CERTIFICATE.sha_hash == SHA_1_HASH
        assert SHA_256_CERTIFICATE.sha_hash == SHA_256_HASH

    def test_sha_certificate_cert_type(self):
        assert SHA_1_CERTIFICATE.cert_type == 'SHA_1'
        assert SHA_256_CERTIFICATE.cert_type == 'SHA_256'


class TestAndroidAppMetadata(object):
    ANDROID_APP_METADATA = project_management.AndroidAppMetadata(
        package_name=TEST_ANDROID_APP_PACKAGE_NAME, name=TEST_ANDROID_APP_NAME,
        app_id=TEST_ANDROID_APP_ID, display_name=TEST_ANDROID_APP_DISPLAY_NAME,
        project_id=TEST_PROJECT_ID)

    def test_create_android_app_metadata_errors(self):
        # package_name must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.AndroidAppMetadata(
                package_name='', name=TEST_ANDROID_APP_NAME, app_id=TEST_ANDROID_APP_ID,
                display_name=TEST_ANDROID_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)
        # name must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.AndroidAppMetadata(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME, name='', app_id=TEST_ANDROID_APP_ID,
                display_name=TEST_ANDROID_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)
        # app_id must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.AndroidAppMetadata(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME, name=TEST_ANDROID_APP_NAME, app_id='',
                display_name=TEST_ANDROID_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)
        # display_name must be a string.
        with pytest.raises(ValueError):
            project_management.AndroidAppMetadata(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME, name=TEST_ANDROID_APP_NAME,
                app_id=TEST_ANDROID_APP_ID, display_name=None, project_id=TEST_PROJECT_ID)
        # project_id must be a nonempty string.
        with pytest.raises(ValueError):
            project_management.AndroidAppMetadata(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME, name=TEST_ANDROID_APP_NAME,
                app_id=TEST_ANDROID_APP_ID, display_name=TEST_ANDROID_APP_NAME, project_id='')

    def test_android_app_metadata_eq_and_hash(self):
        metadata_1 = TestAndroidAppMetadata.ANDROID_APP_METADATA
        metadata_2 = project_management.AndroidAppMetadata(
            package_name='different', name=TEST_ANDROID_APP_NAME,
            app_id=TEST_ANDROID_APP_ID, display_name=TEST_ANDROID_APP_DISPLAY_NAME,
            project_id=TEST_PROJECT_ID)
        metadata_3 = project_management.AndroidAppMetadata(
            package_name=TEST_ANDROID_APP_PACKAGE_NAME, name='different',
            app_id=TEST_ANDROID_APP_ID, display_name=TEST_ANDROID_APP_DISPLAY_NAME,
            project_id=TEST_PROJECT_ID)
        metadata_4 = project_management.AndroidAppMetadata(
            package_name=TEST_ANDROID_APP_PACKAGE_NAME, name=TEST_ANDROID_APP_NAME,
            app_id='different', display_name=TEST_ANDROID_APP_DISPLAY_NAME,
            project_id=TEST_PROJECT_ID)
        metadata_5 = project_management.AndroidAppMetadata(
            package_name=TEST_ANDROID_APP_PACKAGE_NAME, name=TEST_ANDROID_APP_NAME,
            app_id=TEST_ANDROID_APP_ID, display_name='different', project_id=TEST_PROJECT_ID)
        metadata_6 = project_management.AndroidAppMetadata(
            package_name=TEST_ANDROID_APP_PACKAGE_NAME, name=TEST_ANDROID_APP_NAME,
            app_id=TEST_ANDROID_APP_ID, display_name=TEST_ANDROID_APP_DISPLAY_NAME,
            project_id='different')
        metadata_7 = project_management.AndroidAppMetadata(
            package_name=TEST_ANDROID_APP_PACKAGE_NAME, name=TEST_ANDROID_APP_NAME,
            app_id=TEST_ANDROID_APP_ID, display_name=TEST_ANDROID_APP_DISPLAY_NAME,
            project_id=TEST_PROJECT_ID)
        ios_metadata = TestIosAppMetadata.IOS_APP_METADATA

        assert metadata_1 == metadata_1
        assert metadata_1 != metadata_2
        assert metadata_1 != metadata_3
        assert metadata_1 != metadata_4
        assert metadata_1 != metadata_5
        assert metadata_1 != metadata_6
        assert metadata_1 == metadata_7
        assert metadata_1 != ios_metadata
        assert set([metadata_1, metadata_2, metadata_7]) == set([metadata_1, metadata_2])

    def test_android_app_metadata_package_name(self):
        assert (TestAndroidAppMetadata.ANDROID_APP_METADATA.package_name ==
                TEST_ANDROID_APP_PACKAGE_NAME)

    def test_android_app_metadata_name(self):
        assert TestAndroidAppMetadata.ANDROID_APP_METADATA.name == TEST_ANDROID_APP_NAME

    def test_android_app_metadata_app_id(self):
        assert TestAndroidAppMetadata.ANDROID_APP_METADATA.app_id == TEST_ANDROID_APP_ID

    def test_android_app_metadata_display_name(self):
        assert (TestAndroidAppMetadata.ANDROID_APP_METADATA.display_name ==
                TEST_ANDROID_APP_DISPLAY_NAME)

    def test_android_app_metadata_project_id(self):
        assert TestAndroidAppMetadata.ANDROID_APP_METADATA.project_id == TEST_PROJECT_ID


class TestIosAppMetadata(object):
    IOS_APP_METADATA = project_management.IosAppMetadata(
        bundle_id=TEST_IOS_APP_BUNDLE_ID, name=TEST_IOS_APP_NAME, app_id=TEST_IOS_APP_ID,
        display_name=TEST_IOS_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)

    def test_create_ios_app_metadata_errors(self):
        # bundle_id must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.IosAppMetadata(
                bundle_id='', name=TEST_IOS_APP_NAME, app_id=TEST_IOS_APP_ID,
                display_name=TEST_IOS_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)
        # name must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.IosAppMetadata(
                bundle_id=TEST_IOS_APP_BUNDLE_ID, name='', app_id=TEST_IOS_APP_ID,
                display_name=TEST_IOS_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)
        # app_id must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.IosAppMetadata(
                bundle_id=TEST_IOS_APP_BUNDLE_ID, name=TEST_IOS_APP_NAME, app_id='',
                display_name=TEST_IOS_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)
        # display_name must be a string.
        with pytest.raises(ValueError):
            project_management.IosAppMetadata(
                bundle_id=TEST_IOS_APP_BUNDLE_ID, name=TEST_IOS_APP_NAME,
                app_id=TEST_IOS_APP_ID, display_name=None, project_id=TEST_PROJECT_ID)
        # project_id must be a nonempty string.
        with pytest.raises(ValueError):
            project_management.IosAppMetadata(
                bundle_id=TEST_IOS_APP_BUNDLE_ID, name=TEST_IOS_APP_NAME,
                app_id=TEST_IOS_APP_ID, display_name=TEST_IOS_APP_NAME, project_id='')

    def test_ios_app_metadata_eq_and_hash(self):
        metadata_1 = TestIosAppMetadata.IOS_APP_METADATA
        metadata_2 = project_management.IosAppMetadata(
            bundle_id='different', name=TEST_IOS_APP_NAME, app_id=TEST_IOS_APP_ID,
            display_name=TEST_IOS_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)
        metadata_3 = project_management.IosAppMetadata(
            bundle_id=TEST_IOS_APP_BUNDLE_ID, name='different', app_id=TEST_IOS_APP_ID,
            display_name=TEST_IOS_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)
        metadata_4 = project_management.IosAppMetadata(
            bundle_id=TEST_IOS_APP_BUNDLE_ID, name=TEST_IOS_APP_NAME, app_id='different',
            display_name=TEST_IOS_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)
        metadata_5 = project_management.IosAppMetadata(
            bundle_id=TEST_IOS_APP_BUNDLE_ID, name=TEST_IOS_APP_NAME, app_id=TEST_IOS_APP_ID,
            display_name='different', project_id=TEST_PROJECT_ID)
        metadata_6 = project_management.IosAppMetadata(
            bundle_id=TEST_IOS_APP_BUNDLE_ID, name=TEST_IOS_APP_NAME, app_id=TEST_IOS_APP_ID,
            display_name=TEST_IOS_APP_DISPLAY_NAME, project_id='different')
        metadata_7 = project_management.IosAppMetadata(
            bundle_id=TEST_IOS_APP_BUNDLE_ID, name=TEST_IOS_APP_NAME, app_id=TEST_IOS_APP_ID,
            display_name=TEST_IOS_APP_DISPLAY_NAME, project_id=TEST_PROJECT_ID)
        android_metadata = TestAndroidAppMetadata.ANDROID_APP_METADATA

        assert metadata_1 == metadata_1
        assert metadata_1 != metadata_2
        assert metadata_1 != metadata_3
        assert metadata_1 != metadata_4
        assert metadata_1 != metadata_5
        assert metadata_1 != metadata_6
        assert metadata_1 == metadata_7
        assert metadata_1 != android_metadata
        assert set([metadata_1, metadata_2, metadata_7]) == set([metadata_1, metadata_2])

    def test_ios_app_metadata_bundle_id(self):
        assert TestIosAppMetadata.IOS_APP_METADATA.bundle_id == TEST_IOS_APP_BUNDLE_ID

    def test_ios_app_metadata_name(self):
        assert TestIosAppMetadata.IOS_APP_METADATA.name == TEST_IOS_APP_NAME

    def test_ios_app_metadata_app_id(self):
        assert TestIosAppMetadata.IOS_APP_METADATA.app_id == TEST_IOS_APP_ID

    def test_ios_app_metadata_display_name(self):
        assert TestIosAppMetadata.IOS_APP_METADATA.display_name == TEST_IOS_APP_DISPLAY_NAME

    def test_ios_app_metadata_project_id(self):
        assert TestIosAppMetadata.IOS_APP_METADATA.project_id == TEST_PROJECT_ID


class BaseProjectManagementTest(object):
    @classmethod
    def setup_class(cls):
        project_management._ProjectManagementService.POLL_BASE_WAIT_TIME_SECONDS = 0.01
        project_management._ProjectManagementService.MAXIMUM_POLLING_ATTEMPTS = 3
        firebase_admin.initialize_app(
            testutils.MockCredential(), {'projectId': TEST_PROJECT_ID})

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
    _CREATION_URL = '{0}/v1beta1/projects/{1}/{2}'.format(BASE_URL, TEST_PROJECT_ID, 'androidApps')

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
        body = {'packageName': TEST_ANDROID_APP_PACKAGE_NAME}
        self._assert_request_is_correct(
            recorder[0], 'POST', TestCreateAndroidApp._CREATION_URL, body)
        self._assert_request_is_correct(recorder[1], 'GET', POLLING_URL)
        self._assert_request_is_correct(recorder[2], 'GET', POLLING_URL)

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
        body = {
            'packageName': TEST_ANDROID_APP_PACKAGE_NAME,
            'displayName': TEST_ANDROID_APP_DISPLAY_NAME,
        }
        self._assert_request_is_correct(
            recorder[0], 'POST', TestCreateAndroidApp._CREATION_URL, body)
        self._assert_request_is_correct(recorder[1], 'GET', POLLING_URL)
        self._assert_request_is_correct(recorder[2], 'GET', POLLING_URL)

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

    def test_create_android_app_polling_limit_exceeded(self):
        project_management._ProjectManagementService.MAXIMUM_POLLING_ATTEMPTS = 2
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_android_app(
                package_name=TEST_ANDROID_APP_PACKAGE_NAME,
                display_name=TEST_ANDROID_APP_DISPLAY_NAME)

        assert 'Polling deadline exceeded' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 3


class TestCreateIosApp(BaseProjectManagementTest):
    _CREATION_URL = BASE_URL + '/v1beta1/projects/{0}/{1}'.format(TEST_PROJECT_ID, 'iosApps')

    def test_create_ios_app_without_display_name(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                IOS_APP_NO_DISPLAY_NAME_OPERATION_SUCCESSFUL_RESPONSE,  # Operation completed.
            ])

        ios_app = project_management.create_ios_app(
            bundle_id=TEST_IOS_APP_BUNDLE_ID)

        assert ios_app.app_id == TEST_IOS_APP_ID
        assert len(recorder) == 3
        body = {'bundleId': TEST_IOS_APP_BUNDLE_ID}
        self._assert_request_is_correct(recorder[0], 'POST', TestCreateIosApp._CREATION_URL, body)
        self._assert_request_is_correct(recorder[1], 'GET', POLLING_URL)
        self._assert_request_is_correct(recorder[2], 'GET', POLLING_URL)

    def test_create_ios_app(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                IOS_APP_OPERATION_SUCCESSFUL_RESPONSE,  # Creation operation completed.
            ])

        ios_app = project_management.create_ios_app(
            bundle_id=TEST_IOS_APP_BUNDLE_ID,
            display_name=TEST_IOS_APP_DISPLAY_NAME)

        assert ios_app.app_id == TEST_IOS_APP_ID
        assert len(recorder) == 3
        body = {
            'bundleId': TEST_IOS_APP_BUNDLE_ID,
            'displayName': TEST_IOS_APP_DISPLAY_NAME,
        }
        self._assert_request_is_correct(recorder[0], 'POST', TestCreateIosApp._CREATION_URL, body)
        self._assert_request_is_correct(recorder[1], 'GET', POLLING_URL)
        self._assert_request_is_correct(recorder[2], 'GET', POLLING_URL)

    def test_create_ios_app_already_exists(self):
        recorder = self._instrument_service(statuses=[409], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_ios_app(
                bundle_id=TEST_IOS_APP_BUNDLE_ID,
                display_name=TEST_IOS_APP_DISPLAY_NAME)

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_create_ios_app_polling_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 503],  # Error 503 means that backend servers are over capacity.
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                ERROR_RESPONSE,  # Error 503.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_ios_app(
                bundle_id=TEST_IOS_APP_BUNDLE_ID,
                display_name=TEST_IOS_APP_DISPLAY_NAME)

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
                bundle_id=TEST_IOS_APP_BUNDLE_ID,
                display_name=TEST_IOS_APP_DISPLAY_NAME)

        assert 'Polling finished, but the operation terminated in an error' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 3

    def test_create_ios_app_polling_limit_exceeded(self):
        project_management._ProjectManagementService.MAXIMUM_POLLING_ATTEMPTS = 2
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation Operation is still not done.
            ])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.create_ios_app(
                bundle_id=TEST_IOS_APP_BUNDLE_ID,
                display_name=TEST_IOS_APP_DISPLAY_NAME)

        assert 'Polling deadline exceeded' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 3


class TestListAndroidApps(BaseProjectManagementTest):
    _LISTING_URL = '{0}/v1beta1/projects/{1}/androidApps?pageSize=100'.format(
        BASE_URL, TEST_PROJECT_ID)
    _LISTING_PAGE_2_URL = '{0}/v1beta1/projects/{1}/androidApps?pageToken={2}&pageSize=100'.format(
        BASE_URL, TEST_PROJECT_ID, LIST_APPS_NEXT_PAGE_TOKEN)

    def test_list_android_apps(self):
        recorder = self._instrument_service(statuses=[200], responses=[LIST_ANDROID_APPS_RESPONSE])

        android_apps = project_management.list_android_apps()

        expected_app_ids = set([TEST_ANDROID_APP_ID, TEST_ANDROID_APP_ID + 'cafe'])
        assert set(app.app_id for app in android_apps) == expected_app_ids
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestListAndroidApps._LISTING_URL)

    def test_list_android_apps_rpc_error(self):
        recorder = self._instrument_service(statuses=[503], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_android_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_list_android_apps_empty_list(self):
        recorder = self._instrument_service(statuses=[200], responses=[LIST_APPS_EMPTY_RESPONSE])

        android_apps = project_management.list_android_apps()

        assert android_apps == []
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestListAndroidApps._LISTING_URL)

    def test_list_android_apps_multiple_pages(self):
        recorder = self._instrument_service(
            statuses=[200, 200],
            responses=[LIST_ANDROID_APPS_PAGE_1_RESPONSE, LIST_ANDROID_APPS_PAGE_2_RESPONSE])

        android_apps = project_management.list_android_apps()

        expected_app_ids = set([TEST_ANDROID_APP_ID, TEST_ANDROID_APP_ID + 'cafe'])
        assert set(app.app_id for app in android_apps) == expected_app_ids
        assert len(recorder) == 2
        self._assert_request_is_correct(recorder[0], 'GET', TestListAndroidApps._LISTING_URL)
        self._assert_request_is_correct(recorder[1], 'GET', TestListAndroidApps._LISTING_PAGE_2_URL)

    def test_list_android_apps_multiple_pages_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 503],
            responses=[LIST_ANDROID_APPS_PAGE_1_RESPONSE, ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_android_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 2


class TestListIosApps(BaseProjectManagementTest):
    _LISTING_URL = '{0}/v1beta1/projects/{1}/iosApps?pageSize=100'.format(
        BASE_URL, TEST_PROJECT_ID)
    _LISTING_PAGE_2_URL = '{0}/v1beta1/projects/{1}/iosApps?pageToken={2}&pageSize=100'.format(
        BASE_URL, TEST_PROJECT_ID, LIST_APPS_NEXT_PAGE_TOKEN)

    def test_list_ios_apps(self):
        recorder = self._instrument_service(statuses=[200], responses=[LIST_IOS_APPS_RESPONSE])

        ios_apps = project_management.list_ios_apps()

        expected_app_ids = set([TEST_IOS_APP_ID, TEST_IOS_APP_ID + 'cafe'])
        assert set(app.app_id for app in ios_apps) == expected_app_ids
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestListIosApps._LISTING_URL)

    def test_list_ios_apps_rpc_error(self):
        recorder = self._instrument_service(statuses=[503], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_ios_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_list_ios_apps_empty_list(self):
        recorder = self._instrument_service(statuses=[200], responses=[LIST_APPS_EMPTY_RESPONSE])

        ios_apps = project_management.list_ios_apps()

        assert ios_apps == []
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestListIosApps._LISTING_URL)

    def test_list_ios_apps_multiple_pages(self):
        recorder = self._instrument_service(
            statuses=[200, 200],
            responses=[LIST_IOS_APPS_PAGE_1_RESPONSE, LIST_IOS_APPS_PAGE_2_RESPONSE])

        ios_apps = project_management.list_ios_apps()

        expected_app_ids = set([TEST_IOS_APP_ID, TEST_IOS_APP_ID + 'cafe'])
        assert set(app.app_id for app in ios_apps) == expected_app_ids
        assert len(recorder) == 2
        self._assert_request_is_correct(recorder[0], 'GET', TestListIosApps._LISTING_URL)
        self._assert_request_is_correct(recorder[1], 'GET', TestListIosApps._LISTING_PAGE_2_URL)

    def test_list_ios_apps_multiple_pages_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 503],
            responses=[LIST_IOS_APPS_PAGE_1_RESPONSE, ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            project_management.list_ios_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 2


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
        recorder = self._instrument_service(
            statuses=[200], responses=[json.dumps(TEST_ANDROID_APP_NO_DISPLAY_NAME)])

        metadata = android_app.get_metadata()

        assert metadata.name == TEST_ANDROID_APP_NAME
        assert metadata.app_id == TEST_ANDROID_APP_ID
        assert metadata.display_name == ''
        assert metadata.project_id == TEST_PROJECT_ID
        assert metadata.package_name == TEST_ANDROID_APP_PACKAGE_NAME
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._GET_METADATA_URL)

    def test_get_metadata(self, android_app):
        recorder = self._instrument_service(
            statuses=[200], responses=[json.dumps(TEST_ANDROID_APP)])

        metadata = android_app.get_metadata()

        assert metadata.name == TEST_ANDROID_APP_NAME
        assert metadata.app_id == TEST_ANDROID_APP_ID
        assert metadata.display_name == TEST_ANDROID_APP_DISPLAY_NAME
        assert metadata.project_id == TEST_PROJECT_ID
        assert metadata.package_name == TEST_ANDROID_APP_PACKAGE_NAME
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._GET_METADATA_URL)

    def test_get_metadata_not_found(self, android_app):
        recorder = self._instrument_service(statuses=[404], responses=[ERROR_RESPONSE])

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
        recorder = self._instrument_service(statuses=[404], responses=[ERROR_RESPONSE])
        new_display_name = 'A new display name!'

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.set_display_name(new_display_name)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_get_config(self, android_app):
        recorder = self._instrument_service(statuses=[200], responses=[TEST_APP_CONFIG_RESPONSE])

        config = android_app.get_config()

        assert config == TEST_APP_CONFIG
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._GET_CONFIG_URL)

    def test_get_config_not_found(self, android_app):
        recorder = self._instrument_service(statuses=[404], responses=[ERROR_RESPONSE])

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
        recorder = self._instrument_service(statuses=[404], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.get_sha_certificates()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_add_certificate_none_error(self, android_app):
        with pytest.raises(ValueError):
            android_app.add_sha_certificate(None)

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
        recorder = self._instrument_service(statuses=[409], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.add_sha_certificate(project_management.ShaCertificate(SHA_1_HASH))

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_delete_certificate_none_error(self, android_app):
        with pytest.raises(ValueError):
            android_app.delete_sha_certificate(None)

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
        recorder = self._instrument_service(statuses=[404], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            android_app.delete_sha_certificate(SHA_1_CERTIFICATE)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1


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
        recorder = self._instrument_service(
            statuses=[200], responses=[json.dumps(TEST_IOS_APP_NO_DISPLAY_NAME)])

        metadata = ios_app.get_metadata()

        assert metadata.name == TEST_IOS_APP_NAME
        assert metadata.app_id == TEST_IOS_APP_ID
        assert metadata.display_name == ''
        assert metadata.project_id == TEST_PROJECT_ID
        assert metadata.bundle_id == TEST_IOS_APP_BUNDLE_ID
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestIosApp._GET_METADATA_URL)

    def test_get_metadata(self, ios_app):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps(TEST_IOS_APP)])

        metadata = ios_app.get_metadata()

        assert metadata.name == TEST_IOS_APP_NAME
        assert metadata.app_id == TEST_IOS_APP_ID
        assert metadata.display_name == TEST_IOS_APP_DISPLAY_NAME
        assert metadata.project_id == TEST_PROJECT_ID
        assert metadata.bundle_id == TEST_IOS_APP_BUNDLE_ID
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestIosApp._GET_METADATA_URL)

    def test_get_metadata_not_found(self, ios_app):
        recorder = self._instrument_service(statuses=[404], responses=[ERROR_RESPONSE])

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
        recorder = self._instrument_service(statuses=[404], responses=[ERROR_RESPONSE])
        new_display_name = 'A new display name!'

        with pytest.raises(project_management.ApiCallError) as excinfo:
            ios_app.set_display_name(new_display_name)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1

    def test_get_config(self, ios_app):
        recorder = self._instrument_service(statuses=[200], responses=[TEST_APP_CONFIG_RESPONSE])

        config = ios_app.get_config()

        assert config == TEST_APP_CONFIG
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestIosApp._GET_CONFIG_URL)

    def test_get_config_not_found(self, ios_app):
        recorder = self._instrument_service(statuses=[404], responses=[ERROR_RESPONSE])

        with pytest.raises(project_management.ApiCallError) as excinfo:
            ios_app.get_config()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1
