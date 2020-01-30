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
from firebase_admin import exceptions
from firebase_admin import project_management
from firebase_admin import _http_client
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

SHA_1_CERTIFICATE = project_management.SHACertificate(
    '123456789a123456789a123456789a123456789a',
    'projects/-/androidApps/1:12345678:android:deadbeef/sha/name1')
SHA_256_CERTIFICATE = project_management.SHACertificate(
    '123456789a123456789a123456789a123456789a123456789a123456789a1234',
    'projects/-/androidApps/1:12345678:android:deadbeef/sha/name256')
GET_SHA_CERTIFICATES_RESPONSE = json.dumps({'certificates': [
    {'name': cert.name, 'shaHash': cert.sha_hash, 'certType': cert.cert_type}
    for cert in [SHA_1_CERTIFICATE, SHA_256_CERTIFICATE]
]})

ANDROID_APP_METADATA = project_management.AndroidAppMetadata(
    package_name='com.hello.world.android',
    name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
    app_id='1:12345678:android:deadbeef',
    display_name='My Android App',
    project_id='test-project-id')
IOS_APP_METADATA = project_management.IOSAppMetadata(
    bundle_id='com.hello.world.ios',
    name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
    app_id='1:12345678:android:deadbeef',
    display_name='My iOS App',
    project_id='test-project-id')

ALREADY_EXISTS_RESPONSE = ('{"error": {"status": "ALREADY_EXISTS", '
                           '"message": "The resource already exists"}}')
NOT_FOUND_RESPONSE = '{"error": {"message": "Failed to find the resource"}}'
UNAVAILABLE_RESPONSE = '{"error": {"message": "Backend servers are over capacity"}}'

class TestAndroidAppMetadata:

    def test_create_android_app_metadata_errors(self):
        # package_name must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.AndroidAppMetadata(
                package_name='',
                name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
                app_id='1:12345678:android:deadbeef',
                display_name='My Android App',
                project_id='test-project-id')
        # name must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.AndroidAppMetadata(
                package_name='com.hello.world.android',
                name='',
                app_id='1:12345678:android:deadbeef',
                display_name='My Android App',
                project_id='test-project-id')
        # app_id must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.AndroidAppMetadata(
                package_name='com.hello.world.android',
                name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
                app_id='',
                display_name='My Android App',
                project_id='test-project-id')
        # display_name must be a string or None.
        with pytest.raises(ValueError):
            project_management.AndroidAppMetadata(
                package_name='com.hello.world.android',
                name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
                app_id='1:12345678:android:deadbeef',
                display_name=0,
                project_id='test-project-id')
        # project_id must be a nonempty string.
        with pytest.raises(ValueError):
            project_management.AndroidAppMetadata(
                package_name='com.hello.world.android',
                name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
                app_id='1:12345678:android:deadbeef',
                display_name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
                project_id='')

    def test_android_app_metadata_eq_and_hash(self):
        metadata_1 = ANDROID_APP_METADATA
        metadata_2 = project_management.AndroidAppMetadata(
            package_name='different',
            name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
            app_id='1:12345678:android:deadbeef',
            display_name='My Android App',
            project_id='test-project-id')
        metadata_3 = project_management.AndroidAppMetadata(
            package_name='com.hello.world.android',
            name='different',
            app_id='1:12345678:android:deadbeef',
            display_name='My Android App',
            project_id='test-project-id')
        metadata_4 = project_management.AndroidAppMetadata(
            package_name='com.hello.world.android',
            name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
            app_id='different',
            display_name='My Android App',
            project_id='test-project-id')
        metadata_5 = project_management.AndroidAppMetadata(
            package_name='com.hello.world.android',
            name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
            app_id='1:12345678:android:deadbeef',
            display_name=None,
            project_id='test-project-id')
        metadata_6 = project_management.AndroidAppMetadata(
            package_name='com.hello.world.android',
            name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
            app_id='1:12345678:android:deadbeef',
            display_name='My Android App',
            project_id='different')
        metadata_7 = project_management.AndroidAppMetadata(
            package_name='com.hello.world.android',
            name='projects/test-project-id/androidApps/1:12345678:android:deadbeef',
            app_id='1:12345678:android:deadbeef',
            display_name='My Android App',
            project_id='test-project-id')
        ios_metadata = IOS_APP_METADATA

        # Don't trigger __ne__.
        assert not metadata_1 == ios_metadata  # pylint: disable=unneeded-not
        assert metadata_1 != ios_metadata
        assert metadata_1 != metadata_2
        assert metadata_1 != metadata_3
        assert metadata_1 != metadata_4
        assert metadata_1 != metadata_5
        assert metadata_1 != metadata_6
        assert metadata_1 == metadata_7
        assert set([metadata_1, metadata_2, metadata_7]) == set([metadata_1, metadata_2])

    def test_android_app_metadata_package_name(self):
        assert ANDROID_APP_METADATA.package_name == 'com.hello.world.android'

    def test_android_app_metadata_name(self):
        assert (ANDROID_APP_METADATA._name ==
                'projects/test-project-id/androidApps/1:12345678:android:deadbeef')

    def test_android_app_metadata_app_id(self):
        assert ANDROID_APP_METADATA.app_id == '1:12345678:android:deadbeef'

    def test_android_app_metadata_display_name(self):
        assert ANDROID_APP_METADATA.display_name == 'My Android App'

    def test_android_app_metadata_project_id(self):
        assert ANDROID_APP_METADATA.project_id == 'test-project-id'


class TestIOSAppMetadata:

    def test_create_ios_app_metadata_errors(self):
        # bundle_id must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.IOSAppMetadata(
                bundle_id='',
                name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
                app_id='1:12345678:android:deadbeef',
                display_name='My iOS App',
                project_id='test-project-id')
        # name must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.IOSAppMetadata(
                bundle_id='com.hello.world.ios',
                name='',
                app_id='1:12345678:android:deadbeef',
                display_name='My iOS App',
                project_id='test-project-id')
        # app_id must be a non-empty string.
        with pytest.raises(ValueError):
            project_management.IOSAppMetadata(
                bundle_id='com.hello.world.ios',
                name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
                app_id='',
                display_name='My iOS App',
                project_id='test-project-id')
        # display_name must be a string or None.
        with pytest.raises(ValueError):
            project_management.IOSAppMetadata(
                bundle_id='com.hello.world.ios',
                name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
                app_id='1:12345678:android:deadbeef',
                display_name=0,
                project_id='test-project-id')
        # project_id must be a nonempty string.
        with pytest.raises(ValueError):
            project_management.IOSAppMetadata(
                bundle_id='com.hello.world.ios',
                name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
                app_id='1:12345678:android:deadbeef',
                display_name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
                project_id='')

    def test_ios_app_metadata_eq_and_hash(self):
        metadata_1 = IOS_APP_METADATA
        metadata_2 = project_management.IOSAppMetadata(
            bundle_id='different',
            name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
            app_id='1:12345678:android:deadbeef',
            display_name='My iOS App',
            project_id='test-project-id')
        metadata_3 = project_management.IOSAppMetadata(
            bundle_id='com.hello.world.ios',
            name='different',
            app_id='1:12345678:android:deadbeef',
            display_name='My iOS App',
            project_id='test-project-id')
        metadata_4 = project_management.IOSAppMetadata(
            bundle_id='com.hello.world.ios',
            name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
            app_id='different',
            display_name='My iOS App',
            project_id='test-project-id')
        metadata_5 = project_management.IOSAppMetadata(
            bundle_id='com.hello.world.ios',
            name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
            app_id='1:12345678:android:deadbeef',
            display_name='different',
            project_id='test-project-id')
        metadata_6 = project_management.IOSAppMetadata(
            bundle_id='com.hello.world.ios',
            name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
            app_id='1:12345678:android:deadbeef',
            display_name='My iOS App',
            project_id='different')
        metadata_7 = project_management.IOSAppMetadata(
            bundle_id='com.hello.world.ios',
            name='projects/test-project-id/iosApps/1:12345678:ios:ca5cade5',
            app_id='1:12345678:android:deadbeef',
            display_name='My iOS App',
            project_id='test-project-id')
        android_metadata = ANDROID_APP_METADATA

        # Don't trigger __ne__.
        assert not metadata_1 == android_metadata  # pylint: disable=unneeded-not
        assert metadata_1 != android_metadata
        assert metadata_1 != metadata_2
        assert metadata_1 != metadata_3
        assert metadata_1 != metadata_4
        assert metadata_1 != metadata_5
        assert metadata_1 != metadata_6
        assert metadata_1 == metadata_7
        assert set([metadata_1, metadata_2, metadata_7]) == set([metadata_1, metadata_2])

    def test_ios_app_metadata_bundle_id(self):
        assert IOS_APP_METADATA.bundle_id == 'com.hello.world.ios'

    def test_ios_app_metadata_name(self):
        assert IOS_APP_METADATA._name == 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5'

    def test_ios_app_metadata_app_id(self):
        assert IOS_APP_METADATA.app_id == '1:12345678:android:deadbeef'

    def test_ios_app_metadata_display_name(self):
        assert IOS_APP_METADATA.display_name == 'My iOS App'

    def test_ios_app_metadata_project_id(self):
        assert IOS_APP_METADATA.project_id == 'test-project-id'


class TestSHACertificate:
    def test_create_sha_certificate_errors(self):
        # sha_hash cannot be None.
        with pytest.raises(ValueError):
            project_management.SHACertificate(sha_hash=None)
        # sha_hash must be a string.
        with pytest.raises(ValueError):
            project_management.SHACertificate(sha_hash=0x123456789a123456789a123456789a123456789a)
        # sha_hash must be a valid SHA-1 or SHA-256 hash.
        with pytest.raises(ValueError):
            project_management.SHACertificate(sha_hash='123456789a123456789')
        with pytest.raises(ValueError):
            project_management.SHACertificate(sha_hash='123456789a123456789a123456789a123456oops')

    def test_sha_certificate_eq(self):
        sha_cert_1 = project_management.SHACertificate(
            '123456789a123456789a123456789a123456789a',
            'projects/-/androidApps/1:12345678:android:deadbeef/sha/name1')
        # sha_hash is different from sha_cert_1, but name is the same.
        sha_cert_2 = project_management.SHACertificate(
            '0000000000000000000000000000000000000000',
            'projects/-/androidApps/1:12345678:android:deadbeef/sha/name1')
        # name is different from sha_cert_1, but sha_hash is the same.
        sha_cert_3 = project_management.SHACertificate(
            '123456789a123456789a123456789a123456789a', None)
        # name is different from sha_cert_1, but sha_hash is the same.
        sha_cert_4 = project_management.SHACertificate(
            '123456789a123456789a123456789a123456789a', 'projects/-/androidApps/{0}/sha/notname1')
        # sha_hash and cert_type are different from sha_cert_1, but name is the same.
        sha_cert_5 = project_management.SHACertificate(
            '123456789a123456789a123456789a123456789a123456789a123456789a1234',
            'projects/-/androidApps/{0}/sha/name1')
        # Exactly the same as sha_cert_1.
        sha_cert_6 = project_management.SHACertificate(
            '123456789a123456789a123456789a123456789a',
            'projects/-/androidApps/1:12345678:android:deadbeef/sha/name1')
        not_a_sha_cert = {
            'name': 'projects/-/androidApps/1:12345678:android:deadbeef/sha/name1',
            'sha_hash': '123456789a123456789a123456789a123456789a',
            'cert_type': 'SHA_1',
        }

        assert sha_cert_1 != sha_cert_2
        assert sha_cert_1 != sha_cert_3
        assert sha_cert_1 != sha_cert_4
        assert sha_cert_1 != sha_cert_5
        assert sha_cert_1 == sha_cert_6
        # Don't trigger __ne__.
        assert not sha_cert_1 == not_a_sha_cert  # pylint: disable=unneeded-not
        assert sha_cert_1 != not_a_sha_cert

    def test_sha_certificate_name(self):
        assert (SHA_1_CERTIFICATE.name ==
                'projects/-/androidApps/1:12345678:android:deadbeef/sha/name1')
        assert (SHA_256_CERTIFICATE.name ==
                'projects/-/androidApps/1:12345678:android:deadbeef/sha/name256')

    def test_sha_certificate_sha_hash(self):
        assert (SHA_1_CERTIFICATE.sha_hash ==
                '123456789a123456789a123456789a123456789a')
        assert (SHA_256_CERTIFICATE.sha_hash ==
                '123456789a123456789a123456789a123456789a123456789a123456789a1234')

    def test_sha_certificate_cert_type(self):
        assert SHA_1_CERTIFICATE.cert_type == 'SHA_1'
        assert SHA_256_CERTIFICATE.cert_type == 'SHA_256'


class BaseProjectManagementTest:
    @classmethod
    def setup_class(cls):
        project_management._ProjectManagementService.POLL_BASE_WAIT_TIME_SECONDS = 0.01
        project_management._ProjectManagementService.MAXIMUM_POLLING_ATTEMPTS = 3
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
        client_version = 'Python/Admin/{0}'.format(firebase_admin.__version__)
        assert request.headers['X-Client-Version'] == client_version
        if expected_body is None:
            assert request.body is None
        else:
            assert json.loads(request.body.decode()) == expected_body


class TestTimeout(BaseProjectManagementTest):

    def test_default_timeout(self):
        app = firebase_admin.get_app()
        project_management_service = project_management._get_project_management_service(app)
        assert project_management_service._client.timeout == _http_client.DEFAULT_TIMEOUT_SECONDS

    @pytest.mark.parametrize('timeout', [4, None])
    def test_custom_timeout(self, timeout):
        options = {
            'httpTimeout': timeout,
            'projectId': 'test-project-id'
        }
        app = firebase_admin.initialize_app(
            testutils.MockCredential(), options, 'timeout-{0}'.format(timeout))
        project_management_service = project_management._get_project_management_service(app)
        assert project_management_service._client.timeout == timeout


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
        recorder = self._instrument_service(statuses=[409], responses=[ALREADY_EXISTS_RESPONSE])

        with pytest.raises(exceptions.AlreadyExistsError) as excinfo:
            project_management.create_android_app(
                package_name='com.hello.world.android',
                display_name='My Android App')

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_create_android_app_polling_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 503],  # Error 503 means that backend servers are over capacity.
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                UNAVAILABLE_RESPONSE,  # Error 503.
            ])

        with pytest.raises(exceptions.UnavailableError) as excinfo:
            project_management.create_android_app(
                package_name='com.hello.world.android',
                display_name='My Android App')

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 3

    def test_create_android_app_polling_failure(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create Android app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                OPERATION_FAILED_RESPONSE,  # Operation is finished, but terminated with an error.
            ])

        with pytest.raises(exceptions.UnknownError) as excinfo:
            project_management.create_android_app(
                package_name='com.hello.world.android',
                display_name='My Android App')

        assert 'Polling finished, but the operation terminated in an error' in str(excinfo.value)
        assert excinfo.value.cause is None
        assert excinfo.value.http_response is not None
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

        with pytest.raises(exceptions.DeadlineExceededError) as excinfo:
            project_management.create_android_app(
                package_name='com.hello.world.android',
                display_name='My Android App')

        assert 'Polling deadline exceeded' in str(excinfo.value)
        assert excinfo.value.cause is None
        assert len(recorder) == 3


class TestCreateIOSApp(BaseProjectManagementTest):
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
        self._assert_request_is_correct(recorder[0], 'POST', TestCreateIOSApp._CREATION_URL, body)
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
        self._assert_request_is_correct(recorder[0], 'POST', TestCreateIOSApp._CREATION_URL, body)
        self._assert_request_is_correct(
            recorder[1], 'GET', 'https://firebase.googleapis.com/v1/operations/abcdefg')
        self._assert_request_is_correct(
            recorder[2], 'GET', 'https://firebase.googleapis.com/v1/operations/abcdefg')

    def test_create_ios_app_already_exists(self):
        recorder = self._instrument_service(statuses=[409], responses=[ALREADY_EXISTS_RESPONSE])

        with pytest.raises(exceptions.AlreadyExistsError) as excinfo:
            project_management.create_ios_app(
                bundle_id='com.hello.world.ios',
                display_name='My iOS App')

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_create_ios_app_polling_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 503],  # Error 503 means that backend servers are over capacity.
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                UNAVAILABLE_RESPONSE,  # Error 503.
            ])

        with pytest.raises(exceptions.UnavailableError) as excinfo:
            project_management.create_ios_app(
                bundle_id='com.hello.world.ios',
                display_name='My iOS App')

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 3

    def test_create_ios_app_polling_failure(self):
        recorder = self._instrument_service(
            statuses=[200, 200, 200],
            responses=[
                OPERATION_IN_PROGRESS_RESPONSE,  # Request to create iOS app asynchronously.
                OPERATION_IN_PROGRESS_RESPONSE,  # Creation operation is still not done.
                OPERATION_FAILED_RESPONSE,  # Operation is finished, but terminated with an error.
            ])

        with pytest.raises(exceptions.UnknownError) as excinfo:
            project_management.create_ios_app(
                bundle_id='com.hello.world.ios',
                display_name='My iOS App')

        assert 'Polling finished, but the operation terminated in an error' in str(excinfo.value)
        assert excinfo.value.cause is None
        assert excinfo.value.http_response is not None
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

        with pytest.raises(exceptions.DeadlineExceededError) as excinfo:
            project_management.create_ios_app(
                bundle_id='com.hello.world.ios',
                display_name='My iOS App')

        assert 'Polling deadline exceeded' in str(excinfo.value)
        assert excinfo.value.cause is None
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
        recorder = self._instrument_service(statuses=[503], responses=[UNAVAILABLE_RESPONSE])

        with pytest.raises(exceptions.UnavailableError) as excinfo:
            project_management.list_android_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_list_android_apps_empty_list(self):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps(dict())])

        android_apps = project_management.list_android_apps()

        assert android_apps == []
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestListAndroidApps._LISTING_URL)

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
            responses=[LIST_ANDROID_APPS_PAGE_1_RESPONSE, UNAVAILABLE_RESPONSE])

        with pytest.raises(exceptions.UnavailableError) as excinfo:
            project_management.list_android_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 2


class TestListIOSApps(BaseProjectManagementTest):
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
        self._assert_request_is_correct(recorder[0], 'GET', TestListIOSApps._LISTING_URL)

    def test_list_ios_apps_rpc_error(self):
        recorder = self._instrument_service(statuses=[503], responses=[UNAVAILABLE_RESPONSE])

        with pytest.raises(exceptions.UnavailableError) as excinfo:
            project_management.list_ios_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_list_ios_apps_empty_list(self):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps(dict())])

        ios_apps = project_management.list_ios_apps()

        assert ios_apps == []
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestListIOSApps._LISTING_URL)

    def test_list_ios_apps_multiple_pages(self):
        recorder = self._instrument_service(
            statuses=[200, 200],
            responses=[LIST_IOS_APPS_PAGE_1_RESPONSE, LIST_IOS_APPS_PAGE_2_RESPONSE])

        ios_apps = project_management.list_ios_apps()

        expected_app_ids = set(['1:12345678:ios:ca5cade5', '1:12345678:ios:ca5cade5cafe'])
        assert set(app.app_id for app in ios_apps) == expected_app_ids
        assert len(recorder) == 2
        self._assert_request_is_correct(recorder[0], 'GET', TestListIOSApps._LISTING_URL)
        self._assert_request_is_correct(recorder[1], 'GET', TestListIOSApps._LISTING_PAGE_2_URL)

    def test_list_ios_apps_multiple_pages_rpc_error(self):
        recorder = self._instrument_service(
            statuses=[200, 503],
            responses=[LIST_IOS_APPS_PAGE_1_RESPONSE, UNAVAILABLE_RESPONSE])

        with pytest.raises(exceptions.UnavailableError) as excinfo:
            project_management.list_ios_apps()

        assert 'Backend servers are over capacity' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
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
    _DELETE_SHA_1_CERT_URL = ('https://firebase.googleapis.com/v1beta1/projects/-/androidApps/'
                              '1:12345678:android:deadbeef/sha/name1')
    _DELETE_SHA_256_CERT_URL = ('https://firebase.googleapis.com/v1beta1/projects/-/androidApps/'
                                '1:12345678:android:deadbeef/sha/name256')

    @pytest.fixture
    def android_app(self):
        return project_management.android_app('1:12345678:android:deadbeef')

    def test_get_metadata_no_display_name(self, android_app):
        recorder = self._instrument_service(
            statuses=[200], responses=[ANDROID_APP_NO_DISPLAY_NAME_METADATA_RESPONSE])

        metadata = android_app.get_metadata()

        assert metadata._name == 'projects/test-project-id/androidApps/1:12345678:android:deadbeef'
        assert metadata.app_id == '1:12345678:android:deadbeef'
        assert metadata.display_name is None
        assert metadata.project_id == 'test-project-id'
        assert metadata.package_name == 'com.hello.world.android'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._GET_METADATA_URL)

    def test_get_metadata(self, android_app):
        recorder = self._instrument_service(
            statuses=[200], responses=[ANDROID_APP_METADATA_RESPONSE])

        metadata = android_app.get_metadata()

        assert metadata._name == 'projects/test-project-id/androidApps/1:12345678:android:deadbeef'
        assert metadata.app_id == '1:12345678:android:deadbeef'
        assert metadata.display_name == 'My Android App'
        assert metadata.project_id == 'test-project-id'
        assert metadata.package_name == 'com.hello.world.android'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._GET_METADATA_URL)

    def test_get_metadata_unknown_error(self, android_app):
        recorder = self._instrument_service(
            statuses=[428], responses=['precondition required error'])

        with pytest.raises(exceptions.UnknownError) as excinfo:
            android_app.get_metadata()

        message = 'Unexpected HTTP response with status: 428; body: precondition required error'
        assert str(excinfo.value) == message
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_get_metadata_not_found(self, android_app):
        recorder = self._instrument_service(statuses=[404], responses=[NOT_FOUND_RESPONSE])

        with pytest.raises(exceptions.NotFoundError) as excinfo:
            android_app.get_metadata()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
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
        recorder = self._instrument_service(statuses=[404], responses=[NOT_FOUND_RESPONSE])
        new_display_name = 'A new display name!'

        with pytest.raises(exceptions.NotFoundError) as excinfo:
            android_app.set_display_name(new_display_name)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_get_config(self, android_app):
        recorder = self._instrument_service(statuses=[200], responses=[TEST_APP_CONFIG_RESPONSE])

        config = android_app.get_config()

        assert config == 'hello world'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._GET_CONFIG_URL)

    def test_get_config_not_found(self, android_app):
        recorder = self._instrument_service(statuses=[404], responses=[NOT_FOUND_RESPONSE])

        with pytest.raises(exceptions.NotFoundError) as excinfo:
            android_app.get_config()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_get_sha_certificates(self, android_app):
        recorder = self._instrument_service(
            statuses=[200], responses=[GET_SHA_CERTIFICATES_RESPONSE])

        certs = android_app.get_sha_certificates()

        assert set(certs) == set([SHA_1_CERTIFICATE, SHA_256_CERTIFICATE])
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestAndroidApp._LIST_CERTS_URL)

    def test_get_sha_certificates_not_found(self, android_app):
        recorder = self._instrument_service(statuses=[404], responses=[NOT_FOUND_RESPONSE])

        with pytest.raises(exceptions.NotFoundError) as excinfo:
            android_app.get_sha_certificates()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_add_certificate_none_error(self, android_app):
        with pytest.raises(ValueError):
            android_app.add_sha_certificate(None)

    def test_add_sha_1_certificate(self, android_app):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps({})])

        android_app.add_sha_certificate(
            project_management.SHACertificate('123456789a123456789a123456789a123456789a'))

        assert len(recorder) == 1
        body = {'shaHash': '123456789a123456789a123456789a123456789a', 'certType': 'SHA_1'}
        self._assert_request_is_correct(recorder[0], 'POST', TestAndroidApp._ADD_CERT_URL, body)

    def test_add_sha_256_certificate(self, android_app):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps({})])

        android_app.add_sha_certificate(project_management.SHACertificate(
            '123456789a123456789a123456789a123456789a123456789a123456789a1234'))

        assert len(recorder) == 1
        body = {
            'shaHash': '123456789a123456789a123456789a123456789a123456789a123456789a1234',
            'certType': 'SHA_256',
        }
        self._assert_request_is_correct(recorder[0], 'POST', TestAndroidApp._ADD_CERT_URL, body)

    def test_add_sha_certificates_already_exists(self, android_app):
        recorder = self._instrument_service(statuses=[409], responses=[ALREADY_EXISTS_RESPONSE])

        with pytest.raises(exceptions.AlreadyExistsError) as excinfo:
            android_app.add_sha_certificate(
                project_management.SHACertificate('123456789a123456789a123456789a123456789a'))

        assert 'The resource already exists' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
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
        recorder = self._instrument_service(statuses=[404], responses=[NOT_FOUND_RESPONSE])

        with pytest.raises(exceptions.NotFoundError) as excinfo:
            android_app.delete_sha_certificate(SHA_1_CERTIFICATE)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_raises_if_app_has_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')

            with pytest.raises(ValueError):
                project_management.android_app(app_id='1:12345678:android:deadbeef', app=app)

        testutils.run_without_project_id(evaluate)


class TestIOSApp(BaseProjectManagementTest):
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

        assert metadata._name == 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5'
        assert metadata.app_id == '1:12345678:ios:ca5cade5'
        assert metadata.display_name is None
        assert metadata.project_id == 'test-project-id'
        assert metadata.bundle_id == 'com.hello.world.ios'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestIOSApp._GET_METADATA_URL)

    def test_get_metadata(self, ios_app):
        recorder = self._instrument_service(statuses=[200], responses=[IOS_APP_METADATA_RESPONSE])

        metadata = ios_app.get_metadata()

        assert metadata._name == 'projects/test-project-id/iosApps/1:12345678:ios:ca5cade5'
        assert metadata.app_id == '1:12345678:ios:ca5cade5'
        assert metadata.display_name == 'My iOS App'
        assert metadata.project_id == 'test-project-id'
        assert metadata.bundle_id == 'com.hello.world.ios'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestIOSApp._GET_METADATA_URL)

    def test_get_metadata_unknown_error(self, ios_app):
        recorder = self._instrument_service(
            statuses=[428], responses=['precondition required error'])

        with pytest.raises(exceptions.UnknownError) as excinfo:
            ios_app.get_metadata()

        message = 'Unexpected HTTP response with status: 428; body: precondition required error'
        assert str(excinfo.value) == message
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_get_metadata_not_found(self, ios_app):
        recorder = self._instrument_service(statuses=[404], responses=[NOT_FOUND_RESPONSE])

        with pytest.raises(exceptions.NotFoundError) as excinfo:
            ios_app.get_metadata()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_set_display_name(self, ios_app):
        recorder = self._instrument_service(statuses=[200], responses=[json.dumps({})])
        new_display_name = 'A new display name!'

        ios_app.set_display_name(new_display_name)

        assert len(recorder) == 1
        body = {'displayName': new_display_name}
        self._assert_request_is_correct(
            recorder[0], 'PATCH', TestIOSApp._SET_DISPLAY_NAME_URL, body)

    def test_set_display_name_not_found(self, ios_app):
        recorder = self._instrument_service(statuses=[404], responses=[NOT_FOUND_RESPONSE])
        new_display_name = 'A new display name!'

        with pytest.raises(exceptions.NotFoundError) as excinfo:
            ios_app.set_display_name(new_display_name)

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_get_config(self, ios_app):
        recorder = self._instrument_service(statuses=[200], responses=[TEST_APP_CONFIG_RESPONSE])

        config = ios_app.get_config()

        assert config == 'hello world'
        assert len(recorder) == 1
        self._assert_request_is_correct(recorder[0], 'GET', TestIOSApp._GET_CONFIG_URL)

    def test_get_config_not_found(self, ios_app):
        recorder = self._instrument_service(statuses=[404], responses=[NOT_FOUND_RESPONSE])

        with pytest.raises(exceptions.NotFoundError) as excinfo:
            ios_app.get_config()

        assert 'Failed to find the resource' in str(excinfo.value)
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1

    def test_raises_if_app_has_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')

            with pytest.raises(ValueError):
                project_management.ios_app(app_id='1:12345678:ios:ca5cade5', app=app)

        testutils.run_without_project_id(evaluate)
