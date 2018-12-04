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

"""Integration tests for the firebase_admin.project_management module."""

import json
import plistlib
import random

import pytest

from firebase_admin import project_management


TEST_APP_BUNDLE_ID = 'com.firebase.adminsdk-python-integration-test'
TEST_APP_PACKAGE_NAME = 'com.firebase.adminsdk_python_integration_test'
TEST_APP_DISPLAY_NAME_PREFIX = 'Created By Firebase AdminSDK Python Integration Testing'

SHA_1_HASH_1 = '123456789a123456789a123456789a123456789a'
SHA_1_HASH_2 = 'aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb'
SHA_256_HASH_1 = '123456789a123456789a123456789a123456789a123456789a123456789a1234'
SHA_256_HASH_2 = 'cafef00dba5eba11b01dfaceacc01adeda7aba5eca55e77e0b57ac1e5ca1ab1e'
SHA_1 = project_management.ShaCertificate.SHA_1
SHA_256 = project_management.ShaCertificate.SHA_256


def _starts_with(display_name, prefix):
    return display_name and display_name.startswith(prefix)


@pytest.fixture(scope='module')
def android_app(default_app):
    del default_app
    android_apps = project_management.list_android_apps()
    for android_app in android_apps:
        if _starts_with(android_app.get_metadata().display_name, TEST_APP_DISPLAY_NAME_PREFIX):
            return android_app
    return project_management.create_android_app(
        package_name=TEST_APP_PACKAGE_NAME, display_name=TEST_APP_DISPLAY_NAME_PREFIX)


@pytest.fixture(scope='module')
def ios_app(default_app):
    del default_app
    ios_apps = project_management.list_ios_apps()
    for ios_app in ios_apps:
        if _starts_with(ios_app.get_metadata().display_name, TEST_APP_DISPLAY_NAME_PREFIX):
            return ios_app
    return project_management.create_ios_app(
        bundle_id=TEST_APP_BUNDLE_ID, display_name=TEST_APP_DISPLAY_NAME_PREFIX)


def test_create_android_app_already_exists(android_app):
    del android_app

    with pytest.raises(project_management.ApiCallError) as excinfo:
        project_management.create_android_app(
            package_name=TEST_APP_PACKAGE_NAME, display_name=TEST_APP_DISPLAY_NAME_PREFIX)
    assert 'The resource already exists' in str(excinfo.value)
    assert excinfo.value.detail is not None


def test_android_set_display_name_and_get_metadata(android_app, project_id):
    app_id = android_app.app_id
    android_app = project_management.android_app(app_id)
    new_display_name = '{0} helloworld {1}'.format(
        TEST_APP_DISPLAY_NAME_PREFIX, random.randint(0, 10000))

    android_app.set_display_name(new_display_name)
    metadata = project_management.android_app(app_id).get_metadata()
    android_app.set_display_name(TEST_APP_DISPLAY_NAME_PREFIX)  # Revert the display name.

    assert metadata._name == 'projects/{0}/androidApps/{1}'.format(project_id, app_id)
    assert metadata.app_id == app_id
    assert metadata.project_id == project_id
    assert metadata.display_name == new_display_name
    assert metadata.package_name == TEST_APP_PACKAGE_NAME


def test_list_android_apps(android_app):
    del android_app

    android_apps = project_management.list_android_apps()

    assert any(_starts_with(android_app.get_metadata().display_name, TEST_APP_DISPLAY_NAME_PREFIX)
               for android_app in android_apps)


def test_get_android_app_config(android_app, project_id):
    config = android_app.get_config()

    json_config = json.loads(config)
    assert json_config['project_info']['project_id'] == project_id
    for client in json_config['client']:
        client_info = client['client_info']
        if client_info['mobilesdk_app_id'] == android_app.app_id:
            assert client_info['android_client_info']['package_name'] == TEST_APP_PACKAGE_NAME
            break
    else:
        pytest.fail('Failed to find the test Android app in the Android config.')


def test_android_sha_certificates(android_app):
    """Tests all of get_sha_certificates, add_sha_certificate, and delete_sha_certificate."""
    # Delete all existing certs.
    for cert in android_app.get_sha_certificates():
        android_app.delete_sha_certificate(cert)

    # Add four different certs and assert that they have all been added successfully.
    android_app.add_sha_certificate(project_management.ShaCertificate(SHA_1_HASH_1))
    android_app.add_sha_certificate(project_management.ShaCertificate(SHA_1_HASH_2))
    android_app.add_sha_certificate(project_management.ShaCertificate(SHA_256_HASH_1))
    android_app.add_sha_certificate(project_management.ShaCertificate(SHA_256_HASH_2))

    cert_list = android_app.get_sha_certificates()

    sha_1_hashes = set(cert.sha_hash for cert in cert_list if cert.cert_type == SHA_1)
    sha_256_hashes = set(cert.sha_hash for cert in cert_list if cert.cert_type == SHA_256)
    assert sha_1_hashes == set([SHA_1_HASH_1, SHA_1_HASH_2])
    assert sha_256_hashes == set([SHA_256_HASH_1, SHA_256_HASH_2])
    for cert in cert_list:
        assert cert.name

    # Adding the same cert twice should cause an already-exists error.
    with pytest.raises(project_management.ApiCallError) as excinfo:
        android_app.add_sha_certificate(project_management.ShaCertificate(SHA_256_HASH_2))
    assert 'The resource already exists' in str(excinfo.value)
    assert excinfo.value.detail is not None

    # Delete all certs and assert that they have all been deleted successfully.
    for cert in cert_list:
        android_app.delete_sha_certificate(cert)

    assert android_app.get_sha_certificates() == []

    # Deleting a nonexistent cert should cause a not-found error.
    with pytest.raises(project_management.ApiCallError) as excinfo:
        android_app.delete_sha_certificate(cert_list[0])
    assert 'Failed to find the resource' in str(excinfo.value)
    assert excinfo.value.detail is not None


def test_create_ios_app_already_exists(ios_app):
    del ios_app

    with pytest.raises(project_management.ApiCallError) as excinfo:
        project_management.create_ios_app(
            bundle_id=TEST_APP_BUNDLE_ID, display_name=TEST_APP_DISPLAY_NAME_PREFIX)
    assert 'The resource already exists' in str(excinfo.value)
    assert excinfo.value.detail is not None


def test_ios_set_display_name_and_get_metadata(ios_app, project_id):
    app_id = ios_app.app_id
    ios_app = project_management.ios_app(app_id)
    new_display_name = '{0} helloworld {1}'.format(
        TEST_APP_DISPLAY_NAME_PREFIX, random.randint(0, 10000))

    ios_app.set_display_name(new_display_name)
    metadata = project_management.ios_app(app_id).get_metadata()
    ios_app.set_display_name(TEST_APP_DISPLAY_NAME_PREFIX)  # Revert the display name.

    assert metadata._name == 'projects/{0}/iosApps/{1}'.format(project_id, app_id)
    assert metadata.app_id == app_id
    assert metadata.project_id == project_id
    assert metadata.display_name == new_display_name
    assert metadata.bundle_id == TEST_APP_BUNDLE_ID


def test_list_ios_apps(ios_app):
    del ios_app

    ios_apps = project_management.list_ios_apps()

    assert any(_starts_with(ios_app.get_metadata().display_name, TEST_APP_DISPLAY_NAME_PREFIX)
               for ios_app in ios_apps)


def test_get_ios_app_config(ios_app, project_id):
    config = ios_app.get_config()

    # In Python 2.7, the plistlib module works with strings, while in Python 3, it is significantly
    # redesigned and works with bytes objects instead.
    try:
        plist = plistlib.loads(config.encode('utf-8'))
    except AttributeError:  # Python 2.7 plistlib does not have the loads attribute.
        plist = plistlib.readPlistFromString(config)  # pylint: disable=no-member
    assert plist['BUNDLE_ID'] == TEST_APP_BUNDLE_ID
    assert plist['PROJECT_ID'] == project_id
    assert plist['GOOGLE_APP_ID'] == ios_app.app_id
