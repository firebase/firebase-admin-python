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

import random

import pytest

from firebase_admin import project_management


TEST_APP_BUNDLE_ID = 'com.firebase.adminsdk-python-integration-test'
TEST_APP_PACKAGE_NAME = 'com.firebase.adminsdk_python_integration_test'
TEST_APP_DISPLAY_NAME_PREFIX = 'Created By Firebase AdminSDK Python Integration Testing'

SHA_1_HASH_1 = '123456789a123456789a123456789a123456789a'
SHA_1_HASH_2 = 'aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb'
SHA_256_HASH_1 = '123456789a123456789a123456789a123456789a123456789a123456789a1234'
SHA_256_HASH_2 = 'cafef00dba5eba11b01dfaceacc01adeda7aba5eca5ecade0b57ac1e5ca1ab1e'
SHA_1 = project_management.ShaCertificate.SHA_1
SHA_256 = project_management.ShaCertificate.SHA_256


@pytest.fixture(scope='module')
def test_android_app(default_app):
    del default_app
    android_apps = project_management.list_android_apps()
    for android_app in android_apps:
        if android_app.get_metadata().display_name.startswith(TEST_APP_DISPLAY_NAME_PREFIX):
            return android_app
    return project_management.create_android_app(
        package_name=TEST_APP_PACKAGE_NAME, display_name=TEST_APP_DISPLAY_NAME_PREFIX)


@pytest.fixture(scope='module')
def test_ios_app(default_app):
    del default_app
    ios_apps = project_management.list_ios_apps()
    for ios_app in ios_apps:
        if ios_app.get_metadata().display_name.startswith(TEST_APP_DISPLAY_NAME_PREFIX):
            return ios_app
    return project_management.create_ios_app(
        bundle_id=TEST_APP_BUNDLE_ID, display_name=TEST_APP_DISPLAY_NAME_PREFIX)


def test_create_android_app_already_exists(test_android_app):
    del test_android_app

    try:
        project_management.create_android_app(
            package_name=TEST_APP_PACKAGE_NAME, display_name=TEST_APP_DISPLAY_NAME_PREFIX)
        assert False, 'Failed to raise ApiCallError.'
    except project_management.ApiCallError as error:
        assert 'The resource already exists' in str(error)


def test_android_set_display_name_and_get_metadata(test_android_app, project_id):
    app_id = test_android_app.app_id
    android_app = project_management.android_app(app_id)
    new_display_name = '{0} helloworld {1}'.format(
        TEST_APP_DISPLAY_NAME_PREFIX, random.randint(0, 10000))

    android_app.set_display_name(new_display_name)
    metadata = project_management.android_app(app_id).get_metadata()
    android_app.set_display_name(TEST_APP_DISPLAY_NAME_PREFIX)  # Revert the display name.

    assert metadata.name == 'projects/{0}/androidApps/{1}'.format(project_id, app_id)
    assert metadata.app_id == app_id
    assert metadata.project_id == project_id
    assert metadata.display_name == new_display_name
    assert metadata.package_name == TEST_APP_PACKAGE_NAME


def test_list_android_apps(test_android_app):
    del test_android_app

    android_apps = project_management.list_android_apps()

    for android_app in android_apps:
        if android_app.get_metadata().display_name.startswith(TEST_APP_DISPLAY_NAME_PREFIX):
            found = True
            break
    assert found


def test_android_sha_certificates(test_android_app):
    """Tests all of get_sha_certificates, add_sha_certificate, and delete_sha_certificate."""
    # Delete all existing certs.
    for cert in test_android_app.get_sha_certificates():
        test_android_app.delete_sha_certificate(cert)

    # Add four different certs and assert that they have all been added successfully.
    test_android_app.add_sha_certificate(project_management.ShaCertificate(SHA_1_HASH_1))
    test_android_app.add_sha_certificate(project_management.ShaCertificate(SHA_1_HASH_2))
    test_android_app.add_sha_certificate(project_management.ShaCertificate(SHA_256_HASH_1))
    test_android_app.add_sha_certificate(project_management.ShaCertificate(SHA_256_HASH_2))

    cert_list = test_android_app.get_sha_certificates()

    sha_1_hashes = set(cert.sha_hash for cert in cert_list if cert.cert_type == SHA_1)
    sha_256_hashes = set(cert.sha_hash for cert in cert_list if cert.cert_type == SHA_256)
    assert sha_1_hashes == set([SHA_1_HASH_1, SHA_1_HASH_2])
    assert sha_256_hashes == set([SHA_256_HASH_1, SHA_256_HASH_2])
    for cert in cert_list:
        assert cert.name

    # Adding the same cert twice should cause an already-exists error.
    try:
        test_android_app.add_sha_certificate(project_management.ShaCertificate(SHA_256_HASH_2))
        assert False, 'Failed to raise ApiCallError.'
    except project_management.ApiCallError as error:
        assert 'The resource already exists' in str(error)

    # Delete all certs and assert that they have all been deleted successfully.
    for cert in cert_list:
        test_android_app.delete_sha_certificate(cert)

    assert test_android_app.get_sha_certificates() == []

    # Deleting a nonexistent cert should cause a not-found error.
    try:
        test_android_app.delete_sha_certificate(cert_list[0])
        assert False, 'Failed to raise ApiCallError.'
    except project_management.ApiCallError as error:
        assert 'Failed to find the resource' in str(error)


def test_create_ios_app_already_exists(test_ios_app):
    del test_ios_app

    try:
        project_management.create_ios_app(
            bundle_id=TEST_APP_BUNDLE_ID, display_name=TEST_APP_DISPLAY_NAME_PREFIX)
        assert False, 'Failed to raise ApiCallError.'
    except project_management.ApiCallError as error:
        assert 'The resource already exists' in str(error)


def test_ios_set_display_name_and_get_metadata(test_ios_app, project_id):
    app_id = test_ios_app.app_id
    ios_app = project_management.ios_app(app_id)
    new_display_name = '{0} helloworld {1}'.format(
        TEST_APP_DISPLAY_NAME_PREFIX, random.randint(0, 10000))

    ios_app.set_display_name(new_display_name)
    metadata = project_management.ios_app(app_id).get_metadata()
    ios_app.set_display_name(TEST_APP_DISPLAY_NAME_PREFIX)  # Revert the display name.

    assert metadata.name == 'projects/{0}/iosApps/{1}'.format(project_id, app_id)
    assert metadata.app_id == app_id
    assert metadata.project_id == project_id
    assert metadata.display_name == new_display_name
    assert metadata.bundle_id == TEST_APP_BUNDLE_ID


def test_list_ios_apps(test_ios_app):
    del test_ios_app

    ios_apps = project_management.list_ios_apps()

    for ios_app in ios_apps:
        if ios_app.get_metadata().display_name.startswith(TEST_APP_DISPLAY_NAME_PREFIX):
            found = True
            break
    assert found
