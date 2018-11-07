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


def test_android_set_display_name_and_get_metadata(test_android_app, project_id):
    app_id = test_android_app.app_id
    android_app = project_management.android_app(app_id)
    new_display_name = '{0} helloworld {1}'.format(
        TEST_APP_DISPLAY_NAME_PREFIX, random.randint(0, 10000))
    android_app.set_display_name(new_display_name)
    metadata = project_management.android_app(app_id).get_metadata()
    android_app.set_display_name(TEST_APP_DISPLAY_NAME_PREFIX)

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


def test_ios_set_display_name_and_get_metadata(test_ios_app, project_id):
    app_id = test_ios_app.app_id
    ios_app = project_management.ios_app(app_id)
    new_display_name = '{0} helloworld {1}'.format(
        TEST_APP_DISPLAY_NAME_PREFIX, random.randint(0, 10000))
    ios_app.set_display_name(new_display_name)
    metadata = project_management.ios_app(app_id).get_metadata()
    ios_app.set_display_name(TEST_APP_DISPLAY_NAME_PREFIX)

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
