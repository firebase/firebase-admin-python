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

import pytest

from firebase_admin import project_management


TEST_APP_PACKAGE_NAME = 'com.firebase.adminsdk_python_integration_test'
TEST_APP_DISPLAY_NAME_PREFIX = 'Created By Firebase AdminSDK Python Integration Testing'


@pytest.fixture(scope='module')
def test_android_app(default_app):
    android_apps = project_management.list_android_apps()
    for android_app in android_apps:
        if android_app.get_metadata().display_name.startswith(TEST_APP_DISPLAY_NAME_PREFIX):
            return android_app
    return project_management.create_android_app(
        package_name=TEST_APP_PACKAGE_NAME, display_name=TEST_APP_DISPLAY_NAME_PREFIX)


def test_get_android_app_metadata(test_android_app, project_id):
    app_id = test_android_app.app_id
    metadata = project_management.android_app(app_id).get_metadata()

    assert metadata.name == 'projects/{0}/androidApps/{1}'.format(project_id, app_id)
    assert metadata.app_id == app_id
    assert metadata.project_id == project_id
    assert metadata.display_name == TEST_APP_DISPLAY_NAME_PREFIX
    assert metadata.package_name == TEST_APP_PACKAGE_NAME


def test_list_android_apps(test_android_app):
    android_apps = project_management.list_android_apps()
    for android_app in android_apps:
        if android_app.get_metadata().display_name.startswith(TEST_APP_DISPLAY_NAME_PREFIX):
            found = True
            break
    assert found
