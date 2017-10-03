# Copyright 2017 Google Inc.
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

"""Tests for firebase_admin.firestore."""

import os

import pytest

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from tests import testutils


def teardown_function():
    testutils.cleanup_apps()

def test_no_project_id():
    env_var = 'GCLOUD_PROJECT'
    gcloud_project = os.environ.get(env_var)
    if gcloud_project:
        del os.environ[env_var]
    try:
        firebase_admin.initialize_app(testutils.MockCredential())
        with pytest.raises(ValueError):
            firestore.client()
    finally:
        if gcloud_project:
            os.environ[env_var] = gcloud_project

def test_project_id():
    cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
    firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
    client = firestore.client()
    assert client is not None
    assert client.project == 'explicit-project-id'

def test_project_id_with_explicit_app():
    cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
    app = firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
    client = firestore.client(app=app)
    assert client is not None
    assert client.project == 'explicit-project-id'

def test_service_account():
    cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
    firebase_admin.initialize_app(cred)
    client = firestore.client()
    assert client is not None
    assert client.project == 'mock-project-id'

def test_service_account_with_explicit_app():
    cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
    app = firebase_admin.initialize_app(cred)
    client = firestore.client(app=app)
    assert client is not None
    assert client.project == 'mock-project-id'

def test_geo_point():
    geo_point = firestore.GeoPoint(10, 20)
    assert geo_point.latitude == 10
    assert geo_point.longitude == 20

def test_server_timestamp():
    assert firestore.SERVER_TIMESTAMP is not None