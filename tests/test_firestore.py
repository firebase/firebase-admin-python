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

import pytest

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from tests import testutils


def teardown_function():
    testutils.cleanup_apps()

def test_no_project_id():
    firebase_admin.initialize_app(testutils.MockCredential())
    with pytest.raises(ValueError):
        firestore.client()

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
