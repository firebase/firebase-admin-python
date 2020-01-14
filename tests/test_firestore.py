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

import platform

import pytest

import firebase_admin
from firebase_admin import credentials
try:
    from firebase_admin import firestore
except ImportError:
    pass
from tests import testutils


@pytest.mark.skipif(
    platform.python_implementation() == 'PyPy',
    reason='Firestore is not supported on PyPy')
class TestFirestore:
    """Test class Firestore APIs."""

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_no_project_id(self):
        def evaluate():
            firebase_admin.initialize_app(testutils.MockCredential())
            with pytest.raises(ValueError):
                firestore.client()
        testutils.run_without_project_id(evaluate)

    def test_project_id(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        client = firestore.client()
        assert client is not None
        assert client.project == 'explicit-project-id'

    def test_project_id_with_explicit_app(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        app = firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        client = firestore.client(app=app)
        assert client is not None
        assert client.project == 'explicit-project-id'

    def test_service_account(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        firebase_admin.initialize_app(cred)
        client = firestore.client()
        assert client is not None
        assert client.project == 'mock-project-id'

    def test_service_account_with_explicit_app(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        app = firebase_admin.initialize_app(cred)
        client = firestore.client(app=app)
        assert client is not None
        assert client.project == 'mock-project-id'

    def test_geo_point(self):
        geo_point = firestore.GeoPoint(10, 20) # pylint: disable=no-member
        assert geo_point.latitude == 10
        assert geo_point.longitude == 20

    def test_server_timestamp(self):
        assert firestore.SERVER_TIMESTAMP is not None # pylint: disable=no-member
