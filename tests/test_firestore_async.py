# Copyright 2022 Google Inc.
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

"""Tests for firebase_admin.firestore_async."""

import platform

import pytest

import firebase_admin
from firebase_admin import credentials
try:
    from firebase_admin import firestore_async
except ImportError:
    pass
from tests import testutils


@pytest.mark.skipif(
    platform.python_implementation() == 'PyPy',
    reason='Firestore is not supported on PyPy')
class TestFirestoreAsync:
    """Test class Firestore Async APIs."""

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_no_project_id(self):
        def evaluate():
            firebase_admin.initialize_app(testutils.MockCredential())
            with pytest.raises(ValueError):
                firestore_async.client()
        testutils.run_without_project_id(evaluate)

    def test_project_id(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        client = firestore_async.client()
        assert client is not None
        assert client.project == 'explicit-project-id'
        assert client._database == '(default)'

    def test_project_id_with_explicit_app(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        app = firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        client = firestore_async.client(app=app)
        assert client is not None
        assert client.project == 'explicit-project-id'
        assert client._database == '(default)'

    def test_service_account(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        firebase_admin.initialize_app(cred)
        client = firestore_async.client()
        assert client is not None
        assert client.project == 'mock-project-id'
        assert client._database == '(default)'

    def test_service_account_with_explicit_app(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        app = firebase_admin.initialize_app(cred)
        client = firestore_async.client(app=app)
        assert client is not None
        assert client.project == 'mock-project-id'
        assert client._database == '(default)'

    @pytest.mark.parametrize('database_id', [123, False, True, {}, []])
    def test_invalid_database_id(self, database_id):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        firebase_admin.initialize_app(cred)
        with pytest.raises(ValueError) as excinfo:
            firestore_async.client(database_id=database_id)
        assert str(excinfo.value) == f'database_id "{database_id}" must be a string or None.'

    def test_database_id(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        firebase_admin.initialize_app(cred)
        database_id = 'mock-database-id'
        client = firestore_async.client(database_id=database_id)
        assert client is not None
        assert client.project == 'mock-project-id'
        assert client._database == 'mock-database-id'

    @pytest.mark.parametrize('database_id', ['', '(default)', None])
    def test_database_id_with_default_id(self, database_id):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        firebase_admin.initialize_app(cred)
        client = firestore_async.client(database_id=database_id)
        assert client is not None
        assert client.project == 'mock-project-id'
        assert client._database == '(default)'

    def test_database_id_with_explicit_app(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        app = firebase_admin.initialize_app(cred)
        database_id = 'mock-database-id'
        client = firestore_async.client(app, database_id)
        assert client is not None
        assert client.project == 'mock-project-id'
        assert client._database == 'mock-database-id'

    def test_database_id_with_multi_db(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        firebase_admin.initialize_app(cred)
        database_id_1 = 'mock-database-id-1'
        database_id_2 = 'mock-database-id-2'
        client_1 = firestore_async.client(database_id=database_id_1)
        client_2 = firestore_async.client(database_id=database_id_2)
        assert (client_1 is not None) and (client_2 is not None)
        assert client_1 is not client_2
        assert client_1.project == 'mock-project-id'
        assert client_2.project == 'mock-project-id'
        assert client_1._database == 'mock-database-id-1'
        assert client_2._database == 'mock-database-id-2'

    def test_database_id_with_multi_db_uses_cache(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        firebase_admin.initialize_app(cred)
        database_id = 'mock-database-id'
        client_1 = firestore_async.client(database_id=database_id)
        client_2 = firestore_async.client(database_id=database_id)
        assert (client_1 is not None) and (client_2 is not None)
        assert client_1 is client_2
        assert client_1.project == 'mock-project-id'
        assert client_2.project == 'mock-project-id'
        assert client_1._database == 'mock-database-id'
        assert client_2._database == 'mock-database-id'

    def test_database_id_with_multi_db_uses_cache_default(self):
        cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
        firebase_admin.initialize_app(cred)
        database_id_1 = ''
        database_id_2 = '(default)'
        client_1 = firestore_async.client(database_id=database_id_1)
        client_2 = firestore_async.client(database_id=database_id_2)
        client_3 = firestore_async.client()
        assert (client_1 is not None) and (client_2 is not None) and (client_3 is not None)
        assert client_1 is client_2
        assert client_1 is client_3
        assert client_2 is client_3
        assert client_1.project == 'mock-project-id'
        assert client_2.project == 'mock-project-id'
        assert client_3.project == 'mock-project-id'
        assert client_1._database == '(default)'
        assert client_2._database == '(default)'
        assert client_3._database == '(default)'


    def test_geo_point(self):
        geo_point = firestore_async.GeoPoint(10, 20) # pylint: disable=no-member
        assert geo_point.latitude == 10
        assert geo_point.longitude == 20

    def test_server_timestamp(self):
        assert firestore_async.SERVER_TIMESTAMP is not None # pylint: disable=no-member
