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

"""Integration tests for firebase_admin.db module."""
import collections
import json
import os
import time

import pytest

import firebase_admin
from firebase_admin import db
from firebase_admin import exceptions
from integration import conftest
from tests import testutils


def integration_conf(request):
    host_override = os.environ.get('FIREBASE_DATABASE_EMULATOR_HOST')
    if host_override:
        return None, 'fake-project-id'

    return conftest.integration_conf(request)


@pytest.fixture(scope='module')
def app(request):
    cred, project_id = integration_conf(request)
    ops = {
        'databaseURL' : f'https://{project_id}.firebaseio.com',
    }
    return firebase_admin.initialize_app(cred, ops, name='integration-db')


@pytest.fixture(scope='module', autouse=True)
def default_app():
    # Overwrites the default_app fixture in conftest.py.
    # This test suite should not use the default app. Use the app fixture instead.
    pass


@pytest.fixture(scope='module')
def update_rules(app):
    with open(testutils.resource_filename('dinosaurs_index.json'), encoding='utf-8') as rules_file:
        new_rules = json.load(rules_file)
    client = db.reference('', app)._client
    rules = client.body('get', '/.settings/rules.json', params='format=strict')
    existing = rules.get('rules')
    if existing != new_rules:
        rules['rules'] = new_rules
        client.request('put', '/.settings/rules.json', json=rules)

@pytest.fixture(scope='module')
def testdata():
    with open(testutils.resource_filename('dinosaurs.json'), encoding='utf-8') as dino_file:
        return json.load(dino_file)

@pytest.fixture(scope='module')
def testref(update_rules, testdata, app):
    """Adds the necessary DB indices, and sets the initial values.

    This fixture is attached to the module scope, and therefore is guaranteed to run only once
    during the execution of this test module.

    Returns:
        Reference: A reference to the test dinosaur database.
    """
    del update_rules
    ref = db.reference('_adminsdk/python/dinodb', app)
    ref.set(testdata)
    return ref


class TestReferenceAttributes:
    """Test cases for attributes exposed by db.Reference class."""

    def test_ref_attributes(self, testref):
        assert testref.key == 'dinodb'
        assert testref.path == '/_adminsdk/python/dinodb'

    def test_child(self, testref):
        child = testref.child('dinosaurs')
        assert child.key == 'dinosaurs'
        assert child.path == '/_adminsdk/python/dinodb/dinosaurs'

    def test_parent(self, testref):
        parent = testref.parent
        assert parent.key == 'python'
        assert parent.path == '/_adminsdk/python'


class TestReadOperations:
    """Test cases for reading node values."""

    def test_get_value(self, testref, testdata):
        value = testref.get()
        assert isinstance(value, dict)
        assert testdata == value

    def test_get_value_and_etag(self, testref, testdata):
        value, etag = testref.get(etag=True)
        assert isinstance(value, dict)
        assert testdata == value
        assert isinstance(etag, str)

    def test_get_shallow(self, testref):
        value = testref.get(shallow=True)
        assert isinstance(value, dict)
        assert value == {'dinosaurs': True, 'scores': True}

    def test_get_if_changed(self, testref, testdata):
        success, data, etag = testref.get_if_changed('wrong_etag')
        assert success is True
        assert data == testdata
        assert isinstance(etag, str)
        assert testref.get_if_changed(etag) == (False, None, None)

    def test_get_child_value(self, testref, testdata):
        child = testref.child('dinosaurs')
        assert child is not None
        value = child.get()
        assert isinstance(value, dict)
        assert testdata['dinosaurs'] == value

    def test_get_grandchild_value(self, testref, testdata):
        value = testref.child('dinosaurs').child('lambeosaurus').get()
        assert isinstance(value, dict)
        assert testdata['dinosaurs']['lambeosaurus'] == value

    def test_get_nonexisting_child_value(self, testref):
        assert testref.child('none_existing').get() is None


class TestWriteOperations:
    """Test cases for creating and updating node values."""

    def test_push(self, testref):
        python = testref.parent
        ref = python.child('users').push()
        assert ref.path == '/_adminsdk/python/users/' + ref.key
        assert ref.get() == ''

    def test_push_with_value(self, testref):
        python = testref.parent
        value = {'name' : 'Luis Alvarez', 'since' : 1911}
        ref = python.child('users').push(value)
        assert ref.path == '/_adminsdk/python/users/' + ref.key
        assert ref.get() == value

    def test_set_primitive_value(self, testref):
        python = testref.parent
        ref = python.child('users').push()
        ref.set('value')
        assert ref.get() == 'value'

    def test_set_complex_value(self, testref):
        python = testref.parent
        value = {'name' : 'Mary Anning', 'since' : 1799}
        ref = python.child('users').push()
        ref.set(value)
        assert ref.get() == value

    def test_update_children(self, testref):
        python = testref.parent
        value = {'name' : 'Robert Bakker', 'since' : 1945}
        ref = python.child('users').push()
        ref.update(value)
        assert ref.get() == value

    def test_update_children_with_existing_values(self, testref):
        python = testref.parent
        value = {'name' : 'Edwin Colbert', 'since' : 1900, 'temp': True}
        ref = python.child('users').push(value)
        ref.update({'since' : 1905})
        value['since'] = 1905
        assert ref.get() == value
        ref.update({'temp': None})
        del value['temp']
        assert ref.get() == value

    def test_update_nested_children(self, testref):
        python = testref.parent
        edward = python.child('users').push({'name' : 'Edward Cope', 'since' : 1800})
        jack = python.child('users').push({'name' : 'Jack Horner', 'since' : 1940})
        delta = {
            f'{edward.key}/since' : 1840,
            f'{jack.key}/since' : 1946
        }
        python.child('users').update(delta)
        assert edward.get() == {'name' : 'Edward Cope', 'since' : 1840}
        assert jack.get() == {'name' : 'Jack Horner', 'since' : 1946}

    def test_set_if_unchanged(self, testref):
        python = testref.parent
        push_data = {'name' : 'Edward Cope', 'since' : 1800}
        edward = python.child('users').push(push_data)

        update_data = {'name' : 'Jack Horner', 'since' : 1940}
        success, data, etag = edward.set_if_unchanged('invalid-etag', update_data)
        assert success is False
        assert data == push_data
        assert isinstance(etag, str)

        success, data, new_etag = edward.set_if_unchanged(etag, update_data)
        assert success is True
        assert data == update_data
        assert new_etag != etag

    def test_transaction(self, testref):
        python = testref.parent
        def transaction_update(snapshot):
            snapshot['name'] += ' Owen'
            snapshot['since'] = 1804
            return snapshot
        ref = python.child('users').push({'name' : 'Richard'})
        new_value = ref.transaction(transaction_update)
        expected = {'name': 'Richard Owen', 'since': 1804}
        assert new_value == expected
        assert ref.get() == expected

    def test_transaction_scalar(self, testref):
        python = testref.parent
        ref = python.child('users/count')
        ref.set(42)
        new_value = ref.transaction(lambda x: x + 1 if x else 1)
        expected = 43
        assert new_value == expected
        assert ref.get() == expected

    def test_delete(self, testref):
        python = testref.parent
        ref = python.child('users').push('foo')
        assert ref.get() == 'foo'
        ref.delete()
        assert ref.get() is None

class TestListenOperations:
    """Test cases for listening to changes to node values."""

    def test_listen(self, testref):
        self.events = []
        def callback(event):
            self.events.append(event)

        python = testref.parent
        registration = python.listen(callback)
        try:
            ref = python.child('users').push()
            assert ref.path == '/_adminsdk/python/users/' + ref.key
            assert ref.get() == ''

            self.wait_for(self.events, count=2)
            assert len(self.events) == 2

            assert self.events[1].event_type == 'put'
            assert self.events[1].path == '/users/' + ref.key
            assert self.events[1].data == ''
        finally:
            registration.close()

    @classmethod
    def wait_for(cls, events, count=1, timeout_seconds=5):
        must_end = time.time() + timeout_seconds
        while time.time() < must_end:
            if len(events) >= count:
                return
        raise pytest.fail('Timed out while waiting for events')

class TestAdvancedQueries:
    """Test cases for advanced interactions via the db.Query interface."""

    height_sorted = [
        'linhenykus', 'pterodactyl', 'lambeosaurus',
        'triceratops', 'stegosaurus', 'bruhathkayosaurus',
    ]

    def test_order_by_key(self, testref):
        value = testref.child('dinosaurs').order_by_key().get()
        assert isinstance(value, collections.OrderedDict)
        assert list(value.keys()) == [
            'bruhathkayosaurus', 'lambeosaurus', 'linhenykus',
            'pterodactyl', 'stegosaurus', 'triceratops'
        ]

    def test_order_by_value(self, testref):
        value = testref.child('scores').order_by_value().get()
        assert list(value.keys()) == [
            'stegosaurus', 'lambeosaurus', 'triceratops',
            'bruhathkayosaurus', 'linhenykus', 'pterodactyl',
        ]

    def test_order_by_child(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').get()
        assert list(value.keys()) == self.height_sorted

    def test_limit_first(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').limit_to_first(2).get()
        assert list(value.keys()) == self.height_sorted[:2]

    def test_limit_first_all(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').limit_to_first(10).get()
        assert list(value.keys()) == self.height_sorted

    def test_limit_last(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').limit_to_last(2).get()
        assert list(value.keys()) == self.height_sorted[-2:]

    def test_limit_last_all(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').limit_to_last(10).get()
        assert list(value.keys()) == self.height_sorted

    def test_start_at(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').start_at(3.5).get()
        assert list(value.keys()) == self.height_sorted[-2:]

    def test_end_at(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').end_at(3.5).get()
        assert list(value.keys()) == self.height_sorted[:4]

    def test_start_and_end_at(self, testref):
        value = testref.child('dinosaurs').order_by_child('height') \
            .start_at(2.5).end_at(5).get()
        assert list(value.keys()) == self.height_sorted[-3:-1]

    def test_equal_to(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').equal_to(0.6).get()
        assert list(value.keys()) == self.height_sorted[:2]

    def test_order_by_nested_child(self, testref):
        value = testref.child('dinosaurs').order_by_child('ratings/pos').start_at(4).get()
        assert len(value) == 3
        assert 'pterodactyl' in value
        assert 'stegosaurus' in value
        assert 'triceratops' in value

    def test_filter_by_key(self, testref):
        value = testref.child('dinosaurs').order_by_key().limit_to_first(2).get()
        assert len(value) == 2
        assert 'bruhathkayosaurus' in value
        assert 'lambeosaurus' in value

    def test_filter_by_value(self, testref):
        value = testref.child('scores').order_by_value().limit_to_last(2).get()
        assert len(value) == 2
        assert 'pterodactyl' in value
        assert 'linhenykus' in value


@pytest.fixture(scope='module')
def override_app(request, update_rules):
    del update_rules
    cred, project_id = integration_conf(request)
    ops = {
        'databaseURL' : f'https://{project_id}.firebaseio.com',
        'databaseAuthVariableOverride' : {'uid' : 'user1'}
    }
    app = firebase_admin.initialize_app(cred, ops, 'db-override')
    yield app
    firebase_admin.delete_app(app)

@pytest.fixture(scope='module')
def none_override_app(request, update_rules):
    del update_rules
    cred, project_id = integration_conf(request)
    ops = {
        'databaseURL' : f'https://{project_id}.firebaseio.com',
        'databaseAuthVariableOverride' : None
    }
    app = firebase_admin.initialize_app(cred, ops, 'db-none-override')
    yield app
    firebase_admin.delete_app(app)


class TestAuthVariableOverride:
    """Test cases for database auth variable overrides."""

    def init_ref(self, path, app):
        admin_ref = db.reference(path, app)
        admin_ref.set('test')
        assert admin_ref.get() == 'test'

    def test_no_access(self, app, override_app):
        path = '_adminsdk/python/admin'
        self.init_ref(path, app)
        user_ref = db.reference(path, override_app)
        with pytest.raises(exceptions.UnauthenticatedError) as excinfo:
            assert user_ref.get()
        assert str(excinfo.value) == 'Permission denied'

        with pytest.raises(exceptions.UnauthenticatedError) as excinfo:
            user_ref.set('test2')
        assert str(excinfo.value) == 'Permission denied'

    def test_read(self, app, override_app):
        path = '_adminsdk/python/protected/user2'
        self.init_ref(path, app)
        user_ref = db.reference(path, override_app)
        assert user_ref.get() == 'test'
        with pytest.raises(exceptions.UnauthenticatedError) as excinfo:
            user_ref.set('test2')
        assert str(excinfo.value) == 'Permission denied'

    def test_read_write(self, app, override_app):
        path = '_adminsdk/python/protected/user1'
        self.init_ref(path, app)
        user_ref = db.reference(path, override_app)
        assert user_ref.get() == 'test'
        user_ref.set('test2')
        assert user_ref.get() == 'test2'

    def test_query(self, override_app):
        user_ref = db.reference('_adminsdk/python/protected', override_app)
        with pytest.raises(exceptions.UnauthenticatedError) as excinfo:
            user_ref.order_by_key().limit_to_first(2).get()
        assert str(excinfo.value) == 'Permission denied'

    def test_none_auth_override(self, app, none_override_app):
        path = '_adminsdk/python/public'
        self.init_ref(path, app)
        public_ref = db.reference(path, none_override_app)
        assert public_ref.get() == 'test'

        ref = db.reference('_adminsdk/python', none_override_app)
        with pytest.raises(exceptions.UnauthenticatedError) as excinfo:
            assert ref.child('protected/user1').get()
        assert str(excinfo.value) == 'Permission denied'

        with pytest.raises(exceptions.UnauthenticatedError) as excinfo:
            assert ref.child('protected/user2').get()
        assert str(excinfo.value) == 'Permission denied'

        with pytest.raises(exceptions.UnauthenticatedError) as excinfo:
            assert ref.child('admin').get()
        assert str(excinfo.value) == 'Permission denied'
