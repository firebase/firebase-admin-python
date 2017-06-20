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

import pytest

from firebase_admin import db
from tests import testutils

def _update_rules():
    with open(testutils.resource_filename('dinosaurs_index.json')) as index_file:
        index = json.load(index_file)
    client = db.reference()._client
    rules = client.request('get', '/.settings/rules.json')
    existing = rules.get('rules', dict()).get('_adminsdk')
    if existing != index:
        rules['rules']['_adminsdk'] = index
        client.request('put', '/.settings/rules.json', json=rules)

@pytest.fixture(scope='module')
def testdata():
    with open(testutils.resource_filename('dinosaurs.json')) as dino_file:
        return json.load(dino_file)

@pytest.fixture(scope='module')
def testref():
    """Adds the necessary DB indices, and sets the initial values.

    This fixture is attached to the module scope, and therefore is guaranteed to run only once
    during the execution of this test module.

    Returns:
        Reference: A reference to the test dinosaur database.
    """
    _update_rules()
    ref = db.reference('_adminsdk/python/dinodb')
    ref.set(testdata())
    return ref


class TestReferenceAttributes(object):
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


class TestReadOperations(object):
    """Test cases for reading node values."""

    def test_get_value(self, testref, testdata):
        value = testref.get()
        assert isinstance(value, dict)
        assert testdata == value

    def test_get_child_value(self, testref, testdata):
        value = testref.child('dinosaurs').get()
        assert isinstance(value, dict)
        assert testdata['dinosaurs'] == value

    def test_get_grandchild_value(self, testref, testdata):
        value = testref.child('dinosaurs').child('lambeosaurus').get()
        assert isinstance(value, dict)
        assert testdata['dinosaurs']['lambeosaurus'] == value

    def test_get_nonexisting_child_value(self, testref):
        assert testref.child('none_existing').get() is None


class TestWriteOperations(object):
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
        ref = python.child('users').push({'name' : 'Edwin Colbert', 'since' : 1900})
        ref.update({'since' : 1905})
        assert ref.get() == {'name' : 'Edwin Colbert', 'since' : 1905}

    def test_delete(self, testref):
        python = testref.parent
        ref = python.child('users').push('foo')
        assert ref.get() == 'foo'
        ref.delete()
        assert ref.get() is None


class TestAdvancedQueries(object):
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
