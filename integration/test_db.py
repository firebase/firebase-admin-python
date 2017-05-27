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
import json

import pytest

from firebase_admin import db
from tests import testutils

def _update_rules():
    with open(testutils.resource_filename('dinosaurs_index.json')) as index_file:
        index = json.load(index_file)
    client = db.get_reference()._client
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
    ref = db.get_reference('_adminsdk/python/dinodb')
    ref.set_value(testdata())
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
        value = testref.get_value()
        assert isinstance(value, dict)
        assert testdata == value

    def test_get_child_value(self, testref, testdata):
        value = testref.child('dinosaurs').get_value()
        assert isinstance(value, dict)
        assert testdata['dinosaurs'] == value

    def test_get_grandchild_value(self, testref, testdata):
        value = testref.child('dinosaurs').child('lambeosaurus').get_value()
        assert isinstance(value, dict)
        assert testdata['dinosaurs']['lambeosaurus'] == value

    def test_get_nonexisting_child_value(self, testref):
        assert testref.child('none_existing').get_value() is None


class TestWriteOperations(object):
    """Test cases for creating and updating node values."""

    def test_push(self, testref):
        python = testref.parent
        ref = python.child('users').push()
        assert ref.path == '/_adminsdk/python/users/' + ref.key
        assert ref.get_value() == ''

    def test_push_with_value(self, testref):
        python = testref.parent
        value = {'name' : 'Luis Alvarez', 'since' : 1911}
        ref = python.child('users').push(value)
        assert ref.path == '/_adminsdk/python/users/' + ref.key
        assert ref.get_value() == value

    def test_set_primitive_value(self, testref):
        python = testref.parent
        ref = python.child('users').push()
        ref.set_value('value')
        assert ref.get_value() == 'value'

    def test_set_complex_value(self, testref):
        python = testref.parent
        value = {'name' : 'Mary Anning', 'since' : 1799}
        ref = python.child('users').push()
        ref.set_value(value)
        assert ref.get_value() == value

    def test_set_primitive_value_with_priority(self, testref):
        python = testref.parent
        ref = python.child('users').push()
        ref.set_value('value', 1)
        assert ref.get_value() == 'value'
        assert ref.get_priority() == 1

    def test_set_complex_value_with_priority(self, testref):
        python = testref.parent
        value = {'name' : 'Barnum Brown', 'since' : 1873}
        ref = python.child('users').push()
        ref.set_value(value, 2)
        assert ref.get_value() == value
        assert ref.get_priority() == 2

    def test_update_children(self, testref):
        python = testref.parent
        value = {'name' : 'Robert Bakker', 'since' : 1945}
        ref = python.child('users').push()
        ref.update_children(value)
        assert ref.get_value() == value

    def test_delete(self, testref):
        python = testref.parent
        ref = python.child('users').push('foo')
        assert ref.get_value() == 'foo'
        ref.delete()
        assert ref.get_value() is None


class TestAdvancedQueries(object):
    """Test cases for advanced interactions via the db.Query interface."""

    def test_limit_first(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').set_limit_first(2).run()
        assert len(value) == 2
        assert 'pterodactyl' in value
        assert 'linhenykus' in value

    def test_limit_first_all(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').set_limit_first(10).run()
        assert len(value) == 6

    def test_limit_last(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').set_limit_last(2).run()
        assert len(value) == 2
        assert 'stegosaurus' in value
        assert 'bruhathkayosaurus' in value

    def test_limit_last_all(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').set_limit_last(10).run()
        assert len(value) == 6

    def test_start_at(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').set_start_at(3.5).run()
        assert len(value) == 2
        assert 'stegosaurus' in value
        assert 'bruhathkayosaurus' in value

    def test_end_at(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').set_end_at(3.5).run()
        assert len(value) == 4
        assert 'pterodactyl' in value
        assert 'linhenykus' in value
        assert 'lambeosaurus' in value
        assert 'triceratops' in value

    def test_start_and_end_at(self, testref):
        value = testref.child('dinosaurs').order_by_child('height') \
            .set_start_at(2.5).set_end_at(5).run()
        assert len(value) == 2
        assert 'stegosaurus' in value
        assert 'triceratops' in value

    def test_equal_to(self, testref):
        value = testref.child('dinosaurs').order_by_child('height').set_equal_to(0.6).run()
        assert len(value) == 2
        assert 'linhenykus' in value
        assert 'pterodactyl' in value

    def test_order_by_nested_child(self, testref):
        value = testref.child('dinosaurs').order_by_child('ratings/pos').set_start_at(4).run()
        assert len(value) == 3
        assert 'pterodactyl' in value
        assert 'stegosaurus' in value
        assert 'triceratops' in value

    def test_order_by_key(self, testref):
        value = testref.child('dinosaurs').order_by_key().set_limit_first(2).run()
        assert len(value) == 2
        assert 'bruhathkayosaurus' in value
        assert 'lambeosaurus' in value

    def test_order_by_value(self, testref):
        value = testref.child('scores').order_by_value().set_limit_last(2).run()
        assert len(value) == 2
        assert 'pterodactyl' in value
        assert 'linhenykus' in value

    def test_order_by_priority(self, testref):
        python = testref.parent
        museums = python.child('museums').push()
        values = {'Berlin' : 1, 'Chicago' : 2, 'Brussels' : 3}
        for name, priority in values.items():
            ref = museums.push()
            ref.set_value(name, priority)
        result = museums.order_by_priority().set_limit_last(2).run()
        assert len(result) == 2
        assert 'Brussels' in result.values()
        assert 'Chicago' in result.values()
