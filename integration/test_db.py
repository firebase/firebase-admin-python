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

@pytest.fixture(scope='module')
def testdata():
    with open(testutils.resource_filename('dinosaurs.json')) as dino_file:
        return json.load(dino_file)

@pytest.fixture(scope='module')
def testref():
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
        assert ref.get_value() == ''

    def test_push_with_value(self, testref):
        python = testref.parent
        value = {'name' : 'Luis Alvarez', 'since' : 1911}
        ref = python.child('users').push(value)
        assert ref.get_value() == value

    def test_set_value(self, testref):
        python = testref.parent
        ref = python.child('users').push()
        ref.set_value()
        assert ref.get_value() == ''

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
