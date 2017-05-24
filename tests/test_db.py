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

"""Tests for firebase_admin.db."""
import pytest

import firebase_admin
from firebase_admin import credentials
from firebase_admin import db


class MockCredential(credentials.Base):
    def get_access_token(self):
        return None

    def get_credential(self):
        return None


@pytest.fixture
def context():
    app = firebase_admin.App('test', MockCredential(), {'dbURL' : 'https://test.firebaseio.com'})
    return db._Context(app)


class TestDatabaseReference(object):
    """Test cases for DatabaseReference class."""

    valid_keys = {
        '/' : '/',
        '' : '/',
        '/foo' : '/foo',
        'foo' : '/foo',
        '/foo/bar' : '/foo/bar',
        'foo/bar' : '/foo/bar',
        '/foo/bar/' : '/foo/bar',
    }

    invalid_keys = [
        None, True, False, 0, 1, dict(), list(), tuple(),
        'foo#', 'foo.', 'foo$', 'foo[', 'foo]'
    ]

    valid_children = {
        'foo': '/foo',
        'foo/bar' : '/foo/bar',
        'foo/bar/' : '/foo/bar',
    }

    invalid_children = [
        None, '', '/foo', '/foo/bar', True, False, 0, 1, dict(), list(), tuple(),
        'foo#', 'foo.', 'foo$', 'foo[', 'foo]'
    ]

    @pytest.mark.parametrize('key, expected', valid_keys.items())
    def test_valid_key(self, key, expected, context):
        ref = db.DatabaseReference(context, key)
        assert ref._path == expected

    @pytest.mark.parametrize('key', invalid_keys)
    def test_invalid_key(self, key, context):
        with pytest.raises(ValueError):
            db.DatabaseReference(context, key)

    @pytest.mark.parametrize('key, expected', valid_children.items())
    def test_valid_child(self, key, expected, context):
        ref = db.DatabaseReference(context, '/test')
        assert ref.child(key)._path == '/test' + expected

    @pytest.mark.parametrize('key', invalid_children)
    def test_invalid_child(self, key, context):
        ref = db.DatabaseReference(context, '/test')
        with pytest.raises(ValueError):
            ref.child(key)
