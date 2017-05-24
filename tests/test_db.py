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


class TestReferenceCreation(object):
    """Test cases for db._Path class."""

    # path => (fullstr, key, parent)
    valid_paths = {
        '/' : ('/', None, None),
        '' : ('/', None, None),
        '/foo' : ('/foo', 'foo', '/'),
        'foo' :  ('/foo', 'foo', '/'),
        '/foo/bar' : ('/foo/bar', 'bar', '/foo'),
        'foo/bar' : ('/foo/bar', 'bar', '/foo'),
        '/foo/bar/' : ('/foo/bar', 'bar', '/foo'),
    }

    invalid_paths = [
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

    @pytest.mark.parametrize('path, expected', valid_paths.items())
    def test_valid_path(self, path, expected):
        ref = db._new_reference(None, path)
        fullstr, key, parent = expected
        assert ref.path == fullstr
        assert ref.key == key
        if parent is None:
            assert ref.parent is None
        else:
            assert ref.parent.path == parent

    @pytest.mark.parametrize('path', invalid_paths)
    def test_invalid_key(self, path):
        with pytest.raises(ValueError):
            db._new_reference(None, path)

    @pytest.mark.parametrize('child, expected', valid_children.items())
    def test_valid_child(self, child, expected):
        parent = db._new_reference(None, '/test')
        assert parent.child(child).path == '/test' + expected

    @pytest.mark.parametrize('child', invalid_children)
    def test_invalid_child(self, child):
        parent = db._new_reference(None, '/test')
        with pytest.raises(ValueError):
            parent.child(child)
