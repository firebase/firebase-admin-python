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
import json

import pytest
import requests
from requests import adapters
from requests import models
import six

import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from tests import testutils


class MockAdapter(adapters.HTTPAdapter):
    def __init__(self, data, status, recorder):
        adapters.HTTPAdapter.__init__(self)
        self._status = status
        self._data = data
        self._recorder = recorder

    def send(self, request, **kwargs): # pylint: disable=unused-argument
        self._recorder.append(request)
        resp = models.Response()
        resp.status_code = self._status
        resp.raw = six.StringIO(self._data)
        return resp

def ref_with_context(path, data, recorder, status=200):
    """Creates a new db.Reference with a mock transport session and context.

    Creates a mock transport session that records HTTP requests, and responds to them with the
    provided data string. Then creates a db.Reference which would use the mock transport for
    making HTTP calls.

    Args:
        path: Path to the database node.
        data: Data string to respond with for HTTP calls.
        recorder: A list to record HTTP calls made by the Reference.
        status: HTTP status code to include in responses (optional).

    Returns:
        Reference: A database Reference.
    """
    session = requests.Session()
    test_url = 'https://test.firebaseio.com'
    session.mount(test_url, MockAdapter(data, status, recorder))
    context = db._Context(test_url, None, session)
    return db._new_reference(context, path)


class TestReferenceCreation(object):
    """Test cases for creating db.Reference objects."""

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


class TestReferenceQueries(object):
    """Test cases for querying db.Reference class."""

    def test_get_value(self):
        data = {'foo' : 'bar'}
        recorder = []
        ref = ref_with_context('/test', json.dumps(data), recorder)
        assert ref.get_value() == data
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'

    def test_set_value(self):
        data = {'foo' : 'bar'}
        recorder = []
        ref = ref_with_context('/test', '', recorder)
        ref.set_value(data)
        assert len(recorder) == 1
        assert recorder[0].method == 'PUT'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?print=silent'
        assert json.loads(recorder[0].body) == data

    def test_set_value_default(self):
        recorder = []
        ref = ref_with_context('/test', '', recorder)
        ref.set_value()
        assert len(recorder) == 1
        assert recorder[0].method == 'PUT'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?print=silent'
        assert json.loads(recorder[0].body) == ''

    def test_update_children(self):
        data = {'foo' : 'bar'}
        recorder = []
        ref = ref_with_context('/test', '', recorder)
        ref.update_children(data)
        assert len(recorder) == 1
        assert recorder[0].method == 'PATCH'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?print=silent'
        assert json.loads(recorder[0].body) == data

    def test_update_children_default(self):
        ref = ref_with_context('/test', '', [])
        with pytest.raises(ValueError):
            ref.update_children({})

    def test_push(self):
        data = {'foo' : 'bar'}
        recorder = []
        ref = ref_with_context('/test', json.dumps({'name' : 'testkey'}), recorder)
        assert ref.push(data).key == 'testkey'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert json.loads(recorder[0].body) == data

    def test_push_default(self):
        recorder = []
        ref = ref_with_context('/test', json.dumps({'name' : 'testkey'}), recorder)
        assert ref.push().key == 'testkey'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert json.loads(recorder[0].body) == ''

    def test_delete(self):
        recorder = []
        ref = ref_with_context('/test', '', recorder)
        ref.delete()
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'


class TestDatabaseModule(object):
    """Test cases for db module."""

    def teardown_method(self):
        testutils.cleanup_apps()

    def test_get_root_reference(self):
        firebase_admin.initialize_app(
            credentials.Base(), {'dbURL' : 'https://test.firebaseio.com'})
        ref = db.get_reference()
        assert ref.key is None
        assert ref.path == '/'

    @pytest.mark.parametrize('path, expected', TestReferenceCreation.valid_paths.items())
    def test_get_reference(self, path, expected):
        firebase_admin.initialize_app(
            credentials.Base(), {'dbURL' : 'https://test.firebaseio.com'})
        ref = db.get_reference(path)
        fullstr, key, parent = expected
        assert ref.path == fullstr
        assert ref.key == key
        if parent is None:
            assert ref.parent is None
        else:
            assert ref.parent.path == parent

    def test_no_db_url(self):
        firebase_admin.initialize_app(credentials.Base())
        with pytest.raises(ValueError):
            db.get_reference()

    @pytest.mark.parametrize('url', [
        None, '', 'foo', 'http://test.firebaseio.com', 'https://google.com',
        True, False, 1, 0, dict(), list(), tuple(),
    ])
    def test_invalid_db_url(self, url):
        firebase_admin.initialize_app(credentials.Base(), {'dbURL' : url})
        with pytest.raises(ValueError):
            db.get_reference()

    def test_app_delete(self):
        app = firebase_admin.initialize_app(
            credentials.Base(), {'dbURL' : 'https://test.firebaseio.com'})
        ref = db.get_reference()
        assert ref is not None
        firebase_admin.delete_app(app)
        with pytest.raises(ValueError):
            db.get_reference()
