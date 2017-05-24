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
import StringIO

import pytest
import requests
from requests import adapters
from requests import models

from firebase_admin import db


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
        resp.raw = StringIO.StringIO(self._data)
        return resp

def ref_with_context(path, data, recorder, status=200):
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
    """Test cases for querying db.Reference objects."""

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
