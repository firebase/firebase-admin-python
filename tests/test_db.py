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
import datetime
import json

import pytest
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
        self._data = data
        self._status = status
        self._recorder = recorder

    def send(self, request, **kwargs): # pylint: disable=unused-argument
        self._recorder.append(request)
        resp = models.Response()
        resp.status_code = self._status
        resp.raw = six.BytesIO(self._data.encode())
        return resp


class MockCredential(credentials.Base):
    def get_access_token(self):
        expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        return credentials.AccessTokenInfo('mock-token', expiry)

    def get_credential(self):
        return None


class TestReferencePath(object):
    """Test cases for Reference paths."""

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
        'foo': ('/test/foo', 'foo', '/test'),
        'foo/bar' : ('/test/foo/bar', 'bar', '/test/foo'),
        'foo/bar/' : ('/test/foo/bar', 'bar', '/test/foo'),
    }

    invalid_children = [
        None, '', '/foo', '/foo/bar', True, False, 0, 1, dict(), list(), tuple(),
        'foo#', 'foo.', 'foo$', 'foo[', 'foo]'
    ]

    @pytest.mark.parametrize('path, expected', valid_paths.items())
    def test_valid_path(self, path, expected):
        ref = db.Reference(path=path)
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
            db.Reference(path=path)

    @pytest.mark.parametrize('child, expected', valid_children.items())
    def test_valid_child(self, child, expected):
        fullstr, key, parent = expected
        childref = db.Reference(path='/test').child(child)
        assert childref.path == fullstr
        assert childref.key == key
        assert childref.parent.path == parent

    @pytest.mark.parametrize('child', invalid_children)
    def test_invalid_child(self, child):
        parent = db.Reference(path='/test')
        with pytest.raises(ValueError):
            parent.child(child)


class TestReference(object):
    """Test cases for database queries via References."""

    test_url = 'https://test.firebaseio.com'

    @classmethod
    def setup_class(cls):
        firebase_admin.initialize_app(MockCredential(), {'dbURL' : cls.test_url})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def instrument(self, ref, payload, status=200):
        recorder = []
        adapter = MockAdapter(payload, status, recorder)
        ref._client._session.mount(self.test_url, adapter)
        return recorder

    def test_get_value(self):
        ref = db.get_reference('/test')
        data = {'foo' : 'bar'}
        recorder = self.instrument(ref, json.dumps(data))
        assert ref.get_value() == data
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    def test_set_value(self):
        ref = db.get_reference('/test')
        recorder = self.instrument(ref, '')
        data = {'foo' : 'bar'}
        ref.set_value(data)
        assert len(recorder) == 1
        assert recorder[0].method == 'PUT'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?print=silent'
        assert json.loads(recorder[0].body) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    def test_set_value_default(self):
        ref = db.get_reference('/test')
        recorder = self.instrument(ref, '')
        ref.set_value()
        assert len(recorder) == 1
        assert recorder[0].method == 'PUT'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?print=silent'
        assert json.loads(recorder[0].body) == ''
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    def test_update_children(self):
        ref = db.get_reference('/test')
        data = {'foo' : 'bar'}
        recorder = self.instrument(ref, json.dumps(data))
        ref.update_children(data)
        assert len(recorder) == 1
        assert recorder[0].method == 'PATCH'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?print=silent'
        assert json.loads(recorder[0].body) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    def test_update_children_default(self):
        ref = db.get_reference('/test')
        recorder = self.instrument(ref, '')
        with pytest.raises(ValueError):
            ref.update_children({})
        assert len(recorder) is 0

    def test_push(self):
        ref = db.get_reference('/test')
        data = {'foo' : 'bar'}
        recorder = self.instrument(ref, json.dumps({'name' : 'testkey'}))
        child = ref.push(data)
        assert isinstance(child, db.Reference)
        assert child.key == 'testkey'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert json.loads(recorder[0].body) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    def test_push_default(self):
        ref = db.get_reference('/test')
        recorder = self.instrument(ref, json.dumps({'name' : 'testkey'}))
        assert ref.push().key == 'testkey'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert json.loads(recorder[0].body) == ''
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    def test_delete(self):
        ref = db.get_reference('/test')
        recorder = self.instrument(ref, '')
        ref.delete()
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    def test_get_root_reference(self):
        ref = db.get_reference()
        assert ref.key is None
        assert ref.path == '/'

    @pytest.mark.parametrize('path, expected', TestReferencePath.valid_paths.items())
    def test_get_reference(self, path, expected):
        ref = db.get_reference(path)
        fullstr, key, parent = expected
        assert ref.path == fullstr
        assert ref.key == key
        if parent is None:
            assert ref.parent is None
        else:
            assert ref.parent.path == parent


class TestDatabseInitialization(object):
    """Test cases for database initialization."""

    def teardown_method(self):
        testutils.cleanup_apps()

    def test_no_app(self):
        with pytest.raises(ValueError):
            db.get_reference()

    def test_no_db_url(self):
        firebase_admin.initialize_app(credentials.Base())
        with pytest.raises(ValueError):
            db.get_reference()

    @pytest.mark.parametrize('url', [
        'https://test.firebaseio.com', 'https://test.firebaseio.com/'
    ])
    def test_valid_db_url(self, url):
        firebase_admin.initialize_app(credentials.Base(), {'dbURL' : url})
        ref = db.get_reference()
        assert ref._client._url == 'https://test.firebaseio.com'

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
