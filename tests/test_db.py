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
import collections
import json
import sys

import pytest
from requests import adapters
from requests import models
from requests import exceptions
from requests import Response
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
        self._etag = '0'

    def send(self, request, **kwargs):
        if_match = request.headers.get('if-match')
        if if_match and if_match != self._etag:
            response = Response()
            response._content = request.body
            response.headers = {'ETag': self._etag}
            raise exceptions.RequestException(response=response)

        del kwargs
        self._recorder.append(request)
        resp = models.Response()
        resp.url = request.url
        resp.status_code = self._status
        resp.raw = six.BytesIO(self._data.encode())
        resp.headers = {'ETag': self._etag}
        return resp


class MockCredential(credentials.Base):
    """A mock Firebase credential implementation."""

    def __init__(self):
        self._g_credential = testutils.MockGoogleCredential()

    def get_credential(self):
        return self._g_credential


class _Object(object):
    pass


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
        None, True, False, 0, 1, dict(), list(), tuple(), _Object(),
        'foo#', 'foo.', 'foo$', 'foo[', 'foo]',
    ]

    valid_children = {
        'foo': ('/test/foo', 'foo', '/test'),
        'foo/bar' : ('/test/foo/bar', 'bar', '/test/foo'),
        'foo/bar/' : ('/test/foo/bar', 'bar', '/test/foo'),
    }

    invalid_children = [
        None, '', '/foo', '/foo/bar', True, False, 0, 1, dict(), list(), tuple(),
        'foo#', 'foo.', 'foo$', 'foo[', 'foo]', _Object()
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
    valid_values = [
        '', 'foo', 0, 1, 100, 1.2, True, False, [], [1, 2], {}, {'foo' : 'bar'}
    ]

    @classmethod
    def setup_class(cls):
        firebase_admin.initialize_app(MockCredential(), {'databaseURL' : cls.test_url})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def instrument(self, ref, payload, status=200):
        recorder = []
        adapter = MockAdapter(payload, status, recorder)
        ref._client._session.mount(self.test_url, adapter)
        return recorder

    @pytest.mark.parametrize('data', valid_values)
    def test_get_value(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps(data))
        assert ref.get() == data
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT

    @pytest.mark.parametrize('data', valid_values)
    def test_get_with_etag(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps(data))
        assert ref._get_with_etag() == ('0', data)
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT

    @pytest.mark.parametrize('data', valid_values)
    def test_order_by_query(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps(data))
        query = ref.order_by_child('foo')
        query_str = 'orderBy=%22foo%22'
        assert query.get() == data
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?' + query_str
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    @pytest.mark.parametrize('data', valid_values)
    def test_limit_query(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps(data))
        query = ref.order_by_child('foo')
        query.limit_to_first(100)
        query_str = 'limitToFirst=100&orderBy=%22foo%22'
        assert query.get() == data
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?' + query_str
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    @pytest.mark.parametrize('data', valid_values)
    def test_range_query(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps(data))
        query = ref.order_by_child('foo')
        query.start_at(100)
        query.end_at(200)
        query_str = 'endAt=200&orderBy=%22foo%22&startAt=100'
        assert query.get() == data
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?' + query_str
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    @pytest.mark.parametrize('data', valid_values)
    def test_set_value(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, '')
        ref.set(data)
        assert len(recorder) == 1
        assert recorder[0].method == 'PUT'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?print=silent'
        assert json.loads(recorder[0].body.decode()) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    def test_set_none_value(self):
        ref = db.reference('/test')
        self.instrument(ref, '')
        with pytest.raises(ValueError):
            ref.set(None)

    @pytest.mark.parametrize('value', [
        _Object(), {'foo': _Object()}, [_Object()]
    ])
    def test_set_non_json_value(self, value):
        ref = db.reference('/test')
        self.instrument(ref, '')
        with pytest.raises(TypeError):
            ref.set(value)

    def test_update_children(self):
        ref = db.reference('/test')
        data = {'foo' : 'bar'}
        recorder = self.instrument(ref, json.dumps(data))
        ref.update(data)
        assert len(recorder) == 1
        assert recorder[0].method == 'PATCH'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?print=silent'
        assert json.loads(recorder[0].body.decode()) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    def test_update_with_etag(self):
        ref = db.reference('/test')
        data = {'foo': 'bar'}
        recorder = self.instrument(ref, json.dumps(data))
        vals = ref._update_with_etag(data, '0')
        assert vals == (True, '0', data)
        assert len(recorder) == 1
        assert recorder[0].method == 'PUT'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert json.loads(recorder[0].body.decode()) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

        vals = ref._update_with_etag(data, '1')
        assert vals == (False, '0', data)
        assert len(recorder) == 1

    def test_update_children_default(self):
        ref = db.reference('/test')
        recorder = self.instrument(ref, '')
        with pytest.raises(ValueError):
            ref.update({})
        assert len(recorder) is 0

    @pytest.mark.parametrize('update', [
        None, {}, {None:'foo'}, {'foo': None}, '', 'foo', 0, 1, list(), tuple(), _Object()
    ])
    def test_set_invalid_update(self, update):
        ref = db.reference('/test')
        self.instrument(ref, '')
        with pytest.raises(ValueError):
            ref.update(update)

    @pytest.mark.parametrize('data', valid_values)
    def test_push(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps({'name' : 'testkey'}))
        child = ref.push(data)
        assert isinstance(child, db.Reference)
        assert child.key == 'testkey'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert json.loads(recorder[0].body.decode()) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT

    def test_push_default(self):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps({'name' : 'testkey'}))
        assert ref.push().key == 'testkey'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert json.loads(recorder[0].body.decode()) == ''
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT

    def test_push_none_value(self):
        ref = db.reference('/test')
        self.instrument(ref, '')
        with pytest.raises(ValueError):
            ref.push(None)

    def test_delete(self):
        ref = db.reference('/test')
        recorder = self.instrument(ref, '')
        ref.delete()
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT

    def test_transaction(self):
        ref = db.reference('/test')
        data = {'foo1': 'bar1'}
        recorder = self.instrument(ref, json.dumps(data))

        def transaction_update(data):
            data['foo2'] = 'bar2'
            return data

        ref.transaction(transaction_update)
        assert len(recorder) == 2
        assert recorder[0].method == 'GET'
        assert recorder[1].method == 'PUT'
        assert json.loads(recorder[1].body.decode()) == {'foo1': 'bar1', 'foo2': 'bar2'}

    def test_get_root_reference(self):
        ref = db.reference()
        assert ref.key is None
        assert ref.path == '/'

    @pytest.mark.parametrize('path, expected', TestReferencePath.valid_paths.items())
    def test_get_reference(self, path, expected):
        ref = db.reference(path)
        fullstr, key, parent = expected
        assert ref.path == fullstr
        assert ref.key == key
        if parent is None:
            assert ref.parent is None
        else:
            assert ref.parent.path == parent

    @pytest.mark.parametrize('error_code', [400, 401, 500])
    def test_server_error(self, error_code):
        ref = db.reference('/test')
        self.instrument(ref, json.dumps({'error' : 'json error message'}), error_code)
        with pytest.raises(db.ApiCallError) as excinfo:
            ref.get()
        assert 'Reason: json error message' in str(excinfo.value)

    @pytest.mark.parametrize('error_code', [400, 401, 500])
    def test_other_error(self, error_code):
        ref = db.reference('/test')
        self.instrument(ref, 'custom error message', error_code)
        with pytest.raises(db.ApiCallError) as excinfo:
            ref.get()
        assert 'Reason: custom error message' in str(excinfo.value)


class TestReferenceWithAuthOverride(object):
    """Test cases for database queries via References."""

    test_url = 'https://test.firebaseio.com'
    encoded_override = '%7B%22uid%22:%22user1%22%7D'

    @classmethod
    def setup_class(cls):
        firebase_admin.initialize_app(MockCredential(), {
            'databaseURL' : cls.test_url,
            'databaseAuthVariableOverride' : {'uid':'user1'}
        })

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def instrument(self, ref, payload, status=200):
        recorder = []
        adapter = MockAdapter(payload, status, recorder)
        ref._client._session.mount(self.test_url, adapter)
        return recorder

    def test_get_value(self):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps('data'))
        query_str = 'auth_variable_override={0}'.format(self.encoded_override)
        assert ref.get() == 'data'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?' + query_str
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT

    def test_set_value(self):
        ref = db.reference('/test')
        recorder = self.instrument(ref, '')
        data = {'foo' : 'bar'}
        ref.set(data)
        query_str = 'print=silent&auth_variable_override={0}'.format(self.encoded_override)
        assert len(recorder) == 1
        assert recorder[0].method == 'PUT'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?' + query_str
        assert json.loads(recorder[0].body.decode()) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT

    def test_order_by_query(self):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps('data'))
        query = ref.order_by_child('foo')
        query_str = 'orderBy=%22foo%22&auth_variable_override={0}'.format(self.encoded_override)
        assert query.get() == 'data'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?' + query_str
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT

    def test_range_query(self):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps('data'))
        query = ref.order_by_child('foo').start_at(1).end_at(10)
        query_str = ('endAt=10&orderBy=%22foo%22&startAt=1&'
                     'auth_variable_override={0}'.format(self.encoded_override))
        assert query.get() == 'data'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?' + query_str
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT


class TestDatabseInitialization(object):
    """Test cases for database initialization."""

    def teardown_method(self):
        testutils.cleanup_apps()

    def test_no_app(self):
        with pytest.raises(ValueError):
            db.reference()

    def test_no_db_url(self):
        firebase_admin.initialize_app(MockCredential())
        with pytest.raises(ValueError):
            db.reference()

    @pytest.mark.parametrize('url', [
        'https://test.firebaseio.com', 'https://test.firebaseio.com/'
    ])
    def test_valid_db_url(self, url):
        firebase_admin.initialize_app(MockCredential(), {'databaseURL' : url})
        ref = db.reference()
        assert ref._client._url == 'https://test.firebaseio.com'
        assert ref._client._auth_override is None

    @pytest.mark.parametrize('url', [
        None, '', 'foo', 'http://test.firebaseio.com', 'https://google.com',
        True, False, 1, 0, dict(), list(), tuple(), _Object()
    ])
    def test_invalid_db_url(self, url):
        firebase_admin.initialize_app(MockCredential(), {'databaseURL' : url})
        with pytest.raises(ValueError):
            db.reference()

    @pytest.mark.parametrize('override', [{}, {'uid':'user1'}, None])
    def test_valid_auth_override(self, override):
        firebase_admin.initialize_app(MockCredential(), {
            'databaseURL' : 'https://test.firebaseio.com',
            'databaseAuthVariableOverride': override
        })
        ref = db.reference()
        assert ref._client._url == 'https://test.firebaseio.com'
        if override == {}:
            assert ref._client._auth_override is None
        else:
            encoded = json.dumps(override, separators=(',', ':'))
            assert ref._client._auth_override == 'auth_variable_override={0}'.format(encoded)

    @pytest.mark.parametrize('override', [
        '', 'foo', 0, 1, True, False, list(), tuple(), _Object()])
    def test_invalid_auth_override(self, override):
        firebase_admin.initialize_app(MockCredential(), {
            'databaseURL' : 'https://test.firebaseio.com',
            'databaseAuthVariableOverride': override
        })
        with pytest.raises(ValueError):
            db.reference()

    def test_app_delete(self):
        app = firebase_admin.initialize_app(
            MockCredential(), {'databaseURL' : 'https://test.firebaseio.com'})
        ref = db.reference()
        assert ref is not None
        firebase_admin.delete_app(app)
        with pytest.raises(ValueError):
            db.reference()

    def test_user_agent_format(self):
        expected = 'Firebase/HTTP/{0}/{1}.{2}/AdminPython'.format(
            firebase_admin.__version__, sys.version_info.major, sys.version_info.minor)
        assert db._USER_AGENT == expected


@pytest.fixture(params=['foo', '$key', '$value'])
def initquery(request):
    ref = db.Reference(path='foo')
    if request.param == '$key':
        return ref.order_by_key(), request.param
    elif request.param == '$value':
        return ref.order_by_value(), request.param
    else:
        return ref.order_by_child(request.param), request.param


class TestQuery(object):
    """Test cases for db.Query class."""

    valid_paths = {
        'foo' : 'foo',
        'foo/bar' : 'foo/bar',
        'foo/bar/' : 'foo/bar'
    }

    ref = db.Reference(path='foo')

    @pytest.mark.parametrize('path', [
        '', None, '/', '/foo', 0, 1, True, False, dict(), list(), tuple(), _Object(),
        '$foo', '.foo', '#foo', '[foo', 'foo]', '$key', '$value', '$priority'
    ])
    def test_invalid_path(self, path):
        with pytest.raises(ValueError):
            self.ref.order_by_child(path)

    @pytest.mark.parametrize('path, expected', valid_paths.items())
    def test_order_by_valid_path(self, path, expected):
        query = self.ref.order_by_child(path)
        assert query._querystr == 'orderBy="{0}"'.format(expected)

    @pytest.mark.parametrize('path, expected', valid_paths.items())
    def test_filter_by_valid_path(self, path, expected):
        query = self.ref.order_by_child(path)
        query.equal_to(10)
        assert query._querystr == 'equalTo=10&orderBy="{0}"'.format(expected)

    def test_order_by_key(self):
        query = self.ref.order_by_key()
        assert query._querystr == 'orderBy="$key"'

    def test_key_filter(self):
        query = self.ref.order_by_key()
        query.equal_to(10)
        assert query._querystr == 'equalTo=10&orderBy="$key"'

    def test_order_by_value(self):
        query = self.ref.order_by_value()
        assert query._querystr == 'orderBy="$value"'

    def test_value_filter(self):
        query = self.ref.order_by_value()
        query.equal_to(10)
        assert query._querystr == 'equalTo=10&orderBy="$value"'

    def test_multiple_limits(self):
        query = self.ref.order_by_child('foo')
        query.limit_to_first(1)
        with pytest.raises(ValueError):
            query.limit_to_last(2)

        query = self.ref.order_by_child('foo')
        query.limit_to_last(2)
        with pytest.raises(ValueError):
            query.limit_to_first(1)

    @pytest.mark.parametrize('limit', [None, -1, 'foo', 1.2, list(), dict(), tuple(), _Object()])
    def test_invalid_limit(self, limit):
        query = self.ref.order_by_child('foo')
        with pytest.raises(ValueError):
            query.limit_to_first(limit)
        with pytest.raises(ValueError):
            query.limit_to_last(limit)

    def test_start_at_none(self):
        query = self.ref.order_by_child('foo')
        with pytest.raises(ValueError):
            query.start_at(None)

    def test_end_at_none(self):
        query = self.ref.order_by_child('foo')
        with pytest.raises(ValueError):
            query.end_at(None)

    def test_equal_to_none(self):
        query = self.ref.order_by_child('foo')
        with pytest.raises(ValueError):
            query.equal_to(None)

    def test_range_query(self, initquery):
        query, order_by = initquery
        query.start_at(1)
        query.equal_to(2)
        query.end_at(3)
        assert query._querystr == 'endAt=3&equalTo=2&orderBy="{0}"&startAt=1'.format(order_by)

    def test_limit_first_query(self, initquery):
        query, order_by = initquery
        query.limit_to_first(1)
        assert query._querystr == 'limitToFirst=1&orderBy="{0}"'.format(order_by)

    def test_limit_last_query(self, initquery):
        query, order_by = initquery
        query.limit_to_last(1)
        assert query._querystr == 'limitToLast=1&orderBy="{0}"'.format(order_by)

    def test_all_in(self, initquery):
        query, order_by = initquery
        query.start_at(1)
        query.equal_to(2)
        query.end_at(3)
        query.limit_to_first(10)
        expected = 'endAt=3&equalTo=2&limitToFirst=10&orderBy="{0}"&startAt=1'.format(order_by)
        assert query._querystr == expected


class TestSorter(object):
    """Test cases for db._Sorter class."""

    value_test_cases = [
        ({'k1' : 1, 'k2' : 2, 'k3' : 3}, ['k1', 'k2', 'k3']),
        ({'k1' : 3, 'k2' : 2, 'k3' : 1}, ['k3', 'k2', 'k1']),
        ({'k1' : 3, 'k2' : 1, 'k3' : 2}, ['k2', 'k3', 'k1']),
        ({'k1' : 3, 'k2' : 1, 'k3' : 1}, ['k2', 'k3', 'k1']),
        ({'k1' : 1, 'k2' : 2, 'k3' : 1}, ['k1', 'k3', 'k2']),
        ({'k1' : 'foo', 'k2' : 'bar', 'k3' : 'baz'}, ['k2', 'k3', 'k1']),
        ({'k1' : 'foo', 'k2' : 'bar', 'k3' : 10}, ['k3', 'k2', 'k1']),
        ({'k1' : 'foo', 'k2' : 'bar', 'k3' : None}, ['k3', 'k2', 'k1']),
        ({'k1' : 5, 'k2' : 'bar', 'k3' : None}, ['k3', 'k1', 'k2']),
        ({'k1' : False, 'k2' : 'bar', 'k3' : None}, ['k3', 'k1', 'k2']),
        ({'k1' : False, 'k2' : 1, 'k3' : None}, ['k3', 'k1', 'k2']),
        ({'k1' : True, 'k2' : 0, 'k3' : None, 'k4' : 'foo'}, ['k3', 'k1', 'k2', 'k4']),
        ({'k1' : True, 'k2' : 0, 'k3' : None, 'k4' : 'foo', 'k5' : False, 'k6' : dict()},
         ['k3', 'k5', 'k1', 'k2', 'k4', 'k6']),
        ({'k1' : True, 'k2' : 0, 'k3' : 'foo', 'k4' : 'foo', 'k5' : False, 'k6' : dict()},
         ['k5', 'k1', 'k2', 'k3', 'k4', 'k6']),
    ]

    list_test_cases = [
        ([], []),
        ([1, 2, 3], [1, 2, 3]),
        ([3, 2, 1], [1, 2, 3]),
        ([1, 3, 2], [1, 2, 3]),
        (['foo', 'bar', 'baz'], ['bar', 'baz', 'foo']),
        (['foo', 1, False, None, 0, True], [None, False, True, 0, 1, 'foo']),
    ]

    @pytest.mark.parametrize('result, expected', value_test_cases)
    def test_order_by_value(self, result, expected):
        ordered = db._Sorter(result, '$value').get()
        assert isinstance(ordered, collections.OrderedDict)
        assert list(ordered.keys()) == expected

    @pytest.mark.parametrize('result, expected', list_test_cases)
    def test_order_by_value_with_list(self, result, expected):
        ordered = db._Sorter(result, '$value').get()
        assert isinstance(ordered, list)
        assert ordered == expected

    @pytest.mark.parametrize('value', [None, False, True, 0, 1, 'foo'])
    def test_invalid_sort(self, value):
        with pytest.raises(ValueError):
            db._Sorter(value, '$value')

    @pytest.mark.parametrize('result, expected', [
        ({'k1' : 1, 'k2' : 2, 'k3' : 3}, ['k1', 'k2', 'k3']),
        ({'k3' : 3, 'k2' : 2, 'k1' : 1}, ['k1', 'k2', 'k3']),
        ({'k1' : 3, 'k3' : 1, 'k2' : 2}, ['k1', 'k2', 'k3']),
    ])
    def test_order_by_key(self, result, expected):
        ordered = db._Sorter(result, '$key').get()
        assert isinstance(ordered, collections.OrderedDict)
        assert list(ordered.keys()) == expected

    @pytest.mark.parametrize('result, expected', value_test_cases)
    def test_order_by_child(self, result, expected):
        nested = {}
        for key, val in result.items():
            nested[key] = {'child' : val}
        ordered = db._Sorter(nested, 'child').get()
        assert isinstance(ordered, collections.OrderedDict)
        assert list(ordered.keys()) == expected

    @pytest.mark.parametrize('result, expected', value_test_cases)
    def test_order_by_grand_child(self, result, expected):
        nested = {}
        for key, val in result.items():
            nested[key] = {'child' : {'grandchild' : val}}
        ordered = db._Sorter(nested, 'child/grandchild').get()
        assert isinstance(ordered, collections.OrderedDict)
        assert list(ordered.keys()) == expected

    @pytest.mark.parametrize('result, expected', [
        ({'k1': {'child': 1}, 'k2': {}}, ['k2', 'k1']),
        ({'k1': {'child': 1}, 'k2': {'child': 0}}, ['k2', 'k1']),
        ({'k1': {'child': 1}, 'k2': {'child': {}}, 'k3': {}}, ['k3', 'k1', 'k2']),
    ])
    def test_child_path_resolution(self, result, expected):
        ordered = db._Sorter(result, 'child').get()
        assert isinstance(ordered, collections.OrderedDict)
        assert list(ordered.keys()) == expected
