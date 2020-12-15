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
import os
import sys
import time

import pytest

import firebase_admin
from firebase_admin import db
from firebase_admin import exceptions
from firebase_admin import _http_client
from firebase_admin import _sseclient
from tests import testutils


_EMULATOR_HOST_ENV_VAR = 'FIREBASE_DATABASE_EMULATOR_HOST'


class MockAdapter(testutils.MockAdapter):
    """A mock HTTP adapter that mimics RTDB server behavior."""

    ETAG = '0'

    def __init__(self, data, status, recorder, etag=ETAG):
        testutils.MockAdapter.__init__(self, data, status, recorder)
        self._etag = etag

    def send(self, request, **kwargs):
        if_match = request.headers.get('if-match')
        if_none_match = request.headers.get('if-none-match')
        resp = super(MockAdapter, self).send(request, **kwargs)
        resp.headers = {'ETag': self._etag}
        if if_match and if_match != MockAdapter.ETAG:
            resp.status_code = 412
        elif if_none_match == MockAdapter.ETAG:
            resp.status_code = 304
        return resp


class MockSSEClient:
    """A mock SSE client that mimics long-lived HTTP connections."""

    def __init__(self, events):
        self.events = events
        self.closed = False

    def __iter__(self):
        return iter(self.events)

    def close(self):
        self.closed = True


class _Object:
    pass


class TestReferencePath:
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


class _RefOperations:
    """A collection of operations that can be performed using a ``db.Reference``.

    This can be used to test any functionality that is common across multiple API calls.
    """

    @classmethod
    def get(cls, ref):
        ref.get()

    @classmethod
    def push(cls, ref):
        ref.push()

    @classmethod
    def set(cls, ref):
        ref.set({'foo': 'bar'})

    @classmethod
    def delete(cls, ref):
        ref.delete()

    @classmethod
    def query(cls, ref):
        query = ref.order_by_key()
        query.get()

    @classmethod
    def get_ops(cls):
        return [cls.get, cls.push, cls.set, cls.delete, cls.query]


class TestReference:
    """Test cases for database queries via References."""

    test_url = 'https://test.firebaseio.com'
    valid_values = [
        '', 'foo', 0, 1, 100, 1.2, True, False, [], [1, 2], {}, {'foo' : 'bar'}
    ]
    error_codes = {
        400: exceptions.InvalidArgumentError,
        401: exceptions.UnauthenticatedError,
        404: exceptions.NotFoundError,
        500: exceptions.InternalError,
    }

    @classmethod
    def setup_class(cls):
        firebase_admin.initialize_app(testutils.MockCredential(), {'databaseURL' : cls.test_url})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def instrument(self, ref, payload, status=200, etag=MockAdapter.ETAG):
        recorder = []
        adapter = MockAdapter(payload, status, recorder, etag)
        ref._client.session.mount(self.test_url, adapter)
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
        assert 'X-Firebase-ETag' not in recorder[0].headers

    @pytest.mark.parametrize('data', valid_values)
    def test_get_with_etag(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps(data))
        assert ref.get(etag=True) == (data, MockAdapter.ETAG)
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT
        assert recorder[0].headers['X-Firebase-ETag'] == 'true'

    @pytest.mark.parametrize('data', valid_values)
    def test_get_shallow(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps(data))
        assert ref.get(shallow=True) == data
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?shallow=true'
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['User-Agent'] == db._USER_AGENT

    def test_get_with_etag_and_shallow(self):
        ref = db.reference('/test')
        with pytest.raises(ValueError):
            ref.get(etag=True, shallow=True)

    @pytest.mark.parametrize('data', valid_values)
    def test_get_if_changed(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps(data))

        assert ref.get_if_changed('invalid-etag') == (True, data, MockAdapter.ETAG)
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert recorder[0].headers['if-none-match'] == 'invalid-etag'

        assert ref.get_if_changed(MockAdapter.ETAG) == (False, None, None)
        assert len(recorder) == 2
        assert recorder[1].method == 'GET'
        assert recorder[1].url == 'https://test.firebaseio.com/test.json'
        assert recorder[1].headers['if-none-match'] == MockAdapter.ETAG

    @pytest.mark.parametrize('etag', [0, 1, True, False, dict(), list(), tuple()])
    def test_get_if_changed_invalid_etag(self, etag):
        ref = db.reference('/test')
        with pytest.raises(ValueError):
            ref.get_if_changed(etag)

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

    @pytest.mark.parametrize('data', [{'foo': 'bar'}, {'foo': None}])
    def test_update_children(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps(data))
        ref.update(data)
        assert len(recorder) == 1
        assert recorder[0].method == 'PATCH'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json?print=silent'
        assert json.loads(recorder[0].body.decode()) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'

    @pytest.mark.parametrize('data', valid_values)
    def test_set_if_unchanged_success(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps(data))
        vals = ref.set_if_unchanged(MockAdapter.ETAG, data)
        assert vals == (True, data, MockAdapter.ETAG)
        assert len(recorder) == 1
        assert recorder[0].method == 'PUT'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert json.loads(recorder[0].body.decode()) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['if-match'] == MockAdapter.ETAG

    @pytest.mark.parametrize('data', valid_values)
    def test_set_if_unchanged_failure(self, data):
        ref = db.reference('/test')
        recorder = self.instrument(ref, json.dumps({'foo':'bar'}))
        vals = ref.set_if_unchanged('invalid-etag', data)
        assert vals == (False, {'foo':'bar'}, MockAdapter.ETAG)
        assert len(recorder) == 1
        assert recorder[0].method == 'PUT'
        assert recorder[0].url == 'https://test.firebaseio.com/test.json'
        assert json.loads(recorder[0].body.decode()) == data
        assert recorder[0].headers['Authorization'] == 'Bearer mock-token'
        assert recorder[0].headers['if-match'] == 'invalid-etag'

    @pytest.mark.parametrize('etag', [0, 1, True, False, dict(), list(), tuple()])
    def test_set_if_unchanged_invalid_etag(self, etag):
        ref = db.reference('/test')
        with pytest.raises(ValueError):
            ref.set_if_unchanged(etag, 'value')

    def test_set_if_unchanged_none_value(self):
        ref = db.reference('/test')
        self.instrument(ref, '')
        with pytest.raises(ValueError):
            ref.set_if_unchanged(MockAdapter.ETAG, None)

    @pytest.mark.parametrize('value', [
        _Object(), {'foo': _Object()}, [_Object()]
    ])
    def test_set_if_unchanged_non_json_value(self, value):
        ref = db.reference('/test')
        self.instrument(ref, '')
        with pytest.raises(TypeError):
            ref.set_if_unchanged(MockAdapter.ETAG, value)

    @pytest.mark.parametrize('update', [
        None, {}, {None:'foo'}, '', 'foo', 0, 1, list(), tuple(), _Object()
    ])
    def test_set_invalid_update(self, update):
        ref = db.reference('/test')
        recorder = self.instrument(ref, '')
        with pytest.raises(ValueError):
            ref.update(update)
        assert len(recorder) == 0

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

        new_value = ref.transaction(transaction_update)
        assert new_value == {'foo1' : 'bar1', 'foo2' : 'bar2'}
        assert len(recorder) == 2
        assert recorder[0].method == 'GET'
        assert recorder[1].method == 'PUT'
        assert json.loads(recorder[1].body.decode()) == {'foo1': 'bar1', 'foo2': 'bar2'}

    def test_transaction_scalar(self):
        ref = db.reference('/test/count')
        data = 42
        recorder = self.instrument(ref, json.dumps(data))

        new_value = ref.transaction(lambda x: x + 1 if x else 1)
        assert new_value == 43
        assert len(recorder) == 2
        assert recorder[0].method == 'GET'
        assert recorder[1].method == 'PUT'
        assert json.loads(recorder[1].body.decode()) == 43

    def test_transaction_error(self):
        ref = db.reference('/test')
        data = {'foo1': 'bar1'}
        recorder = self.instrument(ref, json.dumps(data))

        def transaction_update(data):
            del data
            raise ValueError('test error')

        with pytest.raises(ValueError) as excinfo:
            ref.transaction(transaction_update)
        assert str(excinfo.value) == 'test error'
        assert len(recorder) == 1
        assert recorder[0].method == 'GET'

    def test_transaction_abort(self):
        ref = db.reference('/test/count')
        data = 42
        recorder = self.instrument(ref, json.dumps(data), etag='1')

        with pytest.raises(db.TransactionAbortedError) as excinfo:
            ref.transaction(lambda x: x + 1 if x else 1)
        assert isinstance(excinfo.value, exceptions.AbortedError)
        assert str(excinfo.value) == 'Transaction aborted after failed retries.'
        assert excinfo.value.cause is None
        assert excinfo.value.http_response is None
        assert len(recorder) == 1 + 25

    @pytest.mark.parametrize('func', [None, 0, 1, True, False, 'foo', dict(), list(), tuple()])
    def test_transaction_invalid_function(self, func):
        ref = db.reference('/test')
        with pytest.raises(ValueError):
            ref.transaction(func)

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

    @pytest.mark.parametrize('error_code', error_codes.keys())
    @pytest.mark.parametrize('func', _RefOperations.get_ops())
    def test_server_error(self, error_code, func):
        ref = db.reference('/test')
        self.instrument(ref, json.dumps({'error' : 'json error message'}), error_code)
        exc_type = self.error_codes[error_code]
        with pytest.raises(exc_type) as excinfo:
            func(ref)
        assert str(excinfo.value) == 'json error message'
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None

    @pytest.mark.parametrize('error_code', error_codes.keys())
    @pytest.mark.parametrize('func', _RefOperations.get_ops())
    def test_other_error(self, error_code, func):
        ref = db.reference('/test')
        self.instrument(ref, 'custom error message', error_code)
        exc_type = self.error_codes[error_code]
        with pytest.raises(exc_type) as excinfo:
            func(ref)
        assert str(excinfo.value) == 'Unexpected response from database: custom error message'
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None


class TestListenerRegistration:
    """Test cases for receiving events via ListenerRegistrations."""

    def test_listen_error(self):
        test_url = 'https://test.firebaseio.com'
        firebase_admin.initialize_app(testutils.MockCredential(), {
            'databaseURL' : test_url,
        })
        try:
            ref = db.reference()
            adapter = MockAdapter(json.dumps({'error' : 'json error message'}), 500, [])
            session = ref._client.session
            session.mount(test_url, adapter)
            def callback(_):
                pass
            with pytest.raises(exceptions.InternalError) as excinfo:
                ref._listen_with_session(callback, session)
            assert str(excinfo.value) == 'json error message'
            assert excinfo.value.cause is not None
            assert excinfo.value.http_response is not None
        finally:
            testutils.cleanup_apps()

    def test_listener_session(self):
        firebase_admin.initialize_app(testutils.MockCredential(), {
            'databaseURL' : 'https://test.firebaseio.com',
        })
        try:
            ref = db.reference()
            session = ref._client.create_listener_session()
            assert isinstance(session, _sseclient.KeepAuthSession)
        finally:
            testutils.cleanup_apps()

    def test_single_event(self):
        self.events = []
        def callback(event):
            self.events.append(event)
        sse = MockSSEClient([
            _sseclient.Event.parse('event: put\ndata: {"path":"/","data":"testevent"}\n\n')
        ])
        registration = db.ListenerRegistration(callback, sse)
        self.wait_for(self.events)
        registration.close()
        assert sse.closed
        assert len(self.events) == 1
        event = self.events[0]
        assert event.event_type == 'put'
        assert event.path == '/'
        assert event.data == 'testevent'

    def test_multiple_events(self):
        self.events = []
        def callback(event):
            self.events.append(event)
        sse = MockSSEClient([
            _sseclient.Event.parse('event: put\ndata: {"path":"/foo","data":"testevent1"}\n\n'),
            _sseclient.Event.parse('event: put\ndata: {"path":"/bar","data":{"a": 1}}\n\n'),
        ])
        registration = db.ListenerRegistration(callback, sse)
        self.wait_for(self.events, count=2)
        registration.close()
        assert sse.closed
        assert len(self.events) == 2
        event = self.events[0]
        assert event.event_type == 'put'
        assert event.path == '/foo'
        assert event.data == 'testevent1'
        event = self.events[1]
        assert event.event_type == 'put'
        assert event.path == '/bar'
        assert event.data == {'a': 1}

    @classmethod
    def wait_for(cls, events, count=1, timeout_seconds=5):
        must_end = time.time() + timeout_seconds
        while time.time() < must_end:
            if len(events) >= count:
                return
        raise pytest.fail('Timed out while waiting for events')


class TestReferenceWithAuthOverride:
    """Test cases for database queries via References."""

    test_url = 'https://test.firebaseio.com'
    encoded_override = '%7B%22uid%22:%22user1%22%7D'

    @classmethod
    def setup_class(cls):
        firebase_admin.initialize_app(testutils.MockCredential(), {
            'databaseURL' : cls.test_url,
            'databaseAuthVariableOverride' : {'uid':'user1'}
        })

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def instrument(self, ref, payload, status=200):
        recorder = []
        adapter = MockAdapter(payload, status, recorder)
        ref._client.session.mount(self.test_url, adapter)
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


class TestDatabaseInitialization:
    """Test cases for database initialization."""

    def teardown_method(self):
        testutils.cleanup_apps()

    def test_no_app(self):
        with pytest.raises(ValueError):
            db.reference()

    def test_no_db_url(self):
        firebase_admin.initialize_app(testutils.MockCredential())
        with pytest.raises(ValueError):
            db.reference()

    @pytest.mark.parametrize(
        'url,emulator_host,expected_base_url,expected_namespace',
        [
            # Production URLs with no override:
            ('https://test.firebaseio.com', None, 'https://test.firebaseio.com', None),
            ('https://test.firebaseio.com/', None, 'https://test.firebaseio.com', None),

            # Production URLs with emulator_host override:
            ('https://test.firebaseio.com', 'localhost:9000', 'http://localhost:9000', 'test'),
            ('https://test.firebaseio.com/', 'localhost:9000', 'http://localhost:9000', 'test'),

            # Emulator URL with no override.
            ('http://localhost:8000/?ns=test', None, 'http://localhost:8000', 'test'),

            # emulator_host is ignored when the original URL is already emulator.
            ('http://localhost:8000/?ns=test', 'localhost:9999', 'http://localhost:8000', 'test'),
        ]
    )
    def test_parse_db_url(self, url, emulator_host, expected_base_url, expected_namespace):
        if emulator_host:
            os.environ[_EMULATOR_HOST_ENV_VAR] = emulator_host

        try:
            firebase_admin.initialize_app(testutils.MockCredential(), {'databaseURL' : url})
            ref = db.reference()
            assert ref._client._base_url == expected_base_url
            assert ref._client.params.get('ns') == expected_namespace
            if expected_base_url.startswith('http://localhost'):
                assert isinstance(ref._client.credential, db._EmulatorAdminCredentials)
            else:
                assert isinstance(ref._client.credential, testutils.MockGoogleCredential)
        finally:
            if _EMULATOR_HOST_ENV_VAR in os.environ:
                del os.environ[_EMULATOR_HOST_ENV_VAR]

    @pytest.mark.parametrize('url', [
        '',
        None,
        42,
        'test.firebaseio.com',  # Not a URL.
        'http://test.firebaseio.com',  # Use of non-HTTPs in production URLs.
        'ftp://test.firebaseio.com',  # Use of non-HTTPs in production URLs.
        'http://localhost:9000/',  # No ns specified.
        'http://localhost:9000/?ns=',  # No ns specified.
        'http://localhost:9000/?ns=test1&ns=test2',  # Two ns parameters specified.
        'ftp://localhost:9000/?ns=test',  # Neither HTTP or HTTPS.
    ])
    def test_parse_db_url_errors(self, url):
        firebase_admin.initialize_app(testutils.MockCredential(), {'databaseURL' : url})
        with pytest.raises(ValueError):
            db.reference()

    @pytest.mark.parametrize('url', [
        'https://test.firebaseio.com', 'https://test.firebaseio.com/',
        'https://test.eu-west1.firebasdatabase.app', 'https://test.eu-west1.firebasdatabase.app/'
    ])
    def test_valid_db_url(self, url):
        firebase_admin.initialize_app(testutils.MockCredential(), {'databaseURL' : url})
        ref = db.reference()
        expected_url = url
        if url.endswith('/'):
            expected_url = url[:-1]
        assert ref._client.base_url == expected_url
        assert 'auth_variable_override' not in ref._client.params
        assert 'ns' not in ref._client.params

    @pytest.mark.parametrize('url', [
        None, '', 'foo', 'http://test.firebaseio.com', 'http://test.firebasedatabase.app',
        True, False, 1, 0, dict(), list(), tuple(), _Object()
    ])
    def test_invalid_db_url(self, url):
        firebase_admin.initialize_app(testutils.MockCredential(), {'databaseURL' : url})
        with pytest.raises(ValueError):
            db.reference()
        other_app = firebase_admin.initialize_app(testutils.MockCredential(), name='otherApp')
        with pytest.raises(ValueError):
            db.reference(app=other_app, url=url)

    def test_multi_db_support(self):
        default_url = 'https://test.firebaseio.com'
        firebase_admin.initialize_app(testutils.MockCredential(), {
            'databaseURL' : default_url,
        })
        ref = db.reference()
        assert ref._client.base_url == default_url
        assert 'auth_variable_override' not in ref._client.params
        assert ref._client is db.reference()._client
        assert ref._client is db.reference(url=default_url)._client

        other_url = 'https://other.firebaseio.com'
        other_ref = db.reference(url=other_url)
        assert other_ref._client.base_url == other_url
        assert 'auth_variable_override' not in ref._client.params
        assert other_ref._client is db.reference(url=other_url)._client
        assert other_ref._client is db.reference(url=other_url + '/')._client

    @pytest.mark.parametrize('override', [{}, {'uid':'user1'}, None])
    def test_valid_auth_override(self, override):
        firebase_admin.initialize_app(testutils.MockCredential(), {
            'databaseURL' : 'https://test.firebaseio.com',
            'databaseAuthVariableOverride': override
        })
        default_ref = db.reference()
        other_ref = db.reference(url='https://other.firebaseio.com')
        for ref in [default_ref, other_ref]:
            if override == {}:
                assert 'auth_variable_override' not in ref._client.params
            else:
                encoded = json.dumps(override, separators=(',', ':'))
                assert ref._client.params['auth_variable_override'] == encoded

    @pytest.mark.parametrize('override', [
        '', 'foo', 0, 1, True, False, list(), tuple(), _Object()])
    def test_invalid_auth_override(self, override):
        firebase_admin.initialize_app(testutils.MockCredential(), {
            'databaseURL' : 'https://test.firebaseio.com',
            'databaseAuthVariableOverride': override
        })
        with pytest.raises(ValueError):
            db.reference()
        other_app = firebase_admin.initialize_app(testutils.MockCredential(), {
            'databaseAuthVariableOverride': override
        }, name='otherApp')
        with pytest.raises(ValueError):
            db.reference(app=other_app, url='https://other.firebaseio.com')

    @pytest.mark.parametrize('options, timeout', [
        ({'httpTimeout': 4}, 4),
        ({'httpTimeout': None}, None),
        ({}, _http_client.DEFAULT_TIMEOUT_SECONDS),
    ])
    def test_http_timeout(self, options, timeout):
        test_url = 'https://test.firebaseio.com'
        all_options = {
            'databaseURL' : test_url,
        }
        all_options.update(options)
        firebase_admin.initialize_app(testutils.MockCredential(), all_options)
        default_ref = db.reference()
        other_ref = db.reference(url='https://other.firebaseio.com')
        for ref in [default_ref, other_ref]:
            self._check_timeout(ref, timeout)

    def test_app_delete(self):
        app = firebase_admin.initialize_app(
            testutils.MockCredential(), {'databaseURL' : 'https://test.firebaseio.com'})
        ref = db.reference()
        other_ref = db.reference(url='https://other.firebaseio.com')
        assert ref._client.session is not None
        assert other_ref._client.session is not None
        firebase_admin.delete_app(app)
        with pytest.raises(ValueError):
            db.reference()
        with pytest.raises(ValueError):
            db.reference(url='https://other.firebaseio.com')
        assert ref._client.session is None
        assert other_ref._client.session is None

    def test_user_agent_format(self):
        expected = 'Firebase/HTTP/{0}/{1}.{2}/AdminPython'.format(
            firebase_admin.__version__, sys.version_info.major, sys.version_info.minor)
        assert db._USER_AGENT == expected

    def _check_timeout(self, ref, timeout):
        assert ref._client.timeout == timeout
        recorder = []
        adapter = MockAdapter('{}', 200, recorder)
        ref._client.session.mount(ref._client.base_url, adapter)
        assert ref.get() == {}
        assert len(recorder) == 1
        if timeout is None:
            assert recorder[0]._extra_kwargs['timeout'] is None
        else:
            assert recorder[0]._extra_kwargs['timeout'] == pytest.approx(timeout, 0.001)


@pytest.fixture(params=['foo', '$key', '$value'])
def initquery(request):
    ref = db.Reference(path='foo')
    if request.param == '$key':
        return ref.order_by_key(), request.param
    if request.param == '$value':
        return ref.order_by_value(), request.param

    return ref.order_by_child(request.param), request.param


class TestQuery:
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

    @pytest.mark.parametrize('arg', ['', 'foo', True, False, 0, 1, dict()])
    def test_valid_start_at(self, arg):
        query = self.ref.order_by_child('foo').start_at(arg)
        assert query._querystr == 'orderBy="foo"&startAt={0}'.format(json.dumps(arg))

    def test_end_at_none(self):
        query = self.ref.order_by_child('foo')
        with pytest.raises(ValueError):
            query.end_at(None)

    @pytest.mark.parametrize('arg', ['', 'foo', True, False, 0, 1, dict()])
    def test_valid_end_at(self, arg):
        query = self.ref.order_by_child('foo').end_at(arg)
        assert query._querystr == 'endAt={0}&orderBy="foo"'.format(json.dumps(arg))

    def test_equal_to_none(self):
        query = self.ref.order_by_child('foo')
        with pytest.raises(ValueError):
            query.equal_to(None)

    @pytest.mark.parametrize('arg', ['', 'foo', True, False, 0, 1, dict()])
    def test_valid_equal_to(self, arg):
        query = self.ref.order_by_child('foo').equal_to(arg)
        assert query._querystr == 'equalTo={0}&orderBy="foo"'.format(json.dumps(arg))

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

    def test_invalid_query_args(self):
        ref = db.Reference(path='foo')
        with pytest.raises(ValueError):
            db.Query(order_by='$key', client=ref._client, pathurl=ref._add_suffix(), foo='bar')


class TestSorter:
    """Test cases for db._Sorter class."""

    value_test_cases = [
        ({'k1' : 1, 'k2' : 2, 'k3' : 3}, ['k1', 'k2', 'k3']),
        ({'k1' : 3, 'k2' : 2, 'k3' : 1}, ['k3', 'k2', 'k1']),
        ({'k1' : 3, 'k2' : 1, 'k3' : 2}, ['k2', 'k3', 'k1']),
        ({'k1' : 3, 'k2' : 1, 'k3' : 1}, ['k2', 'k3', 'k1']),
        ({'k1' : 1, 'k2' : 2, 'k3' : 1}, ['k1', 'k3', 'k2']),
        ({'k1' : 2, 'k2' : 2, 'k3' : 1}, ['k3', 'k1', 'k2']),
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
        ([1, 3, 3], [1, 3, 3]),
        ([2, 3, 2], [2, 2, 3]),
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
