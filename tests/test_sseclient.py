"""Tests for firebase_admin._sseclient."""
import json

import requests
import six

from firebase_admin import _sseclient
from tests.testutils import MockAdapter


class MockSSEClientAdapter(MockAdapter):
    def __init__(self, payload, recorder):
        status = 200
        MockAdapter.__init__(self, payload, status, recorder)

    def send(self, request, **kwargs):
        resp = super(MockSSEClientAdapter, self).send(request, **kwargs)
        resp.url = request.url
        resp.status_code = self._status
        resp.raw = six.BytesIO(self._data.encode())
        resp.encoding = "utf-8"
        return resp


class TestSSEClient(object):
    """Test cases for the SSEClient"""

    test_url = "https://test.firebaseio.com"


    def init_sse(self, payload, recorder=None):
        if recorder is None:
            recorder = []
        adapter = MockSSEClientAdapter(payload, recorder)
        session = requests.Session()
        session.mount(self.test_url, adapter)
        return _sseclient.SSEClient(url=self.test_url, session=session, retry=1)

    def test_init_sseclient(self):
        payload = 'event: put\ndata: {"path":"/","data":"testevent"}\n\n'
        sseclient = self.init_sse(payload)
        assert sseclient.url == self.test_url
        assert sseclient.session != None

    def test_single_event(self):
        payload = 'event: put\ndata: {"path":"/","data":"testevent"}\n\n'
        recorder = []
        sseclient = self.init_sse(payload, recorder)
        event = next(sseclient)
        event_payload = json.loads(event.data)
        assert event_payload["data"] == "testevent"
        assert event_payload["path"] == "/"
        assert len(recorder) == 1
        # The SSEClient should reconnect now, at which point the mock adapter
        # will echo back the same response.
        event = next(sseclient)
        event_payload = json.loads(event.data)
        assert event_payload["data"] == "testevent"
        assert event_payload["path"] == "/"
        assert len(recorder) == 2

    def test_multiple_events(self):
        payload = 'event: put\ndata: {"path":"/foo","data":"testevent1"}\n\n'
        payload += 'event: put\ndata: {"path":"/bar","data":"testevent2"}\n\n'
        recorder = []
        sseclient = self.init_sse(payload, recorder)
        event = next(sseclient)
        event_payload = json.loads(event.data)
        assert event_payload["data"] == "testevent1"
        assert event_payload["path"] == "/foo"
        event = next(sseclient)
        event_payload = json.loads(event.data)
        assert event_payload["data"] == "testevent2"
        assert event_payload["path"] == "/bar"
        assert len(recorder) == 1


class TestEvent(object):
    """Test cases for Events"""

    def test_normal(self):
        data = 'event: put\ndata: {"path":"/","data":"testdata"}'
        event = _sseclient.Event.parse(data)
        assert event.event_type == "put"
        assert event.data == '{"path":"/","data":"testdata"}'

    def test_all_fields(self):
        data = 'event: put\ndata: {"path":"/","data":"testdata"}\nretry: 5000\nid: abcd'
        event = _sseclient.Event.parse(data)
        assert event.event_type == "put"
        assert event.data == '{"path":"/","data":"testdata"}'
        assert event.retry == 5000
        assert event.event_id == 'abcd'

    def test_invalid(self):
        data = 'event: invalid_event'
        event = _sseclient.Event.parse(data)
        assert event.event_type == "invalid_event"
        assert event.data == ''
