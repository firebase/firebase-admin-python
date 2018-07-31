"""Tests for firebase_admin.sseclient."""
import json
import six
import requests

from firebase_admin import _sseclient
from tests.testutils import MockAdapter


class MockSSEClient(MockAdapter):
    def __init__(self, payload):
        status = 200
        recorder = []
        MockAdapter.__init__(self, payload, status, recorder)

    def send(self, request, **kwargs):
        resp = requests.models.Response()
        resp.url = request.url
        resp.status_code = self._status
        resp.raw = six.BytesIO(self._data.encode())
        resp.encoding = "utf-8"
        return resp


class TestSSEClient(object):
    """Test cases for the SSEClient"""

    test_url = "https://test.firebaseio.com"


    def init_sse(self):
        payload = 'event: put\ndata: {"path":"/","data":"testevent"}\n\n'

        adapter = MockSSEClient(payload)
        session = _sseclient.KeepAuthSession()
        session.mount(self.test_url, adapter)

        sseclient = _sseclient.SSEClient(url=self.test_url, session=session)
        return sseclient


    def test_init_sseclient(self):
        sseclient = self.init_sse()

        assert sseclient.url == self.test_url
        assert sseclient.session != None

    def test_event(self):
        sseclient = self.init_sse()
        msg = next(sseclient)
        event = json.loads(msg.data)
        assert event["data"] == "testevent"
        assert event["path"] == "/"


class TestEvent(object):
    """Test cases for Events"""

    def test_normal(self):
        data = 'event: put\ndata: {"path":"/","data":"testdata"}'
        event = _sseclient.Event.parse(data)
        assert event.event == "put"
        assert event.data == '{"path":"/","data":"testdata"}'

    def test_invalid(self):
        data = 'event: invalid_event'
        event = _sseclient.Event.parse(data)
        assert event.event == "invalid_event"
        assert event.data == ''
