"""Tests for firebase_admin.sseclient."""
import json
import six
import requests

from firebase_admin._sseclient import SSEClient, KeepAuthSession
from tests.testutils import MockAdapter


class MockSSEClient(MockAdapter):
    def __init__(self, payload, status, recorder):
        super().__init__(payload, status, recorder)

    def send(self, request, **kwargs):
        resp = requests.models.Response()
        resp.url = request.url
        resp.status_code = self._status
        resp.raw = six.BytesIO(self._data.encode())
        return resp


class TestSSEClient(object):
    """Test cases for the SSEClient"""

    test_url = "https://test.firebaseio.com"

    def build_headers(self):
        """Returns a mock header for SSEClient test"""
        return {
            "content-type": "application/json; charset=UTF-8",
            "Authorization" : "Bearer MOCK_ACCESS_TOKEN"
        }

    def init_sse(self):
        payload = 'event: put\ndata: {"path":"/","data":"testevent"}\n\n'
        status = 200
        recorder = []

        adapter = MockSSEClient(payload, status, recorder)
        session = KeepAuthSession()
        session.mount(self.test_url, adapter)

        sseclient = SSEClient(url=self.test_url, session=session, build_headers=self.build_headers)
        return sseclient


    def test_init_sseclient(self):
        sseclient = self.init_sse()

        assert sseclient.url == self.test_url
        assert sseclient.running
        assert sseclient.session != None

    def test_event(self):
        sseclient = self.init_sse()
        for msg in sseclient:
            event = json.loads(msg.data)
            break
        assert event["data"] == "testevent"
        assert event["path"] == "/"
