"""Common utility classes and functions for testing."""
import os

from google.auth import transport
import firebase_admin


def resource_filename(filename):
    """Returns the absolute path to a test resource."""
    return os.path.join(os.path.dirname(__file__), 'data', filename)


def resource(filename):
    """Returns the contents of a test resource."""
    with open(resource_filename(filename), 'r') as file_obj:
        return file_obj.read()


def cleanup_apps():
    with firebase_admin._apps_lock:
        apps = list(firebase_admin._apps.values())
        for app in apps:
            firebase_admin.delete_app(app)


class MockResponse(transport.Response):
    def __init__(self, status, response):
        self._status = status
        self._response = response

    @property
    def status(self):
        return self._status

    @property
    def headers(self):
        return {}

    @property
    def data(self):
        return self._response.encode()

class MockRequest(transport.Request):
    """A mock HTTP requests implementation.

    This can be used whenever an HTTP interaction needs to be mocked
    for testing purposes. For example HTTP calls to fetch public key
    certificates, and HTTP calls to retrieve access tokens can be
    mocked using this class.
    """

    def __init__(self, status, response):
        self.response = MockResponse(status, response)

    def __call__(self, *args, **kwargs):
        return self.response
