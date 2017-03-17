import httplib2
import os

import firebase


def resource_filename(filename):
  return os.path.join(os.path.dirname(__file__), 'data', filename)


def resource(filename):
  with open(resource_filename(filename), 'r') as file_obj:
    return file_obj.read()


def cleanup_apps():
  with firebase._apps_lock:
    for name in firebase._apps.keys():
      firebase.delete_app(name)


class HttpMock(object):
  """A mock HTTP client implementation.

  This can be used whenever an HTTP interaction needs to be mocked
  for testing purposes. For example HTTP calls to fetch public key
  certificates, and HTTP calls to retrieve access tokens can be
  mocked using this class.
  """

  def __init__(self, status, response):
    self.status = status
    self.response = response

  def request(self, *args, **kwargs):
    return httplib2.Response({'status': self.status}), self.response
