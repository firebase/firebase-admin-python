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

import threading
import urllib

import requests
import six
from six.moves import urllib

from firebase_admin import utils

_db_lock = threading.Lock()

_DB_ATTRIBUTE = '_database'


def _get_db_client(app):
    """Returns a _DatabaseClient instance for an App.

    If the App already has a _DatabaseClient associated with it, simply returns
    it. Otherwise creates a new _DatabaseClient, and adds it to the App before
    returning it.

    Args:
      app: A Firebase App instance (or None to use the default App).

    Returns:
      _DatabaseClient: A _DatabaseClient for the specified App instance.

    Raises:
      ValueError: If the app argument is invalid.
    """
    app = utils.get_initialized_app(app)
    with _db_lock:
        if not hasattr(app, _DB_ATTRIBUTE):
            setattr(app, _DB_ATTRIBUTE, _DatabaseClient(app))
        return getattr(app, _DB_ATTRIBUTE)


class _OAuth2(requests.auth.AuthBase):
    def __init__(self, app):
        self._app = app

    def __call__(self, req):
        req.headers['Authorization'] = 'Bearer {0}'.format(self._app.get_token())
        return req


class _DatabaseClient(object):
    """Client for accessing the Firebase realtime database via REST calls."""

    def __init__(self, app):
        """Initializes database client from a Firebase App instance.

        Args:
          app: A Firebase App instance.

        Raises:
          ValueError: If the App has not been initialized for database access.
        """
        url = app.options.get('dbURL')
        if not url or not isinstance(url, six.string_types):
            raise ValueError(
                'Invalid dbURL option: "{0}". dbURL must be a non-empty URL string.'.format(url))
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != 'https':
            raise ValueError(
                'Invalid dbURL option: "{0}". dbURL must be an HTTPS URL.'.format(url))
        elif not parsed.netloc.endswith('.firebaseio.com'):
            raise ValueError(
                'Invalid dbURL option: "{0}". dbURL must be a valid URL to a Firebase realtime '
                'database instance.'.format(url))
        self._url = 'https://{0}'.format(parsed.netloc)
        self._auth = _OAuth2(app)

    def _get_url(self, path):
        if not isinstance(path, six.string_types):
            raise ValueError('Illegal path argument. Path must be a string.')
        return urllib.parse.urljoin(self._url, '{0}.json'.format(path))

    def get(self, path):
        resp = requests.get(self._get_url(path), auth=self._auth)
        resp.raise_for_status()
        return resp.json()

    def put(self, path, value=None):
        if value is None:
            value = {}
        params = {'print':'silent'}
        resp = requests.put(self._get_url(path), json=value, params=params, auth=self._auth)
        resp.raise_for_status()

    def post(self, path, value=None):
        if value is None:
            value = {}
        resp = requests.post(self._get_url(path), json=value, auth=self._auth)
        resp.raise_for_status()
        push_id = resp.json().get('name')
        if not push_id:
            raise RuntimeError('Unexpected error while pushing to: "{0}". Server did not return '
                               'a push ID.'.format(path))
        return push_id

    def patch(self, path, value):
        if not value or not isinstance(value, dict):
            raise ValueError('value argument must be a non-empty dictionary')
        params = {'print':'silent'}
        resp = requests.patch(self._get_url(path), json=value, params=params, auth=self._auth)
        resp.raise_for_status()
