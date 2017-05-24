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

"""Firebase database module."""
import threading

import requests
import six
from six.moves import urllib

from firebase_admin import utils

_DB_ATTRIBUTE = '_database'
_INVALID_PATH_REGEX = r'[].#$'

_db_lock = threading.Lock()


def get_reference(path='/', app=None):
    app = utils.get_initialized_app(app)
    with _db_lock:
        if not hasattr(app, _DB_ATTRIBUTE):
            setattr(app, _DB_ATTRIBUTE, _Context(app))
        context = getattr(app, _DB_ATTRIBUTE)
        return DatabaseReference(context, path)

def _parse_path(path):
    """Parses and validates the given reference path."""
    if not isinstance(path, six.string_types):
        raise ValueError('Invalid path argument: "{0}". Path must be a string.'.format(path))
    if any(ch in path for ch in _INVALID_PATH_REGEX):
        raise ValueError(
            'Invalid path argument: "{0}". Path contains illegal characters.'.format(path))

    segments = []
    for seg in path.split('/'):
        if seg:
            segments.append(seg)
    return '/{0}'.format('/'.join(segments))

def _get_db_url(app):
    """Extracts database URL from a Firebase App."""
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
    return 'https://{0}'.format(parsed.netloc)


class DatabaseReference(object):
    """DatabaseReference represents a node in the Firebase realtime database."""

    def __init__(self, context, path):
        if not isinstance(context, _Context):
            raise ValueError('Illegal context argument.')
        self._context = context
        self._path = _parse_path(path)

    def child(self, path):
        if not path or not isinstance(path, six.string_types):
            raise ValueError('Invalid child path argument: "{0}". Child path must be a non-empty '
                             'string.'.format(path))
        if path.startswith('/'):
            raise ValueError('Invalid child path argument: "{0}". Child path must not begin with '
                             'a "/".'.format(path))
        return DatabaseReference(self._context, '{0}/{1}'.format(self._path, path))

    def get_value(self):
        resp = requests.get(self._get_url(), auth=self._context)
        resp.raise_for_status()
        return resp.json()

    def set_value(self, value=None):
        if value is None:
            value = {}
        params = {'print':'silent'}
        resp = requests.put(self._get_url(), json=value, params=params, auth=self._context)
        resp.raise_for_status()

    def push(self, value=None):
        if value is None:
            value = ''
        resp = requests.post(self._get_url(), json=value, auth=self._context)
        resp.raise_for_status()
        push_id = resp.json().get('name')
        if not push_id:
            raise RuntimeError('Unexpected error while pushing to: "{0}". Server did not return '
                               'a push ID.'.format(self._path))
        return self.child(push_id)

    def update_children(self, value):
        if not value or not isinstance(value, dict):
            raise ValueError('Value argument must be a non-empty dictionary.')
        params = {'print':'silent'}
        resp = requests.patch(self._get_url(), json=value, params=params, auth=self._context)
        resp.raise_for_status()

    def _get_url(self, suffix='.json'):
        return '{0}{1}{2}'.format(self._context.url, self._path, suffix)


class _OAuth2(requests.auth.AuthBase):
    def __init__(self, app):
        self._app = app

    def __call__(self, req):
        req.headers['Authorization'] = 'Bearer {0}'.format(self._app.get_token())
        return req


class _Context(object):
    """Client for accessing the Firebase realtime database via REST calls."""

    def __init__(self, app):
        self._app = app
        self._url = _get_db_url(app)

    @property
    def url(self):
        return self._url

    def __call__(self, req):
        req.headers['Authorization'] = 'Bearer {0}'.format(self._app.get_token())
        return req
