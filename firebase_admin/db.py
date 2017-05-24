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
_INVALID_PATH_CHARACTERS = r'[].#$'

_db_lock = threading.Lock()


def get_reference(path='/', app=None):
    app = utils.get_initialized_app(app)
    with _db_lock:
        if not hasattr(app, _DB_ATTRIBUTE):
            setattr(app, _DB_ATTRIBUTE, _Context(app))
        context = getattr(app, _DB_ATTRIBUTE)
    return _new_reference(context, path)

def _new_reference(context, path):
    """Creates a new DatabaseReference from given context and path."""
    if not isinstance(path, six.string_types):
        raise ValueError('Invalid path argument: "{0}". Path must be a string.'.format(path))
    if any(ch in path for ch in _INVALID_PATH_CHARACTERS):
        raise ValueError(
            'Invalid path argument: "{0}". Path contains illegal characters.'.format(path))
    segments = []
    for seg in path.split('/'):
        if seg:
            segments.append(seg)
    return Reference(context, segments)


class Reference(object):
    """Reference represents a node in the Firebase realtime database."""

    def __init__(self, context, segments):
        """Creates a new Reference from the given context and path segments.

        This method is for internal use only. Use db.get_reference() to retrieve an instance of
        Reference.
        """
        self._context = context
        self._segments = segments
        self._pathurl = '/' + '/'.join(segments)

    @property
    def key(self):
        if self._segments:
            return self._segments[-1]
        return None

    @property
    def path(self):
        return self._pathurl

    @property
    def parent(self):
        if self._segments:
            return Reference(self._context, self._segments[:-1])
        return None

    def child(self, path):
        if not path or not isinstance(path, six.string_types):
            raise ValueError(
                'Invalid path argument: "{0}". Path must be a non-empty string.'.format(path))
        if path.startswith('/'):
            raise ValueError(
                'Invalid path argument: "{0}". Child path must not start with "/"'.format(path))
        return _new_reference(self._context, self._pathurl + '/' + path)

    def get_value(self):
        return self._context.request('get', self._add_suffix())

    def set_value(self, value=None):
        if value is None:
            value = ''
        params = {'print':'silent'}
        self._context.request_oneway('put', self._add_suffix(), json=value, params=params)

    def push(self, value=None):
        if value is None:
            value = ''
        output = self._context.request('post', self._add_suffix(), json=value)
        push_id = output.get('name')
        if not push_id:
            raise RuntimeError('Unexpected error while pushing to: "{0}". Server did not return '
                               'a push ID.'.format(self._pathurl))
        return self.child(push_id)

    def update_children(self, value):
        if not value or not isinstance(value, dict):
            raise ValueError('Value argument must be a non-empty dictionary.')
        params = {'print':'silent'}
        self._context.request_oneway('patch', self._add_suffix(), json=value, params=params)

    def delete(self):
        self._context.request_oneway('delete', self._add_suffix())

    def _add_suffix(self, suffix='.json'):
        return self._pathurl + suffix


class _Context(object):
    """Per-App context used to make REST calls.

    _Context maintains a HTTP session, and other attributes shared across DatabaseReference
    instances. It handles authenticating HTTP requests, and parsing responses as JSON.
    """

    def __init__(self, app):
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
        self._auth = _OAuth(app)
        self._session = requests.Session()

    def request(self, method, urlpath, **kwargs):
        resp = self._session.request(method, self._url + urlpath, auth=self._auth, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def request_oneway(self, method, urlpath, **kwargs):
        resp = requests.request(method, self._url + urlpath, auth=self._auth, **kwargs)
        resp.raise_for_status()

    def close(self):
        self._session.close()
        self._auth = None
        self._url = None


class _OAuth(requests.auth.AuthBase):
    def __init__(self, app):
        self._app = app

    def __call__(self, req):
        req.headers['Authorization'] = 'Bearer {0}'.format(self._app.get_token())
        return req
