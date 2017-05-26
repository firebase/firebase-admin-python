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
import json

import requests
import six
from six.moves import urllib

from firebase_admin import utils

_DB_ATTRIBUTE = '_database'
_INVALID_PATH_CHARACTERS = r'[].#$'
_RESERVED_FILTERS = ('$key', '$value', '$priority')


def get_reference(path='/', app=None):
    """Returns a database Reference representing the node at the specified path.

    If no path is specified, this function returns a Reference that represents the database root.

    Args:
      path: Path to a node in the Firebase realtime database (optional).
      app: An App instance (optional).

    Returns:
      Reference: A newly initialized Reference.

    Raises:
      ValueError: If the specified path or app is invalid.
    """
    client = utils.get_app_service(app, _DB_ATTRIBUTE, _Client.from_app)
    return Reference(client=client, path=path)

def _parse_path(path):
    """Parses a path string into a set of segments."""
    if not isinstance(path, six.string_types):
        raise ValueError('Invalid path: "{0}". Path must be a string.'.format(path))
    if any(ch in path for ch in _INVALID_PATH_CHARACTERS):
        raise ValueError(
            'Invalid path: "{0}". Path contains illegal characters.'.format(path))
    segments = []
    for seg in path.split('/'):
        if seg:
            segments.append(seg)
    return segments


class Reference(object):
    """Reference represents a node in the Firebase realtime database."""

    def __init__(self, **kwargs):
        """Creates a new Reference using the provided parameters.

        This method is for internal use only. Use db.get_reference() to obtain an instance of
        Reference.
        """
        self._client = kwargs.get('client')
        if 'segments' in kwargs:
            self._segments = kwargs.get('segments')
        else:
            self._segments = _parse_path(kwargs.get('path'))
        self._pathurl = '/' + '/'.join(self._segments)

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
            return Reference(client=self._client, segments=self._segments[:-1])
        return None

    def child(self, path):
        if not path or not isinstance(path, six.string_types):
            raise ValueError(
                'Invalid path argument: "{0}". Path must be a non-empty string.'.format(path))
        if path.startswith('/'):
            raise ValueError(
                'Invalid path argument: "{0}". Child path must not start with "/"'.format(path))
        full_path = self._pathurl + '/' + path
        return Reference(client=self._client, path=full_path)

    def get_value(self):
        return self._client.request('get', self._add_suffix())

    def get_priority(self):
        return self._client.request('get', self._add_suffix('/.priority.json'))

    def set_value(self, value='', priority=None):
        if value is None:
            raise ValueError('Value must not be None.')
        if priority is not None:
            if isinstance(value, dict):
                value['.priority'] = priority
            else:
                value = {'.value' : value, '.priority' : priority}
        params = {'print' : 'silent'}
        self._client.request_oneway('put', self._add_suffix(), json=value, params=params)

    def push(self, value=''):
        if value is None:
            raise ValueError('Value must not be None.')
        output = self._client.request('post', self._add_suffix(), json=value)
        push_id = output.get('name')
        if not push_id:
            raise RuntimeError('Unexpected error while pushing to: "{0}". Server did not return '
                               'a push ID.'.format(self._pathurl))
        return self.child(push_id)

    def update_children(self, value):
        if not value or not isinstance(value, dict):
            raise ValueError('Value argument must be a non-empty dictionary.')
        if None in value.keys() or None in value.values():
            raise ValueError('Dictionary must not contain None keys or values.')
        params = {'print':'silent'}
        self._client.request_oneway('patch', self._add_suffix(), json=value, params=params)

    def delete(self):
        self._client.request_oneway('delete', self._add_suffix())

    def order_by_child(self, path):
        if path in _RESERVED_FILTERS:
            raise ValueError('Illegal child path: {0}'.format(path))
        return Query(order_by=path, client=self._client, pathurl=self._add_suffix())

    def order_by_key(self):
        return Query(order_by='$key', client=self._client, pathurl=self._add_suffix())

    def order_by_value(self):
        return Query(order_by='$value', client=self._client, pathurl=self._add_suffix())

    def order_by_priority(self):
        return Query(order_by='$priority', client=self._client, pathurl=self._add_suffix())

    def _add_suffix(self, suffix='.json'):
        return self._pathurl + suffix


class Query(object):
    """Represents a complex query that can be executed on a Reference."""

    def __init__(self, **kwargs):
        order_by = kwargs.pop('order_by')
        if not order_by or not isinstance(order_by, six.string_types):
            raise ValueError('order_by field must be a non-empty string')
        if order_by not in _RESERVED_FILTERS:
            if order_by.startswith('/'):
                raise ValueError('Invalid path argument: "{0}". Child path must not start '
                                 'with "/"'.format(order_by))
            segments = _parse_path(order_by)
            order_by = '/'.join(segments)
        self._client = kwargs.pop('client')
        self._pathurl = kwargs.pop('pathurl')
        self._params = {'orderBy' : json.dumps(order_by)}
        if kwargs:
            raise ValueError('Unexpected keyword arguments: {0}'.format(kwargs))

    def set_limit_first(self, limit):
        if not isinstance(limit, int):
            raise ValueError('Limit must be an integer.')
        if 'limitToLast' in self._params:
            raise ValueError('Cannot set both first and last limits.')
        self._params['limitToFirst'] = limit
        return self

    def set_limit_last(self, limit):
        if not isinstance(limit, int):
            raise ValueError('Limit must be an integer.')
        if 'limitToFirst' in self._params:
            raise ValueError('Cannot set both first and last limits.')
        self._params['limitToLast'] = limit
        return self

    def set_start_at(self, start):
        if not start:
            raise ValueError('Start value must not be empty or None.')
        self._params['startAt'] = json.dumps(start)
        return self

    def set_end_at(self, end):
        if not end:
            raise ValueError('End value must not be empty or None.')
        self._params['endAt'] = json.dumps(end)
        return self

    def set_equal_to(self, value):
        if not value:
            raise ValueError('Equal to value must not be empty or None.')
        self._params['equalTo'] = json.dumps(value)
        return self

    @property
    def querystr(self):
        if len(self._params) < 2:
            raise ValueError('Illegal query configuration: {0}. Query must have "orderBy" '
                             'and at least one other setting.'.format(self._params))
        params = []
        for key in sorted(self._params):
            params.append('{0}={1}'.format(key, self._params[key]))
        return '&'.join(params)

    def run(self):
        return self._client.request('get', '{0}?{1}'.format(self._pathurl, self.querystr))


class _Client(object):
    """HTTP client used to make REST calls.

    _Client maintains an HTTP session, and handles authenticating HTTP requests along with
    marshalling and unmarshalling of JSON data.
    """

    def __init__(self, url=None, auth=None, session=None):
        self._url = url
        self._auth = auth
        self._session = session

    @classmethod
    def from_app(cls, app):
        """Created a new _Client for a given App"""
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
        return _Client('https://{0}'.format(parsed.netloc), _OAuth(app), requests.Session())

    def request(self, method, urlpath, **kwargs):
        resp = self._session.request(method, self._url + urlpath, auth=self._auth, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def request_oneway(self, method, urlpath, **kwargs):
        resp = self._session.request(method, self._url + urlpath, auth=self._auth, **kwargs)
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
