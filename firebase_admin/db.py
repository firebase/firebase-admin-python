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

"""Firebase Realtime Database module.

This module contains functions and classes that facilitate interacting with the Firebase Realtime
Database. It supports basic data manipulation operations, as well as complex queries such as
limit queries and range queries. However, it does not support realtime update notifications. This
module uses the Firebase REST API underneath.
"""

import collections
import json
import sys

import requests
import six
from six.moves import urllib

import firebase_admin
from firebase_admin import _http_client
from firebase_admin import _utils


_DB_ATTRIBUTE = '_database'
_INVALID_PATH_CHARACTERS = '[].#$'
_RESERVED_FILTERS = ('$key', '$value', '$priority')
_USER_AGENT = 'Firebase/HTTP/{0}/{1}.{2}/AdminPython'.format(
    firebase_admin.__version__, sys.version_info.major, sys.version_info.minor)
_TRANSACTION_MAX_RETRIES = 25


def reference(path='/', app=None):
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
    client = _utils.get_app_service(app, _DB_ATTRIBUTE, _Client.from_app)
    return Reference(client=client, path=path)

def _parse_path(path):
    """Parses a path string into a set of segments."""
    if not isinstance(path, six.string_types):
        raise ValueError('Invalid path: "{0}". Path must be a string.'.format(path))
    if any(ch in path for ch in _INVALID_PATH_CHARACTERS):
        raise ValueError(
            'Invalid path: "{0}". Path contains illegal characters.'.format(path))
    return [seg for seg in path.split('/') if seg]


class Reference(object):
    """Reference represents a node in the Firebase realtime database."""

    def __init__(self, **kwargs):
        """Creates a new Reference using the provided parameters.

        This method is for internal use only. Use db.reference() to obtain an instance of
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
        """Returns a Reference to the specified child node.

        The path may point to an immediate child of the current Reference, or a deeply nested
        child. Child paths must not begin with '/'.

        Args:
          path: Path to the child node.

        Returns:
          Reference: A database Reference representing the specified child node.

        Raises:
          ValueError: If the child path is not a string, not well-formed or begins with '/'.
        """
        if not path or not isinstance(path, six.string_types):
            raise ValueError(
                'Invalid path argument: "{0}". Path must be a non-empty string.'.format(path))
        if path.startswith('/'):
            raise ValueError(
                'Invalid path argument: "{0}". Child path must not start with "/"'.format(path))
        full_path = self._pathurl + '/' + path
        return Reference(client=self._client, path=full_path)

    def get(self, etag=False, shallow=False):
        """Returns the value, and optionally the ETag, at the current location of the database.

        Args:
          etag: A boolean indicating whether the Etag value should be returned or not (optional).
          shallow: A boolean indicating whether to execute a shallow read (optional). Shallow
              reads do not retrieve the child nodes of the current database location. Cannot be
              set to True if ``etag`` is also set to True.

        Returns:
          object: If etag is False returns the decoded JSON value of the current database location.
          If etag is True, returns a 2-tuple consisting of the decoded JSON value and the Etag
          associated with the current database location.

        Raises:
          ValueError: If both ``etag`` and ``shallow`` are set to True.
          ApiCallError: If an error occurs while communicating with the remote database server.
        """
        if etag:
            if shallow:
                raise ValueError('etag and shallow cannot both be set to True.')
            headers, data = self._client.headers_and_body(
                'get', self._add_suffix(), headers={'X-Firebase-ETag' : 'true'})
            return data, headers.get('ETag')
        else:
            params = 'shallow=true' if shallow else None
            return self._client.body('get', self._add_suffix(), params=params)

    def get_if_changed(self, etag):
        """Gets data in this location only if the specified ETag does not match.

        Args:
          etag: The ETag value to be checked against the ETag of the current location.

        Returns:
          tuple: A 3-tuple consisting of a boolean, a decoded JSON value and an ETag. If the ETag
          specified by the caller did not match, the boolen value will be True and the JSON
          and ETag values would reflect the corresponding values in the database. If the ETag
          matched, the boolean value will be False and the other elements of the tuple will be
          None.

        Raises:
          ValueError: If the ETag is not a string.
          ApiCallError: If an error occurs while communicating with the remote database server.
        """
        if not isinstance(etag, six.string_types):
            raise ValueError('ETag must be a string.')

        resp = self._client.request('get', self._add_suffix(), headers={'if-none-match': etag})
        if resp.status_code == 304:
            return False, None, None
        else:
            return True, resp.json(), resp.headers.get('ETag')

    def set(self, value):
        """Sets the data at this location to the given value.

        The value must be JSON-serializable and not None.

        Args:
          value: JSON-serializable value to be set at this location.

        Raises:
          ValueError: If the provided value is None.
          TypeError: If the value is not JSON-serializable.
          ApiCallError: If an error occurs while communicating with the remote database server.
        """
        if value is None:
            raise ValueError('Value must not be None.')
        self._client.request('put', self._add_suffix(), json=value, params='print=silent')

    def set_if_unchanged(self, expected_etag, value):
        """Conditonally sets the data at this location to the given value.

        Sets the data at this location to the given value only if ``expected_etag`` is same as the
        ETag value in the database.

        Args:
          expected_etag: Value of ETag we want to check.
          value: JSON-serializable value to be set at this location.

        Returns:
          tuple: A 3-tuple consisting of a boolean, a decoded JSON value and an ETag. The boolean
          indicates whether the set operation was successful or not. The decoded JSON and the
          ETag corresponds to the latest value in this database location.

        Raises:
          ValueError: If the value is None, or if expected_etag is not a string.
          ApiCallError: If an error occurs while communicating with the remote database server.
        """
        # pylint: disable=missing-raises-doc
        if not isinstance(expected_etag, six.string_types):
            raise ValueError('Expected ETag must be a string.')
        if value is None:
            raise ValueError('Value must not be none.')

        try:
            headers = self._client.headers(
                'put', self._add_suffix(), json=value, headers={'if-match': expected_etag})
            return True, value, headers.get('ETag')
        except ApiCallError as error:
            detail = error.detail
            if detail.response is not None and 'ETag' in detail.response.headers:
                etag = detail.response.headers['ETag']
                snapshot = detail.response.json()
                return False, snapshot, etag
            else:
                raise error

    def push(self, value=''):
        """Creates a new child node.

        The optional value argument can be used to provide an initial value for the child node. If
        no value is provided, child node will have empty string as the default value.

        Args:
          value: JSON-serializable initial value for the child node (optional).

        Returns:
          Reference: A Reference representing the newly created child node.

        Raises:
          ValueError: If the value is None.
          TypeError: If the value is not JSON-serializable.
          ApiCallError: If an error occurs while communicating with the remote database server.
        """
        if value is None:
            raise ValueError('Value must not be None.')
        output = self._client.body('post', self._add_suffix(), json=value)
        push_id = output.get('name')
        return self.child(push_id)

    def update(self, value):
        """Updates the specified child keys of this Reference to the provided values.

        Args:
          value: A dictionary containing the child keys to update, and their new values.

        Raises:
          ValueError: If value is empty or not a dictionary.
          ApiCallError: If an error occurs while communicating with the remote database server.
        """
        if not value or not isinstance(value, dict):
            raise ValueError('Value argument must be a non-empty dictionary.')
        if None in value.keys():
            raise ValueError('Dictionary must not contain None keys.')
        self._client.request('patch', self._add_suffix(), json=value, params='print=silent')

    def delete(self):
        """Deletes this node from the database.

        Raises:
          ApiCallError: If an error occurs while communicating with the remote database server.
        """
        self._client.request('delete', self._add_suffix())

    def transaction(self, transaction_update):
        """Atomically modifies the data at this location.

        Unlike a normal ``set()``, which just overwrites the data regardless of its previous state,
        ``transaction()`` is used to modify the existing value to a new value, ensuring there are
        no conflicts with other clients simultaneously writing to the same location.

        This is accomplished by passing an update function which is used to transform the current
        value of this reference into a new value. If another client writes to this location before
        the new value is successfully saved, the update function is called again with the new
        current value, and the write will be retried. In case of repeated failures, this method
        will retry the transaction up to 25 times before giving up and raising a TransactionError.
        The update function may also force an early abort by raising an exception instead of
        returning a value.

        Args:
          transaction_update: A function which will be passed the current data stored at this
              location. The function should return the new value it would like written. If
              an exception is raised, the transaction will be aborted, and the data at this
              location will not be modified. The exceptions raised by this function are
              propagated to the caller of the transaction method.

        Returns:
          object: New value of the current database Reference (only if the transaction commits).

        Raises:
          TransactionError: If the transaction aborts after exhausting all retry attempts.
          ValueError: If transaction_update is not a function.
        """
        if not callable(transaction_update):
            raise ValueError('transaction_update must be a function.')

        tries = 0
        data, etag = self.get(etag=True)
        while tries < _TRANSACTION_MAX_RETRIES:
            new_data = transaction_update(data)
            success, data, etag = self.set_if_unchanged(etag, new_data)
            if success:
                return new_data
            tries += 1
        raise TransactionError('Transaction aborted after failed retries.')

    def order_by_child(self, path):
        """Returns a Query that orders data by child values.

        Returned Query can be used to set additional parameters, and execute complex database
        queries (e.g. limit queries, range queries).

        Args:
          path: Path to a valid child of the current Reference.

        Returns:
          Query: A database Query instance.

        Raises:
          ValueError: If the child path is not a string, not well-formed or None.
        """
        if path in _RESERVED_FILTERS:
            raise ValueError('Illegal child path: {0}'.format(path))
        return Query(order_by=path, client=self._client, pathurl=self._add_suffix())

    def order_by_key(self):
        """Creates a Query that orderes data by key.

        Returned Query can be used to set additional parameters, and execute complex database
        queries (e.g. limit queries, range queries).

        Returns:
          Query: A database Query instance.
        """
        return Query(order_by='$key', client=self._client, pathurl=self._add_suffix())

    def order_by_value(self):
        """Creates a Query that orderes data by value.

        Returned Query can be used to set additional parameters, and execute complex database
        queries (e.g. limit queries, range queries).

        Returns:
          Query: A database Query instance.
        """
        return Query(order_by='$value', client=self._client, pathurl=self._add_suffix())

    def _add_suffix(self, suffix='.json'):
        return self._pathurl + suffix


class Query(object):
    """Represents a complex query that can be executed on a Reference.

    Complex queries can consist of up to 2 components: a required ordering constraint, and an
    optional filtering constraint. At the server, data is first sorted according to the given
    ordering constraint (e.g. order by child). Then the filtering constraint (e.g. limit, range)
    is applied on the sorted data to produce the final result. Despite the ordering constraint,
    the final result is returned by the server as an unordered collection. Therefore the Query
    interface performs another round of sorting at the client-side before returning the results
    to the caller. This client-side sorted results are returned to the user as a Python
    OrderedDict.
    """

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
        self._order_by = order_by
        self._params = {'orderBy' : json.dumps(order_by)}
        if kwargs:
            raise ValueError('Unexpected keyword arguments: {0}'.format(kwargs))

    def limit_to_first(self, limit):
        """Creates a query with limit, and anchors it to the start of the window.

        Args:
          limit: The maximum number of child nodes to return.

        Returns:
          Query: The updated Query instance.

        Raises:
          ValueError: If the value is not an integer, or set_limit_last() was called previously.
        """
        if not isinstance(limit, int) or limit < 0:
            raise ValueError('Limit must be a non-negative integer.')
        if 'limitToLast' in self._params:
            raise ValueError('Cannot set both first and last limits.')
        self._params['limitToFirst'] = limit
        return self

    def limit_to_last(self, limit):
        """Creates a query with limit, and anchors it to the end of the window.

        Args:
          limit: The maximum number of child nodes to return.

        Returns:
          Query: The updated Query instance.

        Raises:
          ValueError: If the value is not an integer, or set_limit_first() was called previously.
        """
        if not isinstance(limit, int) or limit < 0:
            raise ValueError('Limit must be a non-negative integer.')
        if 'limitToFirst' in self._params:
            raise ValueError('Cannot set both first and last limits.')
        self._params['limitToLast'] = limit
        return self

    def start_at(self, start):
        """Sets the lower bound for a range query.

        The Query will only return child nodes with a value greater than or equal to the specified
        value.

        Args:
          start: JSON-serializable value to start at, inclusive.

        Returns:
          Query: The updated Query instance.

        Raises:
          ValueError: If the value is ``None``.
        """
        if start is None:
            raise ValueError('Start value must not be None.')
        self._params['startAt'] = json.dumps(start)
        return self

    def end_at(self, end):
        """Sets the upper bound for a range query.

        The Query will only return child nodes with a value less than or equal to the specified
        value.

        Args:
          end: JSON-serializable value to end at, inclusive.

        Returns:
          Query: The updated Query instance.

        Raises:
          ValueError: If the value is ``None``.
        """
        if end is None:
            raise ValueError('End value must not be None.')
        self._params['endAt'] = json.dumps(end)
        return self

    def equal_to(self, value):
        """Sets an equals constraint on the Query.

        The Query will only return child nodes whose value is equal to the specified value.

        Args:
          value: JSON-serializable value to query for.

        Returns:
          Query: The updated Query instance.

        Raises:
          ValueError: If the value is ``None``.
        """
        if value is None:
            raise ValueError('Equal to value must not be None.')
        self._params['equalTo'] = json.dumps(value)
        return self

    @property
    def _querystr(self):
        params = []
        for key in sorted(self._params):
            params.append('{0}={1}'.format(key, self._params[key]))
        return '&'.join(params)

    def get(self):
        """Executes this Query and returns the results.

        The results will be returned as a sorted list or an OrderedDict.

        Returns:
          object: Decoded JSON result of the Query.

        Raises:
          ApiCallError: If an error occurs while communicating with the remote database server.
        """
        result = self._client.body('get', self._pathurl, params=self._querystr)
        if isinstance(result, (dict, list)) and self._order_by != '$priority':
            return _Sorter(result, self._order_by).get()
        return result


class ApiCallError(Exception):
    """Represents an Exception encountered while invoking the Firebase database server API."""

    def __init__(self, message, error):
        Exception.__init__(self, message)
        self.detail = error


class TransactionError(Exception):
    """Represents an Exception encountered while performing a transaction."""

    def __init__(self, message):
        Exception.__init__(self, message)



class _Sorter(object):
    """Helper class for sorting query results."""

    def __init__(self, results, order_by):
        if isinstance(results, dict):
            self.dict_input = True
            entries = [_SortEntry(k, v, order_by) for k, v in results.items()]
        elif isinstance(results, list):
            self.dict_input = False
            entries = [_SortEntry(k, v, order_by) for k, v in enumerate(results)]
        else:
            raise ValueError('Sorting not supported for "{0}" object.'.format(type(results)))
        self.sort_entries = sorted(entries)

    def get(self):
        if self.dict_input:
            return collections.OrderedDict([(e.key, e.value) for e in self.sort_entries])
        else:
            return [e.value for e in self.sort_entries]


class _SortEntry(object):
    """A wrapper that is capable of sorting items in a dictionary."""

    _type_none = 0
    _type_bool_false = 1
    _type_bool_true = 2
    _type_numeric = 3
    _type_string = 4
    _type_object = 5

    def __init__(self, key, value, order_by):
        self._key = key
        self._value = value
        if order_by == '$key' or order_by == '$priority':
            self._index = key
        elif order_by == '$value':
            self._index = value
        else:
            self._index = _SortEntry._extract_child(value, order_by)
        self._index_type = _SortEntry._get_index_type(self._index)

    @property
    def key(self):
        return self._key

    @property
    def index(self):
        return self._index

    @property
    def index_type(self):
        return self._index_type

    @property
    def value(self):
        return self._value

    @classmethod
    def _get_index_type(cls, index):
        """Assigns an integer code to the type of the index.

        The index type determines how differently typed values are sorted. This ordering is based
        on https://firebase.google.com/docs/database/rest/retrieve-data#section-rest-ordered-data
        """
        if index is None:
            return cls._type_none
        elif isinstance(index, bool) and not index:
            return cls._type_bool_false
        elif isinstance(index, bool) and index:
            return cls._type_bool_true
        elif isinstance(index, (int, float)):
            return cls._type_numeric
        elif isinstance(index, six.string_types):
            return cls._type_string
        else:
            return cls._type_object

    @classmethod
    def _extract_child(cls, value, path):
        segments = path.split('/')
        current = value
        for segment in segments:
            if isinstance(current, dict):
                current = current.get(segment)
            else:
                return None
        return current

    def _compare(self, other):
        """Compares two _SortEntry instances.

        If the indices have the same numeric or string type, compare them directly. Ties are
        broken by comparing the keys. If the indices have the same type, but are neither numeric
        nor string, compare the keys. In all other cases compare based on the ordering provided
        by index types.
        """
        self_key, other_key = self.index_type, other.index_type
        if self_key == other_key:
            if self_key in (self._type_numeric, self._type_string) and self.index != other.index:
                self_key, other_key = self.index, other.index
            else:
                self_key, other_key = self.key, other.key

        if self_key < other_key:
            return -1
        elif self_key > other_key:
            return 1
        else:
            return 0

    def __lt__(self, other):
        return self._compare(other) < 0

    def __le__(self, other):
        return self._compare(other) <= 0

    def __gt__(self, other):
        return self._compare(other) > 0

    def __ge__(self, other):
        return self._compare(other) >= 0

    def __eq__(self, other):
        return self._compare(other) is 0


class _Client(_http_client.JsonHttpClient):
    """HTTP client used to make REST calls.

    _Client maintains an HTTP session, and handles authenticating HTTP requests along with
    marshalling and unmarshalling of JSON data.
    """

    _DEFAULT_AUTH_OVERRIDE = '_admin_'

    def __init__(self, credential, base_url, auth_override=_DEFAULT_AUTH_OVERRIDE, timeout=None):
        """Creates a new _Client from the given parameters.

        This exists primarily to enable testing. For regular use, obtain _Client instances by
        calling the from_app() class method.

        Args:
          credential: A Google credential that can be used to authenticate requests.
          base_url: A URL prefix to be added to all outgoing requests. This is typically the
              Firebase Realtime Database URL.
          auth_override: A dictionary representing auth variable overrides or None (optional).
              Default value provides admin privileges. A None value here provides un-authenticated
              guest privileges.
          timeout: HTTP request timeout in seconds (optional). If not set connections will never
              timeout, which is the default behavior of the underlying requests library.
        """
        _http_client.JsonHttpClient.__init__(
            self, credential=credential, base_url=base_url, headers={'User-Agent': _USER_AGENT})
        if auth_override != self._DEFAULT_AUTH_OVERRIDE and auth_override != {}:
            encoded = json.dumps(auth_override, separators=(',', ':'))
            self._auth_override = 'auth_variable_override={0}'.format(encoded)
        else:
            self._auth_override = None
        self._timeout = timeout

    @classmethod
    def from_app(cls, app):
        """Creates a new _Client for a given App"""
        credential = app.credential.get_credential()
        db_url = cls._get_db_url(app)
        auth_override = cls._get_auth_override(app)
        timeout = app.options.get('httpTimeout')
        return _Client(credential, db_url, auth_override, timeout)

    @classmethod
    def _get_db_url(cls, app):
        """Retrieves and parses the database URL option."""
        url = app.options.get('databaseURL')
        if not url or not isinstance(url, six.string_types):
            raise ValueError(
                'Invalid databaseURL option: "{0}". databaseURL must be a non-empty URL '
                'string.'.format(url))

        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != 'https':
            raise ValueError(
                'Invalid databaseURL option: "{0}". databaseURL must be an HTTPS URL.'.format(url))
        elif not parsed.netloc.endswith('.firebaseio.com'):
            raise ValueError(
                'Invalid databaseURL option: "{0}". databaseURL must be a valid URL to a '
                'Firebase Realtime Database instance.'.format(url))
        return 'https://{0}'.format(parsed.netloc)

    @classmethod
    def _get_auth_override(cls, app):
        auth_override = app.options.get('databaseAuthVariableOverride', cls._DEFAULT_AUTH_OVERRIDE)
        if auth_override == cls._DEFAULT_AUTH_OVERRIDE or auth_override is None:
            return auth_override
        if not isinstance(auth_override, dict):
            raise ValueError('Invalid databaseAuthVariableOverride option: "{0}". Override '
                             'value must be a dict or None.'.format(auth_override))
        else:
            return auth_override

    @property
    def auth_override(self):
        return self._auth_override

    @property
    def timeout(self):
        return self._timeout

    def request(self, method, url, **kwargs):
        """Makes an HTTP call using the Python requests library.

        Extends the request() method of the parent JsonHttpClient class. Handles auth overrides,
        and low-level exceptions.

        Args:
          method: HTTP method name as a string (e.g. get, post).
          url: URL path of the remote endpoint. This will be appended to the server's base URL.
          kwargs: An additional set of keyword arguments to be passed into requests API
              (e.g. json, params).

        Returns:
          Response: An HTTP response object.

        Raises:
          ApiCallError: If an error occurs while making the HTTP call.
        """
        if self._auth_override:
            params = kwargs.get('params')
            if params:
                params += '&{0}'.format(self._auth_override)
            else:
                params = self._auth_override
            kwargs['params'] = params
        if self._timeout:
            kwargs['timeout'] = self._timeout
        try:
            return super(_Client, self).request(method, url, **kwargs)
        except requests.exceptions.RequestException as error:
            raise ApiCallError(self._extract_error_message(error), error)

    def _extract_error_message(self, error):
        """Extracts an error message from an exception.

        If the server has not sent any response, simply converts the exception into a string.
        If the server has sent a JSON response with an 'error' field, which is the typical
        behavior of the Realtime Database REST API, parses the response to retrieve the error
        message. If the server has sent a non-JSON response, returns the full response
        as the error message.

        Args:
          error: An exception raised by the requests library.

        Returns:
          str: A string error message extracted from the exception.
        """
        if error.response is None:
            return str(error)
        try:
            data = error.response.json()
            if isinstance(data, dict):
                return '{0}\nReason: {1}'.format(error, data.get('error', 'unknown'))
        except ValueError:
            pass
        return '{0}\nReason: {1}'.format(error, error.response.content.decode())
