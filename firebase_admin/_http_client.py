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

"""Internal HTTP client module.

 This module provides utilities for making HTTP calls using the requests library.
 """

from google.auth import transport
import requests
from requests.packages.urllib3.util import retry # pylint: disable=import-error


_ANY_METHOD = None

# Default retry configuration: Retries once on low-level connection and socket read errors.
# Retries up to 4 times on HTTP 500 and 503 errors, with exponential backoff. Returns the
# last response upon exhausting all retries.
DEFAULT_RETRY_CONFIG = retry.Retry(
    connect=1, read=1, status=4, status_forcelist=[500, 503], method_whitelist=_ANY_METHOD,
    raise_on_status=False, backoff_factor=0.5)


class HttpClient(object):
    """Base HTTP client used to make HTTP calls.

    HttpClient maintains an HTTP session, and handles request authentication and retries if
    necessary.
    """

    def __init__(
            self, credential=None, session=None, base_url='', headers=None,
            retries=DEFAULT_RETRY_CONFIG):
        """Creates a new HttpClient instance from the provided arguments.

        If a credential is provided, initializes a new HTTP session authorized with it. If neither
        a credential nor a session is provided, initializes a new unauthorized session.

        Args:
          credential: A Google credential that can be used to authenticate requests (optional).
          session: A custom HTTP session (optional).
          base_url: A URL prefix to be added to all outgoing requests (optional).
          headers: A map of headers to be added to all outgoing requests (optional).
          retries: A urllib retry configuration. Default settings would retry once for low-level
              connection and socket read errors, and up to 4 times for HTTP 500 and 503 errors.
              Pass a False value to disable retries (optional).
        """
        if credential:
            self._session = transport.requests.AuthorizedSession(credential)
        elif session:
            self._session = session
        else:
            self._session = requests.Session() # pylint: disable=redefined-variable-type

        if headers:
            self._session.headers.update(headers)
        if retries:
            self._session.mount('http://', requests.adapters.HTTPAdapter(max_retries=retries))
            self._session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retries))
        self._base_url = base_url

    @property
    def session(self):
        return self._session

    @property
    def base_url(self):
        return self._base_url

    def parse_body(self, resp):
        raise NotImplementedError

    def request(self, method, url, **kwargs):
        """Makes an HTTP call using the Python requests library.

        This is the sole entry point to the requests library. All other helper methods in this
        class call this method to send HTTP requests out. Refer to
        http://docs.python-requests.org/en/master/api/ for more information on supported options
        and features.

        Args:
          method: HTTP method name as a string (e.g. get, post).
          url: URL of the remote endpoint.
          kwargs: An additional set of keyword arguments to be passed into the requests API
              (e.g. json, params).

        Returns:
          Response: An HTTP response object.

        Raises:
          RequestException: Any requests exceptions encountered while making the HTTP call.
        """
        resp = self._session.request(method, self._base_url + url, **kwargs)
        resp.raise_for_status()
        return resp

    def headers(self, method, url, **kwargs):
        resp = self.request(method, url, **kwargs)
        return resp.headers

    def body_and_response(self, method, url, **kwargs):
        resp = self.request(method, url, **kwargs)
        return self.parse_body(resp), resp

    def body(self, method, url, **kwargs):
        resp = self.request(method, url, **kwargs)
        return self.parse_body(resp)

    def headers_and_body(self, method, url, **kwargs):
        resp = self.request(method, url, **kwargs)
        return resp.headers, self.parse_body(resp)

    def close(self):
        self._session.close()
        self._session = None


class JsonHttpClient(HttpClient):
    """An HTTP client that parses response messages as JSON."""

    def __init__(self, **kwargs):
        HttpClient.__init__(self, **kwargs)

    def parse_body(self, resp):
        return resp.json()
