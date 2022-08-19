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

"""Internal async HTTP client module.

 This module provides utilities for making async HTTP calls using the aiohttp library.
 """
import json

import aiohttp
from aiohttp.client_exceptions import ClientResponseError
from google.auth.transport import _aiohttp_requests # type: ignore
from google.auth.transport._aiohttp_requests import _CombinedResponse # type: ignore


DEFAULT_RETRY_ATTEMPTS = 4
DEFAULT_RETRY_CODES = (500, 503)
DEFAULT_TIMEOUT_SECONDS = 120




class HttpClientAsync:
    """Base HTTP client used to make aiohttp calls.

    HttpClientAsync maintains an aiohttp session, and handles request authentication and retries if
    necessary.
    """

    def __init__(
            self,
            credential=None,
            session=None,
            base_url='',
            headers=None,
            retry_attempts=DEFAULT_RETRY_ATTEMPTS,
            retry_codes=DEFAULT_RETRY_CODES,
            timeout=DEFAULT_TIMEOUT_SECONDS
        ):
        """Creates a new HttpClientAsync instance from the provided arguments.

        If a credential is provided, initializes a new aiohttp client session authorized with it.
        If neither a credential nor a session is provided, initializes a new unauthorized client
        session.

        Args:
          credential: A Google credential that can be used to authenticate requests (optional).
          session: A custom aiohttp session (optional).
          base_url: A URL prefix to be added to all outgoing requests (optional).
          headers: A map of headers to be added to all outgoing requests (optional).
          retry_attempts: The maximum number of retries that should be attempeted for a request
              (optional).
          retry_codes: A list of status codes for which the request retry should be attempted
              (optional).
          timeout: A request timeout in seconds. Defaults to 120 seconds when not specified. Set to
              None to disable timeouts (optional).
        """
        if credential:
            self._session = _aiohttp_requests.AuthorizedSession(
                credential,
                max_refresh_attempts=retry_attempts,
                refresh_status_codes=retry_codes,
                refresh_timeout=timeout
            )
        elif session:
            self._session = session
        else:
            self._session = aiohttp.ClientSession() # pylint: disable=redefined-variable-type

        if headers:
            self._session.headers.update(headers)
        self._base_url = base_url
        self._timeout = timeout

    @property
    def session(self):
        return self._session

    @property
    def base_url(self):
        return self._base_url

    @property
    def timeout(self):
        return self._timeout

    def parse_body(self, resp):
        raise NotImplementedError

    async def request(self, method, url, **kwargs):
        """Makes an async HTTP call using the aiohttp library.

        This is the sole entry point to the aiohttp library. All other helper methods in this
        class call this method to send async HTTP requests out. Refer to
        http://docs.python-requests.org/en/master/api/ for more information on supported options
        and features.

        Args:
          method: HTTP method name as a string (e.g. get, post).
          url: URL of the remote endpoint.
          **kwargs: An additional set of keyword arguments to be passed into the aiohttp API
              (e.g. json, params, timeout).

        Returns:
          Response: A ``_CombinedResponse`` wrapped ``ClientResponse`` object.

        Raises:
          ClientResponseWithBodyError: Any requests exceptions encountered while making the async
          HTTP call.
        """
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
        resp = await self._session.request(method, self.base_url + url, **kwargs)
        wrapped_resp = _CombinedResponse(resp)

        try:
            # Get response content from StreamReader before it is closed by error throw.
            resp_content = await wrapped_resp.content()
            resp.raise_for_status()

        # Catch response error and re-release it after appending response body needed to
        # determine the underlying reason for the error.
        except ClientResponseError as err:
            raise ClientResponseWithBodyError(
                err.request_info,
                err.history,
                wrapped_resp,
                resp_content
            ) from err
        return wrapped_resp

    async def headers(self, method, url, **kwargs):
        resp = await self.request(method, url, **kwargs)
        return resp.headers

    async def body_and_response(self, method, url, **kwargs):
        resp = await self.request(method, url, **kwargs)
        return await self.parse_body(resp), resp

    async def body(self, method, url, **kwargs):
        resp = await self.request(method, url, **kwargs)
        return await self.parse_body(resp)

    async def headers_and_body(self, method, url, **kwargs):
        resp = await self.request(method, url, **kwargs)
        return await resp.headers, self.parse_body(resp)

    async def close(self):
        if self._session is not None:
            await self._session.close()
            self._session = None


class JsonHttpClientAsync(HttpClientAsync):
    """An async HTTP client that parses response messages as JSON."""

    def __init__(self, **kwargs):
        HttpClientAsync.__init__(self, **kwargs)

    async def parse_body(self, resp):
        content = await resp.content()
        return json.loads(content)


class ClientResponseWithBodyError(aiohttp.ClientResponseError):
    """A ClientResponseError wrapper to hold the response body of the underlying falied
    aiohttp request.
    """
    def __init__(self, request_info, history, response, response_content):
        super(ClientResponseWithBodyError, self).__init__(request_info, history)
        self.response = response
        self.response_content = response_content
