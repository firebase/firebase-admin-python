# Copyright 2025 Google Inc.
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

"""Internal retry logic module

This module provides utilities for adding retry logic to HTTPX requests
"""

from __future__ import annotations
import copy
import email.utils
import random
import re
import time
from types import CoroutineType
from typing import Any, Callable, List, Optional, Tuple
import logging
import asyncio
import httpx

logger = logging.getLogger(__name__)


class HttpxRetry:
    """HTTPX based retry config"""
    # TODO: Decide
    # urllib3.Retry ignores the status_forcelist when respecting Retry-After header
    # Only 413, 429 and 503 errors are retried with the Retry-After header.
    # Should we do the same?
    # Default status codes to be used for ``status_forcelist``
    RETRY_AFTER_STATUS_CODES = frozenset([413, 429, 503])

    #: Default maximum backoff time.
    DEFAULT_BACKOFF_MAX = 120

    def __init__(
            self,
            status: int = 10,
            status_forcelist: Optional[List[int]] = None,
            backoff_factor: float = 0,
            backoff_max: float = DEFAULT_BACKOFF_MAX,
            raise_on_status: bool = False,
            backoff_jitter: float = 0,
            history: Optional[List[Tuple[
                httpx.Request,
                Optional[httpx.Response],
                Optional[Exception]
            ]]] = None,
            respect_retry_after_header: bool = False,
    ) -> None:
        self.status = status
        self.status_forcelist = status_forcelist
        self.backoff_factor = backoff_factor
        self.backoff_max = backoff_max
        self.raise_on_status = raise_on_status
        self.backoff_jitter = backoff_jitter
        if history:
            self.history = history
        else:
            self.history = []
        self.respect_retry_after_header = respect_retry_after_header

    def copy(self) -> HttpxRetry:
        """Creates a deep copy of this instance."""
        return copy.deepcopy(self)

    def is_retryable_response(self, response: httpx.Response) -> bool:
        """Determine if a response implies that the request should be retried if possible."""
        if self.status_forcelist and response.status_code in self.status_forcelist:
            return True

        has_retry_after = bool(response.headers.get("Retry-After"))
        if (
                self.respect_retry_after_header
                and has_retry_after
                and response.status_code in self.RETRY_AFTER_STATUS_CODES
        ):
            return True

        return False

    # Placeholder for exception retrying
    def is_retryable_error(self, error: Exception):
        """Determine if the error implies that the request should be retired if possible."""
        logger.debug(error)
        return False

    def is_exhausted(self) -> bool:
        """Determine if there are anymore more retires."""
        # status count is negative
        return self.status < 0

    # Identical implementation of `urllib3.Retry.parse_retry_after()`
    def _parse_retry_after(self, retry_after_header: str) -> float | None:
        """Parses Retry-After string into a float with unit seconds."""
        seconds: float
        # Whitespace: https://tools.ietf.org/html/rfc7230#section-3.2.4
        if re.match(r"^\s*[0-9]+\s*$", retry_after_header):
            seconds = int(retry_after_header)
        else:
            retry_date_tuple = email.utils.parsedate_tz(retry_after_header)
            if retry_date_tuple is None:
                # TODO: Verify if this is the appropriate way to handle this.
                raise httpx.RemoteProtocolError(f"Invalid Retry-After header: {retry_after_header}")

            retry_date = email.utils.mktime_tz(retry_date_tuple)
            seconds = retry_date - time.time()

        seconds = max(seconds, 0)

        return seconds

    def get_retry_after(self, response: httpx.Response) -> float | None:
        """Determine the Retry-After time needed before sending the next request."""
        retry_after_header = response.headers.get('Retry-After', None)
        if retry_after_header:
            # Convert retry header to a float in seconds
            return self._parse_retry_after(retry_after_header)
        return None

    def get_backoff_time(self):
        """Determine the backoff time needed before sending the next request."""
        # attempt_count is the number of previous request attempts
        attempt_count = len(self.history)
        # Backoff should be set to 0 until after first retry.
        if attempt_count <= 1:
            return 0
        backoff = self.backoff_factor * (2 ** (attempt_count-1))
        if self.backoff_jitter:
            backoff += random.random() * self.backoff_jitter
        return float(max(0, min(self.backoff_max, backoff)))

    async def sleep_for_backoff(self) -> None:
        """Determine and wait the backoff time needed before sending the next request."""
        backoff = self.get_backoff_time()
        logger.debug('Sleeping for backoff of %f seconds following failed request', backoff)
        await asyncio.sleep(backoff)

    async def sleep(self, response: httpx.Response) -> None:
        """Determine and wait the time needed before sending the next request."""
        if self.respect_retry_after_header:
            retry_after = self.get_retry_after(response)
            if retry_after:
                logger.debug(
                    'Sleeping for Retry-After header of %f seconds following failed request',
                    retry_after
                )
                await asyncio.sleep(retry_after)
                return
        await self.sleep_for_backoff()

    def increment(
            self,
            request: httpx.Request,
            response: Optional[httpx.Response] = None,
            error: Optional[Exception] = None
    ) -> None:
        """Update the retry state based on request attempt."""
        if response and self.is_retryable_response(response):
            self.status -= 1
        self.history.append((request, response, error))


# TODO: Remove comments
# Note - This implementation currently covers:
#   - basic retires for pre-defined status errors
#   - applying retry backoff and backoff jitter
#   - ability to respect a response's retry-after header
class HttpxRetryTransport(httpx.AsyncBaseTransport):
    """HTTPX transport with retry logic."""

    # DEFAULT_RETRY = HttpxRetry(
    #     connect=1, read=1, status=4, status_forcelist=[500, 503],
    #     raise_on_status=False, backoff_factor=0.5, allowed_methods=None
    # )
    DEFAULT_RETRY = HttpxRetry(status=4, status_forcelist=[500, 503], backoff_factor=0.5)

    # We could also support passing kwargs here
    def __init__(self, retry: HttpxRetry = DEFAULT_RETRY, **kwargs) -> None:
        self._retry = retry

        transport_kwargs = kwargs.copy()
        transport_kwargs.update({'retries': 0, 'http2': True})
        # We should use a full AsyncHTTPTransport under the hood since that is
        # fully implemented. We could consider making this class extend a
        # AsyncHTTPTransport instead and use the parent class's methods to handle
        # requests. We sould also ensure that that transport's internal retry is
        # not enabled.
        self._wrapped_transport = httpx.AsyncHTTPTransport(**transport_kwargs)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._dispatch_with_retry(
            request, self._wrapped_transport.handle_async_request)

    # Two types of retries
    # - Status code (500s, redirect)
    # - Error code (read, connect, other)
    async def _dispatch_with_retry(
            self,
            request: httpx.Request,
            dispatch_method: Callable[[httpx.Request], CoroutineType[Any, Any, httpx.Response]]
    ) -> httpx.Response:
        """Sends a request with retry logic using a provided dispatch method."""
        # This request config is used across all requests that use this transport and therefore
        # needs to be copied to be used for just this request ans it's retries.
        retry = self._retry.copy()
        # First request
        response, error = None, None

        while not retry.is_exhausted():

            # First retry
            if response:
                await retry.sleep(response)

            # Need to reset here so only last attempt's error or response is saved.
            response, error = None, None

            try:
                logger.debug('Sending request in _dispatch_with_retry(): %r', request)
                response = await dispatch_method(request)
                logger.debug('Received response: %r', response)
            except httpx.HTTPError as err:
                logger.debug('Received error: %r', err)
                error = err

            if response and not retry.is_retryable_response(response):
                return response

            if error and not retry.is_retryable_error(error):
                raise error

            retry.increment(request, response)

        if response:
            return response
        if error:
            raise error
        raise Exception('_dispatch_with_retry() ended with no response or exception')

    async def aclose(self) -> None:
        await self._wrapped_transport.aclose()
