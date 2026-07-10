# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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
#
from typing import Any, AsyncIterable, Awaitable, Callable, Iterable, Sequence, Tuple, Optional

from google.firebase.appcheck_v1beta.types import configuration


class ListDebugTokensPager:
    """A pager for iterating through ``list_debug_tokens`` requests.

    This class thinly wraps an initial
    :class:`google.firebase.appcheck_v1beta.types.ListDebugTokensResponse` object, and
    provides an ``__iter__`` method to iterate through its
    ``debug_tokens`` field.

    If there are more pages, the ``__iter__`` method will make additional
    ``ListDebugTokens`` requests and continue to iterate
    through the ``debug_tokens`` field on the
    corresponding responses.

    All the usual :class:`google.firebase.appcheck_v1beta.types.ListDebugTokensResponse`
    attributes are available on the pager. If multiple requests are made, only
    the most recent response is retained, and thus used for attribute lookup.
    """
    def __init__(self,
            method: Callable[..., configuration.ListDebugTokensResponse],
            request: configuration.ListDebugTokensRequest,
            response: configuration.ListDebugTokensResponse,
            *,
            metadata: Sequence[Tuple[str, str]] = ()):
        """Instantiate the pager.

        Args:
            method (Callable): The method that was originally called, and
                which instantiated this pager.
            request (google.firebase.appcheck_v1beta.types.ListDebugTokensRequest):
                The initial request object.
            response (google.firebase.appcheck_v1beta.types.ListDebugTokensResponse):
                The initial response object.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.
        """
        self._method = method
        self._request = configuration.ListDebugTokensRequest(request)
        self._response = response
        self._metadata = metadata

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response, name)

    @property
    def pages(self) -> Iterable[configuration.ListDebugTokensResponse]:
        yield self._response
        while self._response.next_page_token:
            self._request.page_token = self._response.next_page_token
            self._response = self._method(self._request, metadata=self._metadata)
            yield self._response

    def __iter__(self) -> Iterable[configuration.DebugToken]:
        for page in self.pages:
            yield from page.debug_tokens

    def __repr__(self) -> str:
        return '{0}<{1!r}>'.format(self.__class__.__name__, self._response)


class ListServicesPager:
    """A pager for iterating through ``list_services`` requests.

    This class thinly wraps an initial
    :class:`google.firebase.appcheck_v1beta.types.ListServicesResponse` object, and
    provides an ``__iter__`` method to iterate through its
    ``services`` field.

    If there are more pages, the ``__iter__`` method will make additional
    ``ListServices`` requests and continue to iterate
    through the ``services`` field on the
    corresponding responses.

    All the usual :class:`google.firebase.appcheck_v1beta.types.ListServicesResponse`
    attributes are available on the pager. If multiple requests are made, only
    the most recent response is retained, and thus used for attribute lookup.
    """
    def __init__(self,
            method: Callable[..., configuration.ListServicesResponse],
            request: configuration.ListServicesRequest,
            response: configuration.ListServicesResponse,
            *,
            metadata: Sequence[Tuple[str, str]] = ()):
        """Instantiate the pager.

        Args:
            method (Callable): The method that was originally called, and
                which instantiated this pager.
            request (google.firebase.appcheck_v1beta.types.ListServicesRequest):
                The initial request object.
            response (google.firebase.appcheck_v1beta.types.ListServicesResponse):
                The initial response object.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.
        """
        self._method = method
        self._request = configuration.ListServicesRequest(request)
        self._response = response
        self._metadata = metadata

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response, name)

    @property
    def pages(self) -> Iterable[configuration.ListServicesResponse]:
        yield self._response
        while self._response.next_page_token:
            self._request.page_token = self._response.next_page_token
            self._response = self._method(self._request, metadata=self._metadata)
            yield self._response

    def __iter__(self) -> Iterable[configuration.Service]:
        for page in self.pages:
            yield from page.services

    def __repr__(self) -> str:
        return '{0}<{1!r}>'.format(self.__class__.__name__, self._response)
