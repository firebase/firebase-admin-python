# Copyright 2020 Google Inc.
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

# This module adds some type annotations that refer to types defined in other
# submodules. To avoid circular import issues (NameError), the evaluation of 
# these annotations is deferred by using string literals (forward references).
# This allows the annotations to be valid at runtime without requiring the immediate
# loading of the referenced symbols.

from collections.abc import Iterable
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    Protocol,
    SupportsFloat,
    SupportsIndex,
    SupportsInt,
    Tuple,
    Union,
)
from typing_extensions import Buffer, Self, TypeAlias, TypeVar

import google.auth.credentials
import requests

import firebase_admin
from firebase_admin import credentials
from firebase_admin import exceptions
from firebase_admin import project_management

__all__ = (
    'AppMetadataSubclass',
    'ConvertibleToFloat',
    'ConvertibleToInt',
    'CredentialLike',
    'EmailActionType',
    'FirebaseErrorFactory',
    'FirebaseErrorFactoryNoHttp',
    'FirebaseErrorFactoryNoHttpWithDefaults',
    'FirebaseErrorFactoryWithDefaults',
    'GoogleAPIErrorHandler',
    'HeadersLike',
    'Json',
    'Page',
    'ProjectApp',
    'RequestErrorHandler',
    'ServiceInitializer',
    'SupportsKeysAndGetItem',
)

_KT = TypeVar('_KT')
_VT_co = TypeVar('_VT_co', covariant=True)
_AnyT = TypeVar('_AnyT', default=Any)
_AnyT_co = TypeVar('_AnyT_co', covariant=True, default=Any)
_FirebaseErrorT_co = TypeVar(
    '_FirebaseErrorT_co', covariant=True, default='exceptions.FirebaseError')
_AppMetadataT_co = TypeVar(
    '_AppMetadataT_co', covariant=True, default='project_management._AppMetadata')


class SupportsKeysAndGetItem(Protocol[_KT, _VT_co]):
    # Equivalent to _typeshed.SupportsKeysAndGetItem, but works at runtime
    def keys(self) -> 'Iterable[_KT]': ...
    def __getitem__(self, __key: _KT) -> _VT_co: ...


class _SupportsTrunc(Protocol):
    def __trunc__(self) -> int: ...


ConvertibleToInt = Union[
    str,
    Buffer,
    SupportsInt,
    SupportsIndex,
    _SupportsTrunc,
]
ConvertibleToFloat: TypeAlias = Union[
    str,
    Buffer,
    SupportsFloat,
    SupportsIndex,
]
CredentialLike = Union['credentials.Base', google.auth.credentials.Credentials]
HeadersLike = Union[
    SupportsKeysAndGetItem[str, Union[bytes, str]],
    'Iterable[Tuple[str, Union[bytes, str]]]',
]
ServiceInitializer: TypeAlias = Callable[['firebase_admin.App'], _AnyT]
RequestErrorHandler: TypeAlias = Callable[
    [
        requests.RequestException,
        str,
        Dict[str, Any]
    ],
    Optional['exceptions.FirebaseError'],
]
GoogleAPIErrorHandler: TypeAlias = Callable[
    [
        Exception,
        str,
        Dict[str, Any],
        requests.Response,
    ],
    Optional['exceptions.FirebaseError'],
]
Json = Optional[Union[
    Dict[str, 'Json'],
    List['Json'],
    str,
    float,
]]
EmailActionType = Literal[
    'VERIFY_EMAIL',
    'EMAIL_SIGNIN',
    'PASSWORD_RESET',
]

class FirebaseErrorFactory(Protocol[_FirebaseErrorT_co]):
    def __call__(
        self,
        message: str,
        cause: Optional[Exception],
        http_response: Optional[requests.Response],
    ) -> _FirebaseErrorT_co: ...


class FirebaseErrorFactoryNoHttp(Protocol[_FirebaseErrorT_co]):
    def __call__(
        self,
        message: str,
        cause: Optional[Exception],
    ) -> _FirebaseErrorT_co: ...


class FirebaseErrorFactoryWithDefaults(Protocol[_FirebaseErrorT_co]):
    def __call__(
        self,
        message: str,
        cause: Optional[Exception] = None,
        http_response: Optional[requests.Response] = None,
    ) -> _FirebaseErrorT_co: ...


class FirebaseErrorFactoryNoHttpWithDefaults(Protocol[_FirebaseErrorT_co]):
    def __call__(
        self,
        message: str,
        cause: Optional[Exception] = None,
    ) -> _FirebaseErrorT_co: ...


class AppMetadataSubclass(Protocol[_AppMetadataT_co]):
    def __call__(
        self,
        __identifier: str,
        name: str,
        app_id: str,
        display_name: Optional[str],
        project_id: str
    ) -> _AppMetadataT_co: ...


class ProjectApp(Protocol[_AnyT_co]):
    def __call__(
        self,
        app_id: str,
        service: 'project_management._ProjectManagementService',
    ) -> _AnyT_co: ...


class Page(Protocol):
    @property
    def has_next_page(self) -> bool: ...

    def get_next_page(self) -> Optional[Self]: ...
