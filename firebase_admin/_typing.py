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

import typing
import typing_extensions

import google.auth.credentials
import requests

import firebase_admin
from firebase_admin import credentials
from firebase_admin import exceptions
from firebase_admin import project_management


_KT = typing.TypeVar('_KT')
_VT_co = typing.TypeVar('_VT_co', covariant=True)
_AnyT = typing_extensions.TypeVar('_AnyT', default=typing.Any)
_AnyT_co = typing_extensions.TypeVar('_AnyT_co', covariant=True, default=typing.Any)
_FirebaseErrorT_co = typing_extensions.TypeVar(
    '_FirebaseErrorT_co', covariant=True, default='exceptions.FirebaseError')
_AppMetadataT_co = typing_extensions.TypeVar(
    '_AppMetadataT_co', covariant=True, default='project_management._AppMetadata')


class SupportsKeysAndGetItem(typing.Protocol[_KT, _VT_co]):
    # Equivalent to _typeshed.SupportsKeysAndGetItem, but works at runtime
    def keys(self) -> typing.Iterable[_KT]: ...
    def __getitem__(self, __key: _KT) -> _VT_co: ...


class _SupportsTrunc(typing.Protocol):
    def __trunc__(self) -> int: ...


ConvertibleToInt = typing.Union[
    str,
    typing_extensions.Buffer,
    typing.SupportsInt,
    typing.SupportsIndex,
    _SupportsTrunc,
]
ConvertibleToFloat: typing_extensions.TypeAlias = typing.Union[
    str,
    typing_extensions.Buffer,
    typing.SupportsFloat,
    typing.SupportsIndex,
]
CredentialLike = typing.Union['credentials.Base', google.auth.credentials.Credentials]
HeadersLike = typing.Union[
    SupportsKeysAndGetItem[str, typing.Union[bytes, str]],
    typing.Iterable[typing.Tuple[
        str,
        typing.Union[bytes, str]
    ]],
]
ServiceInitializer = typing.Callable[['firebase_admin.App'], _AnyT]
RequestErrorHandler = typing.Callable[
    [
        requests.RequestException,
        str,
        typing.Dict[str, typing.Any]
    ],
    typing.Optional['exceptions.FirebaseError'],
]
GoogleAPIErrorHandler = typing.Callable[
    [
        Exception,
        str,
        typing.Dict[str, typing.Any],
        requests.Response,
    ],
    typing.Optional['exceptions.FirebaseError'],
]
Json = typing.Optional[typing.Union[
    typing.Dict[str, 'Json'],
    typing.List['Json'],
    str,
    float,
]]
EmailActionType = typing.Literal[
    'VERIFY_EMAIL',
    'EMAIL_SIGNIN',
    'PASSWORD_RESET',
]

class FirebaseErrorFactory(typing.Protocol[_FirebaseErrorT_co]):
    def __call__(
        self,
        message: str,
        cause: typing.Optional[Exception],
        http_response: typing.Optional[requests.Response],
    ) -> _FirebaseErrorT_co: ...


class FirebaseErrorFactoryNoHttp(typing.Protocol[_FirebaseErrorT_co]):
    def __call__(
        self,
        message: str,
        cause: typing.Optional[Exception],
    ) -> _FirebaseErrorT_co: ...


class FirebaseErrorFactoryWithDefaults(typing.Protocol[_FirebaseErrorT_co]):
    def __call__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
        http_response: typing.Optional[requests.Response] = None,
    ) -> _FirebaseErrorT_co: ...


class FirebaseErrorFactoryNoHttpWithDefaults(typing.Protocol[_FirebaseErrorT_co]):
    def __call__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
    ) -> _FirebaseErrorT_co: ...


class AppMetadataSubclass(typing.Protocol[_AppMetadataT_co]):
    def __call__(
        self,
        __identifier: str,
        name: str,
        app_id: str,
        display_name: typing.Optional[str],
        project_id: str
    ) -> _AppMetadataT_co: ...


class ProjectApp(typing.Protocol[_AnyT_co]):
    def __call__(
        self,
        app_id: str,
        service: 'project_management._ProjectManagementService',
    ) -> _AnyT_co: ...


class Page(typing.Protocol):
    @property
    def has_next_page(self) -> bool: ...

    def get_next_page(self) -> typing.Optional[typing_extensions.Self]: ...
