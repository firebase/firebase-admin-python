# Copyright 2018 Google Inc.
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

"""Firebase auth utils."""

import json
import os
import re
import typing
from urllib import parse

import requests

from firebase_admin import exceptions
from firebase_admin import _typing
from firebase_admin import _utils


_PageT = typing.TypeVar("_PageT", bound=_typing.Page)

EMULATOR_HOST_ENV_VAR = 'FIREBASE_AUTH_EMULATOR_HOST'
MAX_CLAIMS_PAYLOAD_SIZE = 1000
RESERVED_CLAIMS = set([
    'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash', 'exp', 'iat',
    'iss', 'jti', 'nbf', 'nonce', 'sub', 'firebase',
])
VALID_EMAIL_ACTION_TYPES = set(['VERIFY_EMAIL', 'EMAIL_SIGNIN', 'PASSWORD_RESET'])


class PageIterator(typing.Generic[_PageT]):
    """An iterator that allows iterating over a sequence of items, one at a time.

    This implementation loads a page of items into memory, and iterates on them. When the whole
    page has been traversed, it loads another page. This class never keeps more than one page
    of entries in memory.
    """

    def __init__(self, current_page: _PageT) -> None:
        if not current_page:
            raise ValueError('Current page must not be None.')

        self._current_page: typing.Optional[_PageT] = current_page
        self._iter: typing.Optional[typing.Iterator[_PageT]] = None

    def __next__(self) -> _PageT:
        if self._iter is None:
            self._iter = iter(self.items)

        try:
            return next(self._iter)
        except StopIteration:
            if self._current_page and self._current_page.has_next_page:
                self._current_page = self._current_page.get_next_page()
                self._iter = iter(self.items)

                return next(self._iter)

            raise

    def __iter__(self) -> typing.Iterator[_PageT]:
        return self

    @property
    def items(self) -> typing.Sequence[typing.Any]:
        raise NotImplementedError


def get_emulator_host() -> str:
    emulator_host = os.getenv(EMULATOR_HOST_ENV_VAR, '')
    if emulator_host and '//' in emulator_host:
        raise ValueError(
            'Invalid {0}: "{1}". It must follow format "host:port".'.format(
                EMULATOR_HOST_ENV_VAR, emulator_host))
    return emulator_host


def is_emulated() -> bool:
    return get_emulator_host() != ''


@typing.overload
def validate_uid(uid: typing.Optional[typing.Any], required: typing.Literal[True]) -> str: ...
@typing.overload
def validate_uid(uid: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]: ...
def validate_uid(uid: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]:
    if uid is None and not required:
        return None
    if not isinstance(uid, str) or not uid or len(uid) > 128:
        raise ValueError(
            'Invalid uid: "{0}". The uid must be a non-empty string with no more than 128 '
            'characters.'.format(uid))
    return uid


@typing.overload
def validate_email(email: typing.Optional[typing.Any], required: typing.Literal[True]) -> str: ...
@typing.overload
def validate_email(email: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]: ...
def validate_email(email: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]:
    if email is None and not required:
        return None
    if not isinstance(email, str) or not email:
        raise ValueError(
            'Invalid email: "{0}". Email must be a non-empty string.'.format(email))
    parts = email.split('@')
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError('Malformed email address string: "{0}".'.format(email))
    return email


@typing.overload
def validate_phone(phone: typing.Optional[typing.Any], required: typing.Literal[True]) -> str: ...
@typing.overload
def validate_phone(phone: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]: ...
def validate_phone(phone: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]:
    """Validates the specified phone number.

    Phone number vlidation is very lax here. Backend will enforce E.164 spec compliance, and
    normalize accordingly. Here we check if the number starts with + sign, and contains at
    least one alphanumeric character.
    """
    if phone is None and not required:
        return None
    if not isinstance(phone, str) or not phone:
        raise ValueError('Invalid phone number: "{0}". Phone number must be a non-empty '
                         'string.'.format(phone))
    if not phone.startswith('+') or not re.search('[a-zA-Z0-9]', phone):
        raise ValueError('Invalid phone number: "{0}". Phone number must be a valid, E.164 '
                         'compliant identifier.'.format(phone))
    return phone


@typing.overload
def validate_password(password: typing.Optional[typing.Any], required: typing.Literal[True]) -> str: ...
@typing.overload
def validate_password(password: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]: ...
def validate_password(password: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]:
    if password is None and not required:
        return None
    if not isinstance(password, str) or len(password) < 6:
        raise ValueError(
            'Invalid password string. Password must be a string at least 6 characters long.')
    return password


@typing.overload
def validate_bytes(value: typing.Optional[typing.Any], label: typing.Any, required: typing.Literal[True]) -> bytes: ...
@typing.overload
def validate_bytes(value: typing.Optional[typing.Any], label: typing.Any, required: bool = False) -> typing.Optional[bytes]: ...
def validate_bytes(value: typing.Optional[typing.Any], label: typing.Any, required: bool = False) -> typing.Optional[bytes]:
    if value is None and not required:
        return None
    if not isinstance(value, bytes) or not value:
        raise ValueError('{0} must be a non-empty byte sequence.'.format(label))
    return value


@typing.overload
def validate_display_name(display_name: typing.Optional[typing.Any], required: typing.Literal[True]) -> str: ...
@typing.overload
def validate_display_name(display_name: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]: ...
def validate_display_name(display_name: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]:
    if display_name is None and not required:
        return None
    if not isinstance(display_name, str) or not display_name:
        raise ValueError(
            'Invalid display name: "{0}". Display name must be a non-empty '
            'string.'.format(display_name))
    return display_name


@typing.overload
def validate_provider_id(provider_id: typing.Optional[typing.Any], required: typing.Literal[True]) -> str: ...
@typing.overload
def validate_provider_id(provider_id: typing.Optional[typing.Any], required: bool = True) -> typing.Optional[str]: ...
def validate_provider_id(provider_id: typing.Optional[typing.Any], required: bool = True) -> typing.Optional[str]:
    if provider_id is None and not required:
        return None
    if not isinstance(provider_id, str) or not provider_id:
        raise ValueError(
            'Invalid provider ID: "{0}". Provider ID must be a non-empty '
            'string.'.format(provider_id))
    return provider_id


@typing.overload
def validate_provider_uid(provider_uid: typing.Optional[typing.Any], required: typing.Literal[True] = True) -> str: ...
@typing.overload
def validate_provider_uid(provider_uid: typing.Optional[typing.Any], required: bool = True) -> typing.Optional[str]: ...
def validate_provider_uid(provider_uid: typing.Optional[typing.Any], required: bool = True) -> typing.Optional[str]:
    if provider_uid is None and not required:
        return None
    if not isinstance(provider_uid, str) or not provider_uid:
        raise ValueError(
            'Invalid provider UID: "{0}". Provider UID must be a non-empty '
            'string.'.format(provider_uid))
    return provider_uid


@typing.overload
def validate_photo_url(photo_url: typing.Optional[typing.Any], required: typing.Literal[True]) -> str: ...
@typing.overload
def validate_photo_url(photo_url: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]: ...
def validate_photo_url(photo_url: typing.Optional[typing.Any], required: bool = False) -> typing.Optional[str]:
    """Parses and validates the given URL string."""
    if photo_url is None and not required:
        return None
    if not isinstance(photo_url, str) or not photo_url:
        raise ValueError(
            'Invalid photo URL: "{0}". Photo URL must be a non-empty '
            'string.'.format(photo_url))
    try:
        parsed = parse.urlparse(photo_url)
        if not parsed.netloc:
            raise ValueError('Malformed photo URL: "{0}".'.format(photo_url))
        return photo_url
    except Exception:
        raise ValueError('Malformed photo URL: "{0}".'.format(photo_url))


@typing.overload
def validate_timestamp(
    timestamp: typing.Optional[typing.Any],
    label: typing.Any,
    required: typing.Literal[True],
) -> int: ...
@typing.overload
def validate_timestamp(
    timestamp: typing.Optional[typing.Any],
    label: typing.Any,
    required: bool = False,
) -> typing.Optional[int]: ...
def validate_timestamp(
    timestamp: typing.Optional[typing.Any],
    label: typing.Any,
    required: bool = False,
) -> typing.Optional[int]:
    """Validates the given timestamp value. Timestamps must be positive integers."""
    if timestamp is None and not required:
        return None
    if isinstance(timestamp, bool):
        raise ValueError('Boolean value specified as timestamp.')
    try:
        timestamp_int = int(timestamp)  # type: ignore[reportArgumentType, arg-type]
    except TypeError:
        raise ValueError('Invalid type for timestamp value: {0}.'.format(timestamp))
    else:
        if timestamp_int != timestamp:
            raise ValueError('{0} must be a numeric value and a whole number.'.format(label))
        if timestamp_int <= 0:
            raise ValueError('{0} timestamp must be a positive interger.'.format(label))
        return timestamp_int


def validate_int(
    value: typing.Any,
    label: typing.Any,
    low: typing.Optional[int] = None,
    high: typing.Optional[int] = None,
) -> int:
    """Validates that the given value represents an integer.

    There are several ways to represent an integer in Python (e.g. 2, 2L, 2.0). This method allows
    for all such representations except for booleans. Booleans also behave like integers, but
    always translate to 1 and 0. Passing a boolean to an API that expects integers is most likely
    a developer error.
    """
    if value is None or isinstance(value, bool):
        raise ValueError('Invalid type for integer value: {0}.'.format(value))
    try:
        val_int = int(value)
    except TypeError:
        raise ValueError('Invalid type for integer value: {0}.'.format(value))
    else:
        if val_int != value:
            # This will be True for non-numeric values like '2' and non-whole numbers like 2.5.
            raise ValueError('{0} must be a numeric value and a whole number.'.format(label))
        if low is not None and val_int < low:
            raise ValueError('{0} must not be smaller than {1}.'.format(label, low))
        if high is not None and val_int > high:
            raise ValueError('{0} must not be larger than {1}.'.format(label, high))
        return val_int


def validate_string(value: typing.Any, label: typing.Any) -> str:
    """Validates that the given value is a string."""
    if not isinstance(value, str):
        raise ValueError('Invalid type for {0}: {1}.'.format(label, value))
    return value


def validate_boolean(value: typing.Any, label: typing.Any) -> bool:
    """Validates that the given value is a boolean."""
    if not isinstance(value, bool):
        raise ValueError('Invalid type for {0}: {1}.'.format(label, value))
    return value


@typing.overload
def validate_custom_claims(custom_claims: typing.Any, required: typing.Literal[True]) -> str: ...
@typing.overload
def validate_custom_claims(custom_claims: typing.Any, required: bool = False) -> typing.Optional[str]: ...
def validate_custom_claims(custom_claims: typing.Any, required: bool = False) -> typing.Optional[str]:
    """Validates the specified custom claims.

    Custom claims must be specified as a JSON string. The string must not exceed 1000
    characters, and the parsed JSON payload must not contain reserved JWT claims.
    """
    if custom_claims is None and not required:
        return None
    claims_str = str(custom_claims)
    if len(claims_str) > MAX_CLAIMS_PAYLOAD_SIZE:
        raise ValueError(
            'Custom claims payload must not exceed {0} characters.'.format(
                MAX_CLAIMS_PAYLOAD_SIZE))
    try:
        parsed = json.loads(claims_str)
    except Exception:
        raise ValueError('Failed to parse custom claims string as JSON.')

    if not isinstance(parsed, dict):
        raise ValueError('Custom claims must be parseable as a JSON object.')
    invalid_claims = RESERVED_CLAIMS.intersection(set(parsed.keys()))  # type: ignore[reportUnknownArgumentType]
    if len(invalid_claims) > 1:
        joined = ', '.join(sorted(invalid_claims))
        raise ValueError('Claims "{0}" are reserved, and must not be set.'.format(joined))
    if len(invalid_claims) == 1:
        raise ValueError(
            'Claim "{0}" is reserved, and must not be set.'.format(invalid_claims.pop()))
    return claims_str


def validate_action_type(action_type: typing.Any) -> _typing.EmailActionType:
    if action_type not in VALID_EMAIL_ACTION_TYPES:
        raise ValueError('Invalid action type provided action_type: {0}. \
            Valid values are {1}'.format(action_type, ', '.join(VALID_EMAIL_ACTION_TYPES)))
    return action_type


def validate_provider_ids(provider_ids: typing.Any, required: bool = False) -> typing.List[str]:
    if not provider_ids:
        if required:
            raise ValueError('Invalid provider IDs. Provider ids should be provided')
        return []
    for provider_id in provider_ids:
        validate_provider_id(provider_id, True)
    return provider_ids


def build_update_mask(params: typing.Dict[str, typing.Any]) -> typing.List[str]:
    """Creates an update mask list from the given dictionary."""
    mask: typing.List[str] = []
    for key, value in params.items():
        if isinstance(value, dict):
            child_mask = build_update_mask(value)  # type: ignore[reportUnknownArgumentType]
            for child in child_mask:
                mask.append('{0}.{1}'.format(key, child))
        else:
            mask.append(key)

    return sorted(mask)


class UidAlreadyExistsError(exceptions.AlreadyExistsError):
    """The user with the provided uid already exists."""

    default_message = 'The user with the provided uid already exists'

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception],
        http_response: typing.Optional[requests.Response]
    ) -> None:
        exceptions.AlreadyExistsError.__init__(self, message, cause, http_response)


class EmailAlreadyExistsError(exceptions.AlreadyExistsError):
    """The user with the provided email already exists."""

    default_message = 'The user with the provided email already exists'

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception],
        http_response: typing.Optional[requests.Response]
    ) -> None:
        exceptions.AlreadyExistsError.__init__(self, message, cause, http_response)


class InsufficientPermissionError(exceptions.PermissionDeniedError):
    """The credential used to initialize the SDK lacks required permissions."""

    default_message = ('The credential used to initialize the SDK has insufficient '
                       'permissions to perform the requested operation. See '
                       'https://firebase.google.com/docs/admin/setup for details '
                       'on how to initialize the Admin SDK with appropriate permissions')

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception],
        http_response: typing.Optional[requests.Response]
    ) -> None:
        exceptions.PermissionDeniedError.__init__(self, message, cause, http_response)


class InvalidDynamicLinkDomainError(exceptions.InvalidArgumentError):
    """Dynamic link domain in ActionCodeSettings is not authorized."""

    default_message = 'Dynamic link domain specified in ActionCodeSettings is not authorized'

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception],
        http_response: typing.Optional[requests.Response]
    ) -> None:
        exceptions.InvalidArgumentError.__init__(self, message, cause, http_response)


class InvalidIdTokenError(exceptions.InvalidArgumentError):
    """The provided ID token is not a valid Firebase ID token."""

    default_message = 'The provided ID token is invalid'

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
        http_response: typing.Optional[requests.Response] = None,
    ) -> None:
        exceptions.InvalidArgumentError.__init__(self, message, cause, http_response)


class PhoneNumberAlreadyExistsError(exceptions.AlreadyExistsError):
    """The user with the provided phone number already exists."""

    default_message = 'The user with the provided phone number already exists'

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception],
        http_response: typing.Optional[requests.Response],
    ) -> None:
        exceptions.AlreadyExistsError.__init__(self, message, cause, http_response)


class UnexpectedResponseError(exceptions.UnknownError):
    """Backend service responded with an unexpected or malformed response."""

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
        http_response: typing.Optional[requests.Response] = None,
    ) -> None:
        exceptions.UnknownError.__init__(self, message, cause, http_response)


class UserNotFoundError(exceptions.NotFoundError):
    """No user record found for the specified identifier."""

    default_message = 'No user record found for the given identifier'

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
        http_response: typing.Optional[requests.Response] = None,
    ) -> None:
        exceptions.NotFoundError.__init__(self, message, cause, http_response)


class EmailNotFoundError(exceptions.NotFoundError):
    """No user record found for the specified email."""

    default_message = 'No user record found for the given email'

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
        http_response: typing.Optional[requests.Response] = None,
    ) -> None:
        exceptions.NotFoundError.__init__(self, message, cause, http_response)


class TenantNotFoundError(exceptions.NotFoundError):
    """No tenant found for the specified identifier."""

    default_message = 'No tenant found for the given identifier'

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
        http_response: typing.Optional[requests.Response] = None,
    ) -> None:
        exceptions.NotFoundError.__init__(self, message, cause, http_response)


class TenantIdMismatchError(exceptions.InvalidArgumentError):
    """Missing or invalid tenant ID field in the given JWT."""

    def __init__(self, message: str) -> None:
        exceptions.InvalidArgumentError.__init__(self, message)


class ConfigurationNotFoundError(exceptions.NotFoundError):
    """No auth provider found for the specified identifier."""

    default_message = 'No auth provider found for the given identifier'

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
        http_response: typing.Optional[requests.Response] = None,
    ) -> None:
        exceptions.NotFoundError.__init__(self, message, cause, http_response)


class UserDisabledError(exceptions.InvalidArgumentError):
    """An operation failed due to a user record being disabled."""

    default_message = 'The user record is disabled'

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
        http_response: typing.Optional[requests.Response] = None,
    ) -> None:
        exceptions.InvalidArgumentError.__init__(self, message, cause, http_response)


class TooManyAttemptsTryLaterError(exceptions.ResourceExhaustedError):
    """Rate limited because of too many attempts."""

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
        http_response: typing.Optional[requests.Response] = None,
    ) -> None:
        exceptions.ResourceExhaustedError.__init__(self, message, cause, http_response)


class ResetPasswordExceedLimitError(exceptions.ResourceExhaustedError):
    """Reset password emails exceeded their limits."""

    def __init__(
        self,
        message: str,
        cause: typing.Optional[Exception] = None,
        http_response: typing.Optional[requests.Response] = None,
    ) -> None:
        exceptions.ResourceExhaustedError.__init__(self, message, cause, http_response)


_CODE_TO_EXC_TYPE: typing.Dict[str, _typing.FirebaseErrorFactory] = {
    'CONFIGURATION_NOT_FOUND': ConfigurationNotFoundError,
    'DUPLICATE_EMAIL': EmailAlreadyExistsError,
    'DUPLICATE_LOCAL_ID': UidAlreadyExistsError,
    'EMAIL_EXISTS': EmailAlreadyExistsError,
    'EMAIL_NOT_FOUND': EmailNotFoundError,
    'INSUFFICIENT_PERMISSION': InsufficientPermissionError,
    'INVALID_DYNAMIC_LINK_DOMAIN': InvalidDynamicLinkDomainError,
    'INVALID_ID_TOKEN': InvalidIdTokenError,
    'PHONE_NUMBER_EXISTS': PhoneNumberAlreadyExistsError,
    'TENANT_NOT_FOUND': TenantNotFoundError,
    'USER_NOT_FOUND': UserNotFoundError,
    'TOO_MANY_ATTEMPTS_TRY_LATER': TooManyAttemptsTryLaterError,
    'RESET_PASSWORD_EXCEED_LIMIT': ResetPasswordExceedLimitError,
}


def handle_auth_backend_error(error: requests.RequestException) -> exceptions.FirebaseError:
    """Converts a requests error received from the Firebase Auth service into a FirebaseError."""
    if error.response is None:
        return _utils.handle_requests_error(error)

    code, custom_message = _parse_error_body(error.response)
    if not code:
        msg = 'Unexpected error response: {0}'.format(error.response.content.decode())
        return _utils.handle_requests_error(error, message=msg)

    exc_type = _CODE_TO_EXC_TYPE.get(code)
    msg = _build_error_message(code, exc_type, custom_message)
    if not exc_type:
        return _utils.handle_requests_error(error, message=msg)

    return exc_type(msg, cause=error, http_response=error.response)


def _parse_error_body(response: requests.Response) -> typing.Tuple[typing.Optional[str], typing.Optional[str]]:
    """Parses the given error response to extract Auth error code and message."""
    parsed_body = None
    try:
        parsed_body = response.json()
    except ValueError:
        pass

    if not isinstance(parsed_body, dict):
        return None, None

    # Auth error response format: {"error": {"message": "AUTH_ERROR_CODE: Optional text"}}
    parsed_body = typing.cast(typing.Dict[str, typing.Any], parsed_body)
    error_dict = parsed_body.get('error', {})
    if not isinstance(error_dict, dict):
        return None, None
    error_dict = typing.cast(typing.Dict[str, str], error_dict)
    code, custom_message = error_dict.get('message'), None
    if code:
        separator = code.find(':')
        if separator != -1:
            custom_message = code[separator + 1:].strip()
            code = code[:separator]

    return code, custom_message


def _build_error_message(
    code: str,
    exc_type: typing.Optional[_typing.FirebaseErrorFactory],
    custom_message: typing.Optional[str]
) -> str:
    default_message: str = getattr(exc_type, 'default_message', 'Error while calling Auth service')
    ext = ' {0}'.format(custom_message) if custom_message else ''
    return '{0} ({1}).{2}'.format(default_message, code, ext)
