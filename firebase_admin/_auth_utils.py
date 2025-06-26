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
from urllib import parse

from firebase_admin import exceptions
from firebase_admin import _utils


EMULATOR_HOST_ENV_VAR = 'FIREBASE_AUTH_EMULATOR_HOST'
MAX_CLAIMS_PAYLOAD_SIZE = 1000
RESERVED_CLAIMS = set([
    'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash', 'exp', 'iat',
    'iss', 'jti', 'nbf', 'nonce', 'sub', 'firebase',
])
VALID_EMAIL_ACTION_TYPES = set(['VERIFY_EMAIL', 'EMAIL_SIGNIN', 'PASSWORD_RESET'])


class PageIterator:
    """An iterator that allows iterating over a sequence of items, one at a time.

    This implementation loads a page of items into memory, and iterates on them. When the whole
    page has been traversed, it loads another page. This class never keeps more than one page
    of entries in memory.
    """

    def __init__(self, current_page):
        if not current_page:
            raise ValueError('Current page must not be None.')

        self._current_page = current_page
        self._iter = None

    def __next__(self):
        if self._iter is None:
            self._iter = iter(self.items)

        try:
            return next(self._iter)
        except StopIteration:
            if self._current_page.has_next_page:
                self._current_page = self._current_page.get_next_page()
                self._iter = iter(self.items)

                return next(self._iter)

            raise

    def __iter__(self):
        return self

    @property
    def items(self):
        raise NotImplementedError


def get_emulator_host():
    emulator_host = os.getenv(EMULATOR_HOST_ENV_VAR, '')
    if emulator_host and '//' in emulator_host:
        raise ValueError(
            f'Invalid {EMULATOR_HOST_ENV_VAR}: "{emulator_host}". '
            'It must follow format "host:port".')
    return emulator_host


def is_emulated():
    return get_emulator_host() != ''


def validate_uid(uid, required=False):
    if uid is None and not required:
        return None
    if not isinstance(uid, str) or not uid or len(uid) > 128:
        raise ValueError(
            f'Invalid uid: "{uid}". The uid must be a non-empty string with no more than 128 '
            'characters.')
    return uid

def validate_email(email, required=False):
    if email is None and not required:
        return None
    if not isinstance(email, str) or not email:
        raise ValueError(
            f'Invalid email: "{email}". Email must be a non-empty string.')
    parts = email.split('@')
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f'Malformed email address string: "{email}".')
    return email

def validate_phone(phone, required=False):
    """Validates the specified phone number.

    Phone number vlidation is very lax here. Backend will enforce E.164 spec compliance, and
    normalize accordingly. Here we check if the number starts with + sign, and contains at
    least one alphanumeric character.
    """
    if phone is None and not required:
        return None
    if not isinstance(phone, str) or not phone:
        raise ValueError(
            f'Invalid phone number: "{phone}". Phone number must be a non-empty string.')
    if not phone.startswith('+') or not re.search('[a-zA-Z0-9]', phone):
        raise ValueError(
            f'Invalid phone number: "{phone}". Phone number must be a valid, E.164 '
            'compliant identifier.')
    return phone

def validate_password(password, required=False):
    if password is None and not required:
        return None
    if not isinstance(password, str) or len(password) < 6:
        raise ValueError(
            'Invalid password string. Password must be a string at least 6 characters long.')
    return password

def validate_bytes(value, label, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, bytes) or not value:
        raise ValueError(f'{label} must be a non-empty byte sequence.')
    return value

def validate_display_name(display_name, required=False):
    if display_name is None and not required:
        return None
    if not isinstance(display_name, str) or not display_name:
        raise ValueError(
            f'Invalid display name: "{display_name}". Display name must be a non-empty '
            'string.')
    return display_name

def validate_provider_id(provider_id, required=True):
    if provider_id is None and not required:
        return None
    if not isinstance(provider_id, str) or not provider_id:
        raise ValueError(
            f'Invalid provider ID: "{provider_id}". Provider ID must be a non-empty string.')
    return provider_id

def validate_provider_uid(provider_uid, required=True):
    if provider_uid is None and not required:
        return None
    if not isinstance(provider_uid, str) or not provider_uid:
        raise ValueError(
            f'Invalid provider UID: "{provider_uid}". Provider UID must be a non-empty string.')
    return provider_uid

def validate_photo_url(photo_url, required=False):
    """Parses and validates the given URL string."""
    if photo_url is None and not required:
        return None
    if not isinstance(photo_url, str) or not photo_url:
        raise ValueError(
            f'Invalid photo URL: "{photo_url}". Photo URL must be a non-empty string.')
    try:
        parsed = parse.urlparse(photo_url)
        if not parsed.netloc:
            raise ValueError(f'Malformed photo URL: "{photo_url}".')
        return photo_url
    except Exception as err:
        raise ValueError(f'Malformed photo URL: "{photo_url}".') from err

def validate_timestamp(timestamp, label, required=False):
    """Validates the given timestamp value. Timestamps must be positive integers."""
    if timestamp is None and not required:
        return None
    if isinstance(timestamp, bool):
        raise ValueError('Boolean value specified as timestamp.')
    try:
        timestamp_int = int(timestamp)
    except TypeError as err:
        raise ValueError(f'Invalid type for timestamp value: {timestamp}.') from err
    if timestamp_int != timestamp:
        raise ValueError(f'{label} must be a numeric value and a whole number.')
    if timestamp_int <= 0:
        raise ValueError(f'{label} timestamp must be a positive interger.')
    return timestamp_int

def validate_int(value, label, low=None, high=None):
    """Validates that the given value represents an integer.

    There are several ways to represent an integer in Python (e.g. 2, 2L, 2.0). This method allows
    for all such representations except for booleans. Booleans also behave like integers, but
    always translate to 1 and 0. Passing a boolean to an API that expects integers is most likely
    a developer error.
    """
    if value is None or isinstance(value, bool):
        raise ValueError(f'Invalid type for integer value: {value}.')
    try:
        val_int = int(value)
    except TypeError as err:
        raise ValueError(f'Invalid type for integer value: {value}.') from err
    if val_int != value:
        # This will be True for non-numeric values like '2' and non-whole numbers like 2.5.
        raise ValueError(f'{label} must be a numeric value and a whole number.')
    if low is not None and val_int < low:
        raise ValueError(f'{label} must not be smaller than {low}.')
    if high is not None and val_int > high:
        raise ValueError(f'{label} must not be larger than {high}.')
    return val_int

def validate_string(value, label):
    """Validates that the given value is a string."""
    if not isinstance(value, str):
        raise ValueError(f'Invalid type for {label}: {value}.')
    return value

def validate_boolean(value, label):
    """Validates that the given value is a boolean."""
    if not isinstance(value, bool):
        raise ValueError(f'Invalid type for {label}: {value}.')
    return value

def validate_custom_claims(custom_claims, required=False):
    """Validates the specified custom claims.

    Custom claims must be specified as a JSON string. The string must not exceed 1000
    characters, and the parsed JSON payload must not contain reserved JWT claims.
    """
    if custom_claims is None and not required:
        return None
    claims_str = str(custom_claims)
    if len(claims_str) > MAX_CLAIMS_PAYLOAD_SIZE:
        raise ValueError(
            f'Custom claims payload must not exceed {MAX_CLAIMS_PAYLOAD_SIZE} characters.')
    try:
        parsed = json.loads(claims_str)
    except Exception as err:
        raise ValueError('Failed to parse custom claims string as JSON.') from err

    if not isinstance(parsed, dict):
        raise ValueError('Custom claims must be parseable as a JSON object.')
    invalid_claims = RESERVED_CLAIMS.intersection(set(parsed.keys()))
    if len(invalid_claims) > 1:
        joined = ', '.join(sorted(invalid_claims))
        raise ValueError(f'Claims "{joined}" are reserved, and must not be set.')
    if len(invalid_claims) == 1:
        raise ValueError(
            f'Claim "{invalid_claims.pop()}" is reserved, and must not be set.')
    return claims_str

def validate_action_type(action_type):
    if action_type not in VALID_EMAIL_ACTION_TYPES:
        raise ValueError(
            f'Invalid action type provided action_type: {action_type}. Valid values are '
            f'{", ".join(VALID_EMAIL_ACTION_TYPES)}')
    return action_type

def validate_provider_ids(provider_ids, required=False):
    if not provider_ids:
        if required:
            raise ValueError('Invalid provider IDs. Provider ids should be provided')
        return []
    for provider_id in provider_ids:
        validate_provider_id(provider_id, True)
    return provider_ids

def build_update_mask(params):
    """Creates an update mask list from the given dictionary."""
    mask = []
    for key, value in params.items():
        if isinstance(value, dict):
            child_mask = build_update_mask(value)
            for child in child_mask:
                mask.append(f'{key}.{child}')
        else:
            mask.append(key)

    return sorted(mask)


class UidAlreadyExistsError(exceptions.AlreadyExistsError):
    """The user with the provided uid already exists."""

    default_message = 'The user with the provided uid already exists'

    def __init__(self, message, cause, http_response):
        exceptions.AlreadyExistsError.__init__(self, message, cause, http_response)


class EmailAlreadyExistsError(exceptions.AlreadyExistsError):
    """The user with the provided email already exists."""

    default_message = 'The user with the provided email already exists'

    def __init__(self, message, cause, http_response):
        exceptions.AlreadyExistsError.__init__(self, message, cause, http_response)


class InsufficientPermissionError(exceptions.PermissionDeniedError):
    """The credential used to initialize the SDK lacks required permissions."""

    default_message = ('The credential used to initialize the SDK has insufficient '
                       'permissions to perform the requested operation. See '
                       'https://firebase.google.com/docs/admin/setup for details '
                       'on how to initialize the Admin SDK with appropriate permissions')

    def __init__(self, message, cause, http_response):
        exceptions.PermissionDeniedError.__init__(self, message, cause, http_response)


class InvalidDynamicLinkDomainError(exceptions.InvalidArgumentError):
    """Dynamic link domain in ActionCodeSettings is not authorized."""

    default_message = 'Dynamic link domain specified in ActionCodeSettings is not authorized'

    def __init__(self, message, cause, http_response):
        exceptions.InvalidArgumentError.__init__(self, message, cause, http_response)


class InvalidIdTokenError(exceptions.InvalidArgumentError):
    """The provided ID token is not a valid Firebase ID token."""

    default_message = 'The provided ID token is invalid'

    def __init__(self, message, cause=None, http_response=None):
        exceptions.InvalidArgumentError.__init__(self, message, cause, http_response)


class PhoneNumberAlreadyExistsError(exceptions.AlreadyExistsError):
    """The user with the provided phone number already exists."""

    default_message = 'The user with the provided phone number already exists'

    def __init__(self, message, cause, http_response):
        exceptions.AlreadyExistsError.__init__(self, message, cause, http_response)


class UnexpectedResponseError(exceptions.UnknownError):
    """Backend service responded with an unexpected or malformed response."""

    def __init__(self, message, cause=None, http_response=None):
        exceptions.UnknownError.__init__(self, message, cause, http_response)


class UserNotFoundError(exceptions.NotFoundError):
    """No user record found for the specified identifier."""

    default_message = 'No user record found for the given identifier'

    def __init__(self, message, cause=None, http_response=None):
        exceptions.NotFoundError.__init__(self, message, cause, http_response)


class EmailNotFoundError(exceptions.NotFoundError):
    """No user record found for the specified email."""

    default_message = 'No user record found for the given email'

    def __init__(self, message, cause=None, http_response=None):
        exceptions.NotFoundError.__init__(self, message, cause, http_response)


class TenantNotFoundError(exceptions.NotFoundError):
    """No tenant found for the specified identifier."""

    default_message = 'No tenant found for the given identifier'

    def __init__(self, message, cause=None, http_response=None):
        exceptions.NotFoundError.__init__(self, message, cause, http_response)


class TenantIdMismatchError(exceptions.InvalidArgumentError):
    """Missing or invalid tenant ID field in the given JWT."""

    def __init__(self, message):
        exceptions.InvalidArgumentError.__init__(self, message)


class ConfigurationNotFoundError(exceptions.NotFoundError):
    """No auth provider found for the specified identifier."""

    default_message = 'No auth provider found for the given identifier'

    def __init__(self, message, cause=None, http_response=None):
        exceptions.NotFoundError.__init__(self, message, cause, http_response)


class UserDisabledError(exceptions.InvalidArgumentError):
    """An operation failed due to a user record being disabled."""

    default_message = 'The user record is disabled'

    def __init__(self, message, cause=None, http_response=None):
        exceptions.InvalidArgumentError.__init__(self, message, cause, http_response)


class TooManyAttemptsTryLaterError(exceptions.ResourceExhaustedError):
    """Rate limited because of too many attempts."""

    def __init__(self, message, cause=None, http_response=None):
        exceptions.ResourceExhaustedError.__init__(self, message, cause, http_response)


class ResetPasswordExceedLimitError(exceptions.ResourceExhaustedError):
    """Reset password emails exceeded their limits."""

    def __init__(self, message, cause=None, http_response=None):
        exceptions.ResourceExhaustedError.__init__(self, message, cause, http_response)


_CODE_TO_EXC_TYPE = {
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


def handle_auth_backend_error(error):
    """Converts a requests error received from the Firebase Auth service into a FirebaseError."""
    if error.response is None:
        return _utils.handle_requests_error(error)

    code, custom_message = _parse_error_body(error.response)
    if not code:
        msg = f'Unexpected error response: {error.response.content.decode()}'
        return _utils.handle_requests_error(error, message=msg)

    exc_type = _CODE_TO_EXC_TYPE.get(code)
    msg = _build_error_message(code, exc_type, custom_message)
    if not exc_type:
        return _utils.handle_requests_error(error, message=msg)

    return exc_type(msg, cause=error, http_response=error.response)


def _parse_error_body(response):
    """Parses the given error response to extract Auth error code and message."""
    error_dict = {}
    try:
        parsed_body = response.json()
        if isinstance(parsed_body, dict):
            error_dict = parsed_body.get('error', {})
    except ValueError:
        pass

    # Auth error response format: {"error": {"message": "AUTH_ERROR_CODE: Optional text"}}
    code = error_dict.get('message') if isinstance(error_dict, dict) else None
    custom_message = None
    if code:
        separator = code.find(':')
        if separator != -1:
            custom_message = code[separator + 1:].strip()
            code = code[:separator]

    return code, custom_message


def _build_error_message(code, exc_type, custom_message):
    default_message = exc_type.default_message if (
        exc_type and hasattr(exc_type, 'default_message')) else 'Error while calling Auth service'
    ext = f' {custom_message}' if custom_message else ''
    return f'{default_message} ({code}).{ext}'
