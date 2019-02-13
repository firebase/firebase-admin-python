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
import re

import six
from six.moves import urllib


MAX_CLAIMS_PAYLOAD_SIZE = 1000
RESERVED_CLAIMS = set([
    'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash', 'exp', 'iat',
    'iss', 'jti', 'nbf', 'nonce', 'sub', 'firebase',
])
VALID_EMAIL_ACTION_TYPES = set(['VERIFY_EMAIL', 'EMAIL_SIGNIN', 'PASSWORD_RESET'])


def validate_uid(uid, required=False):
    if uid is None and not required:
        return None
    if not isinstance(uid, six.string_types) or not uid or len(uid) > 128:
        raise ValueError(
            'Invalid uid: "{0}". The uid must be a non-empty string with no more than 128 '
            'characters.'.format(uid))
    return uid

def validate_email(email, required=False):
    if email is None and not required:
        return None
    if not isinstance(email, six.string_types) or not email:
        raise ValueError(
            'Invalid email: "{0}". Email must be a non-empty string.'.format(email))
    parts = email.split('@')
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError('Malformed email address string: "{0}".'.format(email))
    return email

def validate_phone(phone, required=False):
    """Validates the specified phone number.

    Phone number vlidation is very lax here. Backend will enforce E.164 spec compliance, and
    normalize accordingly. Here we check if the number starts with + sign, and contains at
    least one alphanumeric character.
    """
    if phone is None and not required:
        return None
    if not isinstance(phone, six.string_types) or not phone:
        raise ValueError('Invalid phone number: "{0}". Phone number must be a non-empty '
                         'string.'.format(phone))
    if not phone.startswith('+') or not re.search('[a-zA-Z0-9]', phone):
        raise ValueError('Invalid phone number: "{0}". Phone number must be a valid, E.164 '
                         'compliant identifier.'.format(phone))
    return phone

def validate_password(password, required=False):
    if password is None and not required:
        return None
    if not isinstance(password, six.string_types) or len(password) < 6:
        raise ValueError(
            'Invalid password string. Password must be a string at least 6 characters long.')
    return password

def validate_bytes(value, label, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, six.binary_type) or not value:
        raise ValueError('{0} must be a non-empty byte sequence.'.format(label))
    return value

def validate_display_name(display_name, required=False):
    if display_name is None and not required:
        return None
    if not isinstance(display_name, six.string_types) or not display_name:
        raise ValueError(
            'Invalid display name: "{0}". Display name must be a non-empty '
            'string.'.format(display_name))
    return display_name

def validate_provider_id(provider_id, required=True):
    if provider_id is None and not required:
        return None
    if not isinstance(provider_id, six.string_types) or not provider_id:
        raise ValueError(
            'Invalid provider ID: "{0}". Provider ID must be a non-empty '
            'string.'.format(provider_id))
    return provider_id

def validate_photo_url(photo_url, required=False):
    if photo_url is None and not required:
        return None
    if not isinstance(photo_url, six.string_types) or not photo_url:
        raise ValueError(
            'Invalid photo URL: "{0}". Photo URL must be a non-empty '
            'string.'.format(photo_url))
    try:
        parsed = urllib.parse.urlparse(photo_url)
        if not parsed.netloc:
            raise ValueError('Malformed photo URL: "{0}".'.format(photo_url))
        return photo_url
    except Exception:
        raise ValueError('Malformed photo URL: "{0}".'.format(photo_url))

def validate_timestamp(timestamp, label, required=False):
    if timestamp is None and not required:
        return None
    if isinstance(timestamp, bool):
        raise ValueError('Boolean value specified as timestamp.')
    try:
        timestamp_int = int(timestamp)
    except TypeError:
        raise ValueError('Invalid type for timestamp value: {0}.'.format(timestamp))
    else:
        if timestamp_int != timestamp:
            raise ValueError('{0} must be a numeric value and a whole number.'.format(label))
        if timestamp_int <= 0:
            raise ValueError('{0} timestamp must be a positive interger.'.format(label))
        return timestamp_int

def validate_int(value, label, low=None, high=None):
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
            'Custom claims payload must not exceed {0} characters.'.format(
                MAX_CLAIMS_PAYLOAD_SIZE))
    try:
        parsed = json.loads(claims_str)
    except Exception:
        raise ValueError('Failed to parse custom claims string as JSON.')

    if not isinstance(parsed, dict):
        raise ValueError('Custom claims must be parseable as a JSON object.')
    invalid_claims = RESERVED_CLAIMS.intersection(set(parsed.keys()))
    if len(invalid_claims) > 1:
        joined = ', '.join(sorted(invalid_claims))
        raise ValueError('Claims "{0}" are reserved, and must not be set.'.format(joined))
    elif len(invalid_claims) == 1:
        raise ValueError(
            'Claim "{0}" is reserved, and must not be set.'.format(invalid_claims.pop()))
    return claims_str

def validate_action_type(action_type):
    if action_type not in VALID_EMAIL_ACTION_TYPES:
        raise ValueError('Invalid action type provided action_type: {0}. \
            Valid values are {1}'.format(action_type, ', '.join(VALID_EMAIL_ACTION_TYPES)))
    return action_type
