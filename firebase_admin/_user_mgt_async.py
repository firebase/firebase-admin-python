# Copyright 2021 Google Inc.
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

"""Firebase user management async sub module."""

import base64
import json

import requests

from firebase_admin import _auth_utils
from firebase_admin import _rfc3339


MAX_LIST_USERS_RESULTS = 1000
MAX_IMPORT_USERS_SIZE = 1000
B64_REDACTED = base64.b64encode(b'REDACTED')


class Sentinel:

    def __init__(self, description):
        self.description = description


DELETE_ATTRIBUTE = Sentinel('Value used to delete an attribute from a user profile')


class UserMetadata:
    """Contains additional metadata associated with a user account."""

    def __init__(self, creation_timestamp=None, last_sign_in_timestamp=None,
                 last_refresh_timestamp=None):
        self._creation_timestamp = _auth_utils.validate_timestamp(
            creation_timestamp, 'creation_timestamp')
        self._last_sign_in_timestamp = _auth_utils.validate_timestamp(
            last_sign_in_timestamp, 'last_sign_in_timestamp')
        self._last_refresh_timestamp = _auth_utils.validate_timestamp(
            last_refresh_timestamp, 'last_refresh_timestamp')

    @property
    def creation_timestamp(self):
        """ Creation timestamp in milliseconds since the epoch.

        Returns:
          integer: The user creation timestamp in milliseconds since the epoch.
        """
        return self._creation_timestamp

    @property
    def last_sign_in_timestamp(self):
        """ Last sign in timestamp in milliseconds since the epoch.

        Returns:
          integer: The last sign in timestamp in milliseconds since the epoch.
        """
        return self._last_sign_in_timestamp

    @property
    def last_refresh_timestamp(self):
        """The time at which the user was last active (ID token refreshed).

        Returns:
          integer: Milliseconds since epoch timestamp, or `None` if the user was
          never active.
        """
        return self._last_refresh_timestamp


class UserInfo:
    """A collection of standard profile information for a user.

    Used to expose profile information returned by an identity provider.
    """

    @property
    def uid(self):
        """Returns the user ID of this user."""
        raise NotImplementedError

    @property
    def display_name(self):
        """Returns the display name of this user."""
        raise NotImplementedError

    @property
    def email(self):
        """Returns the email address associated with this user."""
        raise NotImplementedError

    @property
    def phone_number(self):
        """Returns the phone number associated with this user."""
        raise NotImplementedError

    @property
    def photo_url(self):
        """Returns the photo URL of this user."""
        raise NotImplementedError

    @property
    def provider_id(self):
        """Returns the ID of the identity provider.

        This can be a short domain name (e.g. google.com), or the identity of an OpenID
        identity provider.
        """
        raise NotImplementedError


class UserRecord(UserInfo):
    """Contains metadata associated with a Firebase user account."""

    def __init__(self, data):
        super(UserRecord, self).__init__()
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument: {0}. Must be a dictionary.'.format(data))
        if not data.get('localId'):
            raise ValueError('User ID must not be None or empty.')
        self._data = data

    @property
    def uid(self):
        """Returns the user ID of this user.

        Returns:
          string: A user ID string. This value is never None or empty.
        """
        return self._data.get('localId')

    @property
    def display_name(self):
        """Returns the display name of this user.

        Returns:
          string: A display name string or None.
        """
        return self._data.get('displayName')

    @property
    def email(self):
        """Returns the email address associated with this user.

        Returns:
          string: An email address string or None.
        """
        return self._data.get('email')

    @property
    def phone_number(self):
        """Returns the phone number associated with this user.

        Returns:
          string: A phone number string or None.
        """
        return self._data.get('phoneNumber')

    @property
    def photo_url(self):
        """Returns the photo URL of this user.

        Returns:
          string: A URL string or None.
        """
        return self._data.get('photoUrl')

    @property
    def provider_id(self):
        """Returns the provider ID of this user.

        Returns:
          string: A constant provider ID value.
        """
        return 'firebase'

    @property
    def email_verified(self):
        """Returns whether the email address of this user has been verified.

        Returns:
          bool: True if the email has been verified, and False otherwise.
        """
        return bool(self._data.get('emailVerified'))

    @property
    def disabled(self):
        """Returns whether this user account is disabled.

        Returns:
          bool: True if the user account is disabled, and False otherwise.
        """
        return bool(self._data.get('disabled'))

    @property
    def tokens_valid_after_timestamp(self):
        """Returns the time, in milliseconds since the epoch, before which tokens are invalid.

        Note: this is truncated to 1 second accuracy.

        Returns:
            int: Timestamp in milliseconds since the epoch, truncated to the second.
            All tokens issued before that time are considered revoked.
        """
        valid_since = self._data.get('validSince')
        if valid_since is not None:
            return 1000 * int(valid_since)
        return 0

    @property
    def user_metadata(self):
        """Returns additional metadata associated with this user.

        Returns:
          UserMetadata: A UserMetadata instance. Does not return None.
        """
        def _int_or_none(key):
            if key in self._data:
                return int(self._data[key])
            return None
        last_refresh_at_millis = None
        last_refresh_at_rfc3339 = self._data.get('lastRefreshAt', None)
        if last_refresh_at_rfc3339:
            last_refresh_at_millis = int(_rfc3339.parse_to_epoch(last_refresh_at_rfc3339) * 1000)
        return UserMetadata(
            _int_or_none('createdAt'), _int_or_none('lastLoginAt'), last_refresh_at_millis)

    @property
    def provider_data(self):
        """Returns a list of UserInfo instances.

        Each object represents an identity from an identity provider that is linked to this user.

        Returns:
          list: A list of UserInfo objects, which may be empty.
        """
        providers = self._data.get('providerUserInfo', [])
        return [ProviderUserInfo(entry) for entry in providers]

    @property
    def custom_claims(self):
        """Returns any custom claims set on this user account.

        Returns:
          dict: A dictionary of claims or None.
        """
        claims = self._data.get('customAttributes')
        if claims:
            parsed = json.loads(claims)
            if parsed != {}:
                return parsed
        return None

    @property
    def tenant_id(self):
        """Returns the tenant ID of this user.

        Returns:
          string: A tenant ID string or None.
        """
        return self._data.get('tenantId')


class ProviderUserInfo(UserInfo):
    """Contains metadata regarding how a user is known by a particular identity provider."""

    def __init__(self, data):
        super(ProviderUserInfo, self).__init__()
        if not isinstance(data, dict):
            raise ValueError('Invalid data argument: {0}. Must be a dictionary.'.format(data))
        if not data.get('rawId'):
            raise ValueError('User ID must not be None or empty.')
        self._data = data

    @property
    def uid(self):
        return self._data.get('rawId')

    @property
    def display_name(self):
        return self._data.get('displayName')

    @property
    def email(self):
        return self._data.get('email')

    @property
    def phone_number(self):
        return self._data.get('phoneNumber')

    @property
    def photo_url(self):
        return self._data.get('photoUrl')

    @property
    def provider_id(self):
        return self._data.get('providerId')


class UserManager:
    """Provides methods for interacting with the Google Identity Toolkit."""

    ID_TOOLKIT_URL = 'https://identitytoolkit.googleapis.com/v1'

    def __init__(self, http_client, project_id, tenant_id=None, url_override=None):
        self.http_client = http_client
        url_prefix = url_override or self.ID_TOOLKIT_URL
        self.base_url = '{0}/projects/{1}'.format(url_prefix, project_id)
        if tenant_id:
            self.base_url += '/tenants/{0}'.format(tenant_id)

    async def get_user(self, **kwargs):
        """Gets the user data corresponding to the provided key."""
        if 'uid' in kwargs:
            key, key_type = kwargs.pop('uid'), 'user ID'
            payload = {'localId' : [_auth_utils.validate_uid(key, required=True)]}
        elif 'email' in kwargs:
            key, key_type = kwargs.pop('email'), 'email'
            payload = {'email' : [_auth_utils.validate_email(key, required=True)]}
        elif 'phone_number' in kwargs:
            key, key_type = kwargs.pop('phone_number'), 'phone number'
            payload = {'phoneNumber' : [_auth_utils.validate_phone(key, required=True)]}
        else:
            raise TypeError('Unsupported keyword arguments: {0}.'.format(kwargs))

        body, http_resp = await self._make_request('post', '/accounts:lookup', json=payload)
        if not body or not body.get('users'):
            raise _auth_utils.UserNotFoundError(
                'No user record found for the provided {0}: {1}.'.format(key_type, key),
                http_response=http_resp)
        return body['users'][0]

    async def create_user(self, uid=None, display_name=None, email=None, phone_number=None,
                          photo_url=None, password=None, disabled=None, email_verified=None):
        """Creates a new user account with the specified properties."""
        payload = {
            'localId': _auth_utils.validate_uid(uid),
            'displayName': _auth_utils.validate_display_name(display_name),
            'email': _auth_utils.validate_email(email),
            'phoneNumber': _auth_utils.validate_phone(phone_number),
            'photoUrl': _auth_utils.validate_photo_url(photo_url),
            'password': _auth_utils.validate_password(password),
            'emailVerified': bool(email_verified) if email_verified is not None else None,
            'disabled': bool(disabled) if disabled is not None else None,
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        body, http_resp = await self._make_request('post', '/accounts', json=payload)
        if not body or not body.get('localId'):
            raise _auth_utils.UnexpectedResponseError(
                'Failed to create new user.', http_response=http_resp)
        return body.get('localId')

    async def _make_request(self, method, path, **kwargs):
        url = '{0}{1}'.format(self.base_url, path)
        try:
            return await self.http_client.body_and_response(method, url, **kwargs)
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
