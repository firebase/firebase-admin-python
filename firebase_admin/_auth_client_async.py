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

"""Firebase auth client async sub module."""

import asyncio
import firebase_admin
from firebase_admin import _auth_utils
from firebase_admin import _http_client
from firebase_admin import _user_mgt_async
from firebase_admin import _utils


class Client:
    """Firebase Authentication client scoped to a specific tenant."""

    async def __aexit__(self, exc_type, exc, tb):
        print("clean up -------------")
        await self.http_client.close()
        self.http_client = None

    async def __aenter__(self):
        print('__aenter__')
        if self.http_client is None:
            print('http_client is None')
            self.http_client = _http_client.HttpClientAsync(
            credential=self.credential, headers={'X-Client-Version': self.version_header}, timeout=self.timeout)
        print(self.http_client)
        return self

    def close(self):
        print("Closing async auth session ----------")
        #asyncio.run(self.http_client.close()) ## python 3.7
        asyncio.get_event_loop().run_until_complete(self.http_client.close())
        self.http_client = None

    def __init__(self, app, tenant_id=None):
        if not app.project_id:
            raise ValueError("""A project ID is required to access the auth service.
            1. Use a service account credential, or
            2. set the project ID explicitly via Firebase App options, or
            3. set the project ID via the GOOGLE_CLOUD_PROJECT environment variable.""")

        credential = None
        version_header = 'Python/Admin/{0}'.format(firebase_admin.__version__)
        timeout = app.options.get('httpTimeout', _http_client.DEFAULT_TIMEOUT_SECONDS)
        # Non-default endpoint URLs for emulator support are set in this dict later.
        endpoint_urls = {}
        self.emulated = False

        # If an emulator is present, check that the given value matches the expected format and set
        # endpoint URLs to use the emulator. Additionally, use a fake credential.
        emulator_host = _auth_utils.get_emulator_host()
        if emulator_host:
            base_url = 'http://{0}/identitytoolkit.googleapis.com'.format(emulator_host)
            endpoint_urls['v1'] = base_url + '/v1'
            endpoint_urls['v2beta1'] = base_url + '/v2beta1'
            credential = _utils.EmulatorAdminCredentialsAsync()
            self.emulated = True
        else:
            # Use credentials if provided
            credential = app.credential.get_credential_async()

        self.http_client = _http_client.HttpClientAsync(
            credential=credential, headers={'X-Client-Version': version_header}, timeout=timeout)

        self.credential = credential
        self.version_header = version_header
        self.timeout = timeout

        self._tenant_id = tenant_id
        self._user_manager = _user_mgt_async.UserManager(
            self.http_client, app.project_id, tenant_id, url_override=endpoint_urls.get('v1'))

    @property
    def tenant_id(self):
        """Tenant ID associated with this client."""
        return self._tenant_id

    async def get_user(self, uid):
        """Gets the user data corresponding to the specified user ID.

        Args:
            uid: A user ID string.

        Returns:
            UserRecord: A user record instance.

        Raises:
            ValueError: If the user ID is None, empty or malformed.
            UserNotFoundError: If the specified user ID does not exist.
            FirebaseError: If an error occurs while retrieving the user.
        """
        response = await self._user_manager.get_user(uid=uid)
        return _user_mgt_async.UserRecord(response)

    async def create_user(self, **kwargs): # pylint: disable=differing-param-doc
        """Creates a new user account with the specified properties.

        Args:
            kwargs: A series of keyword arguments (optional).

        Keyword Args:
            uid: User ID to assign to the newly created user (optional).
            display_name: The user's display name (optional).
            email: The user's primary email (optional).
            email_verified: A boolean indicating whether or not the user's primary email is
                verified (optional).
            phone_number: The user's primary phone number (optional).
            photo_url: The user's photo URL (optional).
            password: The user's raw, unhashed password. (optional).
            disabled: A boolean indicating whether or not the user account is disabled (optional).

        Returns:
            UserRecord: A UserRecord instance for the newly created user.

        Raises:
            ValueError: If the specified user properties are invalid.
            FirebaseError: If an error occurs while creating the user account.
        """
        uid = await self._user_manager.create_user(**kwargs)
        return await self.get_user(uid=uid)
