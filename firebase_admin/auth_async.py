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

"""Firebase Authentication Async module.

This module contains async functions for minting and verifying JWTs used for
authenticating against Firebase services. It also provides functions for
creating and managing user accounts in Firebase projects.
"""

from firebase_admin import _auth_client_async
from firebase_admin import _auth_utils
from firebase_admin import _user_mgt
from firebase_admin import _utils


_AUTH_ATTRIBUTE = '_auth'


__all__ = [
    'Client',
    'UserNotFoundError',
    'UserRecord',

    'create_user',
    'get_user',
]

Client = _auth_client_async.Client
UserNotFoundError = _auth_utils.UserNotFoundError
UserRecord = _user_mgt.UserRecord


def _get_client(app):
    """Returns a client instance for an App.

    If the App already has a client associated with it, simply returns
    it. Otherwise creates a new client, and adds it to the App before
    returning it.

    Args:
        app: A Firebase App instance (or ``None`` to use the default App).

    Returns:
        Client: A client for the specified App instance.

    Raises:
        ValueError: If the app argument is invalid.
    """
    return _utils.get_app_service(app, _AUTH_ATTRIBUTE, Client)


async def get_user(uid, app=None):
    """Gets the user data corresponding to the specified user ID.

    Args:
        uid: A user ID string.
        app: An App instance (optional).

    Returns:
        UserRecord: A user record instance.

    Raises:
        ValueError: If the user ID is None, empty or malformed.
        UserNotFoundError: If the specified user ID does not exist.
        FirebaseError: If an error occurs while retrieving the user.
    """
    client = _get_client(app)
    return await client.get_user(uid=uid)


async def create_user(**kwargs): # pylint: disable=differing-param-doc
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
        app: An App instance (optional).

    Returns:
        UserRecord: A user record instance for the newly created user.

    Raises:
        ValueError: If the specified user properties are invalid.
        FirebaseError: If an error occurs while creating the user account.
    """
    app = kwargs.pop('app', None)
    client = _get_client(app)
    return await client.create_user(**kwargs)
