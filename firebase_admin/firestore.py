# Copyright 2017 Google Inc.
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

"""Cloud Firestore module.

This module contains utilities for accessing the Google Cloud Firestore databases associated with
Firebase apps. This requires the ``google-cloud-firestore`` Python module.
"""

import typing

import firebase_admin
from firebase_admin import _utils

try:
    import google.cloud.firestore
    # firestore defines __all__ for safe import *
    from google.cloud.firestore import *  # pyright: ignore[reportWildcardImportFromLibrary]
    from google.cloud.firestore_v1.base_client import DEFAULT_DATABASE
except ImportError as error:
    raise ImportError('Failed to import the Cloud Firestore library for Python. Make sure '
                      'to install the "google-cloud-firestore" module.') from error

__all__ = ['client']
__all__.extend(google.cloud.firestore.__all__)  # pyright: ignore[reportUnsupportedDunderAll]


_FIRESTORE_ATTRIBUTE = '_firestore'


def client(app: typing.Optional[firebase_admin.App] = None, database_id: typing.Optional[str] = None) -> Client:
    """Returns a client that can be used to interact with Google Cloud Firestore.

    Args:
        app: An App instance (optional).
        database_id: The database ID of the Google Cloud Firestore database to be used.
            Defaults to the default Firestore database ID if not specified or an empty string
            (optional).

    Returns:
        google.cloud.firestore.Firestore: A `Firestore Client`_.

    Raises:
        ValueError: If the specified database ID is not a valid string, or if a project ID is not
            specified either via options, credentials or environment variables, or if the specified
            project ID is not a valid string.

    .. _Firestore Client: https://cloud.google.com/python/docs/reference/firestore/latest/\
        google.cloud.firestore_v1.client.Client
    """
    # Validate database_id
    if database_id is not None and not isinstance(database_id, str):
        raise ValueError(f'database_id "{database_id}" must be a string or None.')
    fs_service = _utils.get_app_service(app, _FIRESTORE_ATTRIBUTE, _FirestoreService)
    return fs_service.get_client(database_id)


class _FirestoreService:
    """Service that maintains a collection of firestore clients."""

    def __init__(self, app: firebase_admin.App) -> None:
        self._app = app
        self._clients: typing.Dict[str, Client] = {}

    def get_client(self, database_id: typing.Optional[str]) -> Client:
        """Creates a client based on the database_id. These clients are cached."""
        database_id = database_id or DEFAULT_DATABASE
        if database_id not in self._clients:
            # Create a new client and cache it in _clients
            credentials = self._app.credential.get_credential()
            project = self._app.project_id
            if not project:
                raise ValueError(
                    'Project ID is required to access Firestore. Either set the projectId option, '
                    'or use service account credentials. Alternatively, set the '
                    'GOOGLE_CLOUD_PROJECT environment variable.')

            fs_client = Client(
                credentials=credentials, project=project, database=database_id)
            self._clients[database_id] = fs_client

        return self._clients[database_id]
