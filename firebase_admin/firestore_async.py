# Copyright 2022 Google Inc.
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

"""Cloud Firestore Async module.

This module contains utilities for asynchronusly accessing the Google Cloud Firestore databases
associated with Firebase apps. This requires the ``google-cloud-firestore`` Python module.
"""

from typing import Type

from firebase_admin import (
    App,
    _utils,
)
from firebase_admin.credentials import Base

try:
    from google.cloud import firestore # type: ignore # pylint: disable=import-error,no-name-in-module
    existing = globals().keys()
    for key, value in firestore.__dict__.items():
        if not key.startswith('_') and key not in existing:
            globals()[key] = value
except ImportError:
    raise ImportError('Failed to import the Cloud Firestore library for Python. Make sure '
                      'to install the "google-cloud-firestore" module.')

_FIRESTORE_ASYNC_ATTRIBUTE: str = '_firestore_async'


def client(app: App = None) -> firestore.AsyncClient:
    """Returns an async client that can be used to interact with Google Cloud Firestore.

    Args:
      app: An App instance (optional).

    Returns:
      google.cloud.firestore.Firestore_Async: A `Firestore Async Client`_.

    Raises:
      ValueError: If a project ID is not specified either via options, credentials or
          environment variables, or if the specified project ID is not a valid string.

    .. _Firestore Async Client: https://googleapis.dev/python/firestore/latest/client.html
    """
    fs_client = _utils.get_app_service(
        app, _FIRESTORE_ASYNC_ATTRIBUTE, _FirestoreAsyncClient.from_app)
    return fs_client.get()


class _FirestoreAsyncClient:
    """Holds a Google Cloud Firestore Async Client instance."""

    def __init__(self, credentials: Type[Base], project: str) -> None:
        self._client = firestore.AsyncClient(credentials=credentials, project=project)

    def get(self) -> firestore.AsyncClient:
        return self._client

    @classmethod
    def from_app(cls, app: App) -> "_FirestoreAsyncClient":
        # Replace remove future reference quotes by importing annotations in Python 3.7+ b/238779406
        """Creates a new _FirestoreAsyncClient for the specified app."""
        credentials = app.credential.get_credential()
        project = app.project_id
        if not project:
            raise ValueError(
                'Project ID is required to access Firestore. Either set the projectId option, '
                'or use service account credentials. Alternatively, set the GOOGLE_CLOUD_PROJECT '
                'environment variable.')
        return _FirestoreAsyncClient(credentials, project)
