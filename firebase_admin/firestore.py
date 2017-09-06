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

"""Firebase Cloud Storage module.

This module contains utilities for accessing Google Cloud Storage buckets associated with
Firebase apps. This requires installing the google-cloud-storage Python module separately.
"""

# pylint: disable=import-error,no-name-in-module
try:
    from google.cloud import firestore
except ImportError:
    raise ImportError('Failed to import the Cloud Storage library for Python. Make sure '
                      'to install the "google-cloud-storage" module.')

from firebase_admin import utils


_FIRESTORE_ATTRIBUTE = '_firestore'


def client(app=None):
    fs_client = utils.get_app_service(app, _FIRESTORE_ATTRIBUTE, _FirestoreClient.from_app)
    return fs_client.get()


class _FirestoreClient(object):
    """Holds a Google Cloud Firestore client instance."""

    def __init__(self, credentials, project):
        self._client = firestore.Client(credentials=credentials, project=project)

    def get(self):
        return self._client

    @classmethod
    def from_app(cls, app):
        credentials = app.credential.get_credential()
        # TODO: Refactor when https://github.com/firebase/firebase-admin-python/pull/69 is done.
        try:
            project = app.credential.project_id
        except AttributeError:
            raise ValueError('Project ID not available.')
        return _FirestoreClient(credentials, project)
