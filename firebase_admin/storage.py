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
Firebase apps. This requires the ``google-cloud-storage`` Python module.
"""

# pylint: disable=import-error,no-name-in-module
try:
    from google.cloud import storage
except ImportError:
    raise ImportError('Failed to import the Cloud Storage library for Python. Make sure '
                      'to install the "google-cloud-storage" module.')
import os
import urllib
from firebase_admin import _utils, _http_client
from firebase_admin.__about__ import __version__

_STORAGE_ATTRIBUTE = '_storage'

def bucket(name=None, app=None) -> storage.Bucket:
    """Returns a handle to a Google Cloud Storage bucket.

    If the name argument is not provided, uses the 'storageBucket' option specified when
    initializing the App. If that is also not available raises an error. This function
    does not make any RPC calls.

    Args:
      name: Name of a cloud storage bucket (optional).
      app: An App instance (optional).

    Returns:
      google.cloud.storage.Bucket: A handle to the specified bucket.

    Raises:
      ValueError: If a bucket name is not specified either via options or method arguments,
          or if the specified bucket name is not a valid string.
    """
    client = _utils.get_app_service(app, _STORAGE_ATTRIBUTE, _StorageClient.from_app)
    return client.bucket(name)

def get_download_url(blob, app=None) -> str:
    """Gets the download URL for the given Google Cloud Storage Blob reference.

    Args:
      blob: reference to a Google Cloud Storage Blob.
      app: An App instance (optional).

    Returns:
      str: the download URL of the Blob.

    Raises:
      ValueError: If there are no downloadTokens available for the given Blob
    """
    client = _utils.get_app_service(app, _STORAGE_ATTRIBUTE, _StorageClient.from_app)
    return client.get_download_url(blob)

class _StorageClient:
    """Holds a Google Cloud Storage client instance."""

    def __init__(self, app):
        self._app = app
        self._default_bucket = app.options.get('storageBucket')
        self._client = storage.Client(
            credentials=app.credential.get_credential(), project=app.project_id)

    @classmethod
    def from_app(cls, app):
        # Specifying project ID is not required, but providing it when available
        # significantly speeds up the initialization of the storage client.
        return _StorageClient(app)

    def bucket(self, name=None):
        """Returns a handle to the specified Cloud Storage Bucket."""
        bucket_name = name if name is not None else self._default_bucket
        if bucket_name is None:
            raise ValueError(
                'Storage bucket name not specified. Specify the bucket name via the '
                '"storageBucket" option when initializing the App, or specify the bucket '
                'name explicitly when calling the storage.bucket() function.')
        if not bucket_name or not isinstance(bucket_name, str):
            raise ValueError(
                'Invalid storage bucket name: "{0}". Bucket name must be a non-empty '
                'string.'.format(bucket_name))
        return self._client.bucket(bucket_name)

    def get_download_url(self, blob):
        """Gets the download URL for the given Blob"""
        endpoint = os.getenv("STORAGE_EMULATOR_HOST")
        credential = _utils.EmulatorAdminCredentials()
        if endpoint is None:
            endpoint = 'https://firebasestorage.googleapis.com'
            credential = self._app.credential.get_credential()

        endpoint = endpoint + '/v0'

        version_header = 'Python/Admin/{0}'.format(__version__)
        timeout = self._app.options.get('httpTimeout', _http_client.DEFAULT_TIMEOUT_SECONDS)
        encoded_blob_name = urllib.parse.quote(blob.name, safe='')

        http_client = _http_client.JsonHttpClient(
            credential=credential, headers={'X-Client-Version': version_header}, timeout=timeout)

        metadata_endpoint = '{0}/b/{1}/o/{2}'.format(endpoint, blob.bucket.name, encoded_blob_name)
        body, resp = http_client.body_and_response('GET', metadata_endpoint)
        if resp.status_code != 200:
            raise ValueError('No download token available. '
                             'Please create one in the Firebase Console.')

        if 'downloadTokens' not in body:
            raise ValueError('No download token available. '
                             'Please create one in the Firebase Console.')

        tokens = body['downloadTokens'].split(',')
        if not tokens:
            raise ValueError('No download token available. '
                             'Please create one in the Firebase Console.')

        return '{0}?alt=media&token={1}'.format(metadata_endpoint, tokens[0])
