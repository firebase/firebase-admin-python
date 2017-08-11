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
    from google.cloud import storage
except ImportError:
    raise ImportError('Failed to import the Cloud Storage library for Python. Make sure '
                      'to install the "google-cloud-storage" module.')

import six

from firebase_admin import utils


_STORAGE_ATTRIBUTE = '_storage'

def bucket(name=None, app=None):
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
    client = utils.get_app_service(app, _STORAGE_ATTRIBUTE, _StorageClient.from_app)
    return client.bucket(name)


class _StorageClient(object):
    """Holds a Google Cloud Storage client instance."""

    def __init__(self, credentials, project, default_bucket):
        self._client = storage.Client(credentials=credentials, project=project)
        self._default_bucket = default_bucket

    @classmethod
    def from_app(cls, app):
        credentials = app.credential.get_credential()
        # Specifying project ID is not required, but providing it when available
        # significantly speeds up the initialization of the storage client.
        try:
            project = app.credential.project_id
        except AttributeError:
            project = None
        default_bucket = app.options.get('storageBucket')
        return _StorageClient(credentials, project, default_bucket)

    def bucket(self, name=None):
        """Returns a handle to the specified Cloud Storage Bucket."""
        bucket_name = name if name is not None else self._default_bucket
        if bucket_name is None:
            raise ValueError(
                'Storage bucket name not specified. Specify the bucket name via the '
                '"storageBucket" option when initializing the App, or specify the bucket '
                'name explicitly when calling the storage.bucket() function.')
        elif not bucket_name or not isinstance(bucket_name, six.string_types):
            raise ValueError(
                'Invalid storage bucket name: "{0}". Bucket name must be a non-empty '
                'string.'.format(bucket_name))
        return self._client.bucket(bucket_name)
