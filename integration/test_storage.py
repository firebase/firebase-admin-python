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

"""Integration tests for firebase_admin.storage module."""
import time

from firebase_admin import storage


def test_default_bucket(project_id):
    bucket = storage.bucket()
    _verify_bucket(bucket, '{0}.appspot.com'.format(project_id))

def test_custom_bucket(project_id):
    bucket_name = '{0}.appspot.com'.format(project_id)
    bucket = storage.bucket(bucket_name)
    _verify_bucket(bucket, bucket_name)

def test_non_existing_bucket():
    bucket = storage.bucket('non.existing')
    assert bucket.exists() is False

def _verify_bucket(bucket, expected_name):
    assert bucket.name == expected_name
    file_name = 'data_{0}.txt'.format(int(time.time()))
    blob = bucket.blob(file_name)
    blob.upload_from_string('Hello World')

    blob = bucket.get_blob(file_name)
    assert blob.download_as_string().decode() == 'Hello World'

    bucket.delete_blob(file_name)
    assert not bucket.get_blob(file_name)
