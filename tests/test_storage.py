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

"""Tests for firebase_admin.storage."""

import pytest

import firebase_admin
from firebase_admin import credentials
from firebase_admin import storage
from tests import testutils


def setup_module():
    cred = credentials.Certificate(testutils.resource_filename('service_account.json'))
    firebase_admin.initialize_app(cred)

def teardown_module():
    testutils.cleanup_apps()

def test_invalid_config():
    with pytest.raises(ValueError):
        storage.bucket()

@pytest.mark.parametrize('name', [None, '', 0, 1, True, False, list(), tuple(), dict()])
def test_invalid_name(name):
    with pytest.raises(ValueError):
        storage.bucket(name)

def test_valid_name():
    # Should not make RPC calls.
    bucket = storage.bucket('foo')
    assert bucket is not None
    assert bucket.name == 'foo'

def test_valid_name_with_explicit_app():
    # Should not make RPC calls.
    app = firebase_admin.get_app()
    bucket = storage.bucket('foo', app=app)
    assert bucket is not None
    assert bucket.name == 'foo'
