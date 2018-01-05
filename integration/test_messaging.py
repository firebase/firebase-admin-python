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

"""Integration tests for firebase_admin.messaging module."""

import six

from firebase_admin import messaging


def test_send():
    msg = messaging.Message(
        topic='foo-bar',
        notification=messaging.Notification('test-title', 'test-body')
    )
    msg_id = messaging.send(msg, dry_run=True)
    assert isinstance(msg_id, six.string_types)
