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

import re

from firebase_admin import messaging


_REGISTRATION_TOKEN = ('fGw0qy4TGgk:APA91bGtWGjuhp4WRhHXgbabIYp1jxEKI08ofj_v1bKhWAGJQ4e3arRCWzeTf'
                       'HaLz83mBnDh0aPWB1AykXAVUUGl2h1wT4XI6XazWpvY7RBUSYfoxtqSWGIm2nvWh2BOP1YG50'
                       '1SsRoE')


def test_send():
    msg = messaging.Message(
        topic='foo-bar',
        notification=messaging.Notification('test-title', 'test-body'),
        android=messaging.AndroidConfig(
            restricted_package_name='com.google.firebase.demos',
            notification=messaging.AndroidNotification(
                title='android-title',
                body='android-body'
            )
        ),
        apns=messaging.APNSConfig(payload=messaging.APNSPayload(
            aps=messaging.Aps(
                alert=messaging.ApsAlert(
                    title='apns-title',
                    body='apns-body'
                )
            )
        ))
    )
    msg_id = messaging.send(msg, dry_run=True)
    assert re.match('^projects/.*/messages/.*$', msg_id)

def test_subscribe():
    resp = messaging.subscribe_to_topic(_REGISTRATION_TOKEN, 'mock-topic')
    assert resp.success_count + resp.failure_count == 1

def test_unsubscribe():
    resp = messaging.unsubscribe_from_topic(_REGISTRATION_TOKEN, 'mock-topic')
    assert resp.success_count + resp.failure_count == 1
