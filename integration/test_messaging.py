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

def test_send_all():
    messages = [
        messaging.Message(topic='foo-bar', notification=messaging.Notification('Title', 'Body')),
        messaging.Message(topic='foo-bar', notification=messaging.Notification('Title', 'Body')),
        messaging.Message(token='not-a-token', notification=messaging.Notification('Title', 'Body')),
    ]

    batch_response = messaging.send_all(messages, dry_run=True)

    assert batch_response.success_count == 2
    assert batch_response.failure_count == 1
    assert len(batch_response.responses) == 3

    response = batch_response.responses[0]
    assert response.success is True
    assert response.exception is None
    assert re.match('^projects/.*/messages/.*$', response.message_id)

    response = batch_response.responses[1]
    assert response.success is True
    assert response.exception is None
    assert re.match('^projects/.*/messages/.*$', response.message_id)

    response = batch_response.responses[2]
    assert response.success is False
    assert response.exception is not None
    assert response.message_id is None

def test_send_one_hundred():
    messages = []
    for i in range(100):
        topic = 'foo-bar-{0}'.format(i % 10)
        messages.append(messaging.Message(topic=topic))

    batch_response = messaging.send_all(messages, dry_run=True)

    assert batch_response.success_count == 100
    assert batch_response.failure_count == 0
    assert len(batch_response.responses) == 100
    for response in batch_response.responses:
        assert response.success is True
        assert response.exception is None
        assert re.match('^projects/.*/messages/.*$', response.message_id)

def test_send_multicast():
    multicast = messaging.MulticastMessage(
        notification=messaging.Notification('Title', 'Body'),
        tokens=['not-a-token', 'also-not-a-token'])

    batch_response = messaging.send_multicast(multicast)

    assert batch_response.success_count is 0
    assert batch_response.failure_count == 2
    assert len(batch_response.responses) == 2
    for response in batch_response.responses:
        assert response.success is False
        assert response.exception is not None
        assert response.message_id is None

def test_subscribe():
    resp = messaging.subscribe_to_topic(_REGISTRATION_TOKEN, 'mock-topic')
    assert resp.success_count + resp.failure_count == 1

def test_unsubscribe():
    resp = messaging.unsubscribe_from_topic(_REGISTRATION_TOKEN, 'mock-topic')
    assert resp.success_count + resp.failure_count == 1
