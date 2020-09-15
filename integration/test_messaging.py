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
from datetime import datetime

import pytest

from firebase_admin import exceptions
from firebase_admin import messaging


_REGISTRATION_TOKEN = ('fGw0qy4TGgk:APA91bGtWGjuhp4WRhHXgbabIYp1jxEKI08ofj_v1bKhWAGJQ4e3arRCWzeTf'
                       'HaLz83mBnDh0aPWB1AykXAVUUGl2h1wT4XI6XazWpvY7RBUSYfoxtqSWGIm2nvWh2BOP1YG50'
                       '1SsRoE')


def test_send():
    msg = messaging.Message(
        topic='foo-bar',
        notification=messaging.Notification('test-title', 'test-body',
                                            'https://images.unsplash.com/photo-1494438639946'
                                            '-1ebd1d20bf85?fit=crop&w=900&q=60'),
        android=messaging.AndroidConfig(
            restricted_package_name='com.google.firebase.demos',
            notification=messaging.AndroidNotification(
                title='android-title',
                body='android-body',
                image='https://images.unsplash.com/'
                      'photo-1494438639946-1ebd1d20bf85?fit=crop&w=900&q=60',
                event_timestamp=datetime.now(),
                priority='high',
                vibrate_timings_millis=[100, 200, 300, 400],
                visibility='public',
                sticky=True,
                local_only=False,
                default_vibrate_timings=False,
                default_sound=True,
                default_light_settings=False,
                light_settings=messaging.LightSettings(
                    color='#aabbcc',
                    light_off_duration_millis=200,
                    light_on_duration_millis=300
                ),
                notification_count=1
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

def test_send_invalid_token():
    msg = messaging.Message(
        token=_REGISTRATION_TOKEN,
        notification=messaging.Notification('test-title', 'test-body')
    )
    with pytest.raises(messaging.UnregisteredError):
        messaging.send(msg, dry_run=True)

def test_send_malformed_token():
    msg = messaging.Message(
        token='not-a-token',
        notification=messaging.Notification('test-title', 'test-body')
    )
    with pytest.raises(exceptions.InvalidArgumentError):
        messaging.send(msg, dry_run=True)

def test_send_all():
    messages = [
        messaging.Message(
            topic='foo-bar', notification=messaging.Notification('Title', 'Body')),
        messaging.Message(
            topic='foo-bar', notification=messaging.Notification('Title', 'Body')),
        messaging.Message(
            token='not-a-token', notification=messaging.Notification('Title', 'Body')),
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
    assert isinstance(response.exception, exceptions.InvalidArgumentError)
    assert response.message_id is None

def test_send_all_500():
    messages = []
    for msg_number in range(500):
        topic = 'foo-bar-{0}'.format(msg_number % 10)
        messages.append(messaging.Message(topic=topic))

    batch_response = messaging.send_all(messages, dry_run=True)

    assert batch_response.success_count == 500
    assert batch_response.failure_count == 0
    assert len(batch_response.responses) == 500
    for response in batch_response.responses:
        assert response.success is True
        assert response.exception is None
        assert re.match('^projects/.*/messages/.*$', response.message_id)

def test_send_multicast():
    multicast = messaging.MulticastMessage(
        notification=messaging.Notification('Title', 'Body'),
        tokens=['not-a-token', 'also-not-a-token'])

    batch_response = messaging.send_multicast(multicast)

    assert batch_response.success_count == 0
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
