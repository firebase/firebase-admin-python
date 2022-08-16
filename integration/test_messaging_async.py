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

"""Integration tests for firebase_admin.messaging module."""

import re
from datetime import datetime

import pytest

from firebase_admin import (
    exceptions,
    messaging,
    messaging_async,
)


_REGISTRATION_TOKEN = ('fGw0qy4TGgk:APA91bGtWGjuhp4WRhHXgbabIYp1jxEKI08ofj_v1bKhWAGJQ4e3arRCWzeTf'
                       'HaLz83mBnDh0aPWB1AykXAVUUGl2h1wT4XI6XazWpvY7RBUSYfoxtqSWGIm2nvWh2BOP1YG50'
                       '1SsRoE')

@pytest.mark.asyncio
async def test_send():
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
    msg_id = await messaging_async.send(msg, dry_run=True)
    assert re.match('^projects/.*/messages/.*$', msg_id)

@pytest.mark.asyncio
async def test_send_invalid_token():
    msg = messaging.Message(
        token=_REGISTRATION_TOKEN,
        notification=messaging.Notification('test-title', 'test-body')
    )
    with pytest.raises(messaging.UnregisteredError):
        await messaging_async.send(msg, dry_run=True)

@pytest.mark.asyncio
async def test_send_malformed_token():
    msg = messaging.Message(
        token='not-a-token',
        notification=messaging.Notification('test-title', 'test-body')
    )
    with pytest.raises(exceptions.InvalidArgumentError):
        await messaging_async.send(msg, dry_run=True)

@pytest.mark.asyncio
async def test_subscribe():
    resp = await messaging_async.subscribe_to_topic(_REGISTRATION_TOKEN, 'mock-topic')
    assert resp.success_count + resp.failure_count == 1

@pytest.mark.asyncio
async def test_unsubscribe():
    resp = await messaging_async.unsubscribe_from_topic(_REGISTRATION_TOKEN, 'mock-topic')
    assert resp.success_count + resp.failure_count == 1
