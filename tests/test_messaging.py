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

"""Test cases for the firebase_admin.messaging module."""
import datetime
import json
import numbers

from googleapiclient import http
from googleapiclient import _helpers
import pytest

import firebase_admin
from firebase_admin import exceptions
from firebase_admin import messaging
from firebase_admin import _http_client
from tests import testutils


NON_STRING_ARGS = [list(), tuple(), dict(), True, False, 1, 0]
NON_DICT_ARGS = ['', list(), tuple(), True, False, 1, 0, {1: 'foo'}, {'foo': 1}]
NON_OBJECT_ARGS = [list(), tuple(), dict(), 'foo', 0, 1, True, False]
NON_LIST_ARGS = ['', tuple(), dict(), True, False, 1, 0, [1], ['foo', 1]]
NON_UINT_ARGS = ['1.23s', list(), tuple(), dict(), -1.23]
HTTP_ERROR_CODES = {
    400: exceptions.InvalidArgumentError,
    403: exceptions.PermissionDeniedError,
    404: exceptions.NotFoundError,
    500: exceptions.InternalError,
    503: exceptions.UnavailableError,
}
FCM_ERROR_CODES = {
    'APNS_AUTH_ERROR': messaging.ThirdPartyAuthError,
    'QUOTA_EXCEEDED': messaging.QuotaExceededError,
    'SENDER_ID_MISMATCH': messaging.SenderIdMismatchError,
    'THIRD_PARTY_AUTH_ERROR': messaging.ThirdPartyAuthError,
    'UNREGISTERED': messaging.UnregisteredError,
}


def check_encoding(msg, expected=None):
    encoded = messaging._MessagingService.encode_message(msg)
    if expected:
        assert encoded == expected

def check_exception(exception, message, status):
    assert isinstance(exception, exceptions.FirebaseError)
    assert str(exception) == message
    assert exception.cause is not None
    assert exception.http_response is not None
    assert exception.http_response.status_code == status


class TestMessageStr:

    @pytest.mark.parametrize('msg', [
        messaging.Message(),
        messaging.Message(topic='topic', token='token'),
        messaging.Message(topic='topic', condition='condition'),
        messaging.Message(condition='condition', token='token'),
        messaging.Message(topic='topic', token='token', condition='condition'),
    ])
    def test_invalid_target_message(self, msg):
        with pytest.raises(ValueError) as excinfo:
            str(msg)
        assert str(
            excinfo.value) == 'Exactly one of token, topic or condition must be specified.'

    def test_empty_message(self):
        assert str(messaging.Message(token='value')) == '{"token": "value"}'
        assert str(messaging.Message(topic='value')) == '{"topic": "value"}'
        assert str(messaging.Message(condition='value')
                  ) == '{"condition": "value"}'

    def test_data_message(self):
        assert str(messaging.Message(topic='topic', data={})
                  ) == '{"topic": "topic"}'
        assert str(messaging.Message(topic='topic', data={
            'k1': 'v1', 'k2': 'v2'})) == '{"data": {"k1": "v1", "k2": "v2"}, "topic": "topic"}'


class TestMulticastMessage:

    @pytest.mark.parametrize('tokens', NON_LIST_ARGS)
    def test_invalid_tokens_type(self, tokens):
        with pytest.raises(ValueError) as excinfo:
            messaging.MulticastMessage(tokens=tokens)
        if isinstance(tokens, list):
            expected = 'MulticastMessage.tokens must not contain non-string values.'
            assert str(excinfo.value) == expected
        else:
            expected = 'MulticastMessage.tokens must be a list of strings.'
            assert str(excinfo.value) == expected

    def test_tokens_over_500(self):
        with pytest.raises(ValueError) as excinfo:
            messaging.MulticastMessage(tokens=['token' for _ in range(0, 501)])
        expected = 'MulticastMessage.tokens must not contain more than 500 tokens.'
        assert str(excinfo.value) == expected

    def test_tokens_type(self):
        message = messaging.MulticastMessage(tokens=['token'])
        assert len(message.tokens) == 1

        message = messaging.MulticastMessage(tokens=['token' for _ in range(0, 500)])
        assert len(message.tokens) == 500


class TestMessageEncoder:

    @pytest.mark.parametrize('msg', [
        messaging.Message(),
        messaging.Message(topic='topic', token='token'),
        messaging.Message(topic='topic', condition='condition'),
        messaging.Message(condition='condition', token='token'),
        messaging.Message(topic='topic', token='token', condition='condition'),
    ])
    def test_invalid_target_message(self, msg):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(msg)
        assert str(excinfo.value) == 'Exactly one of token, topic or condition must be specified.'

    @pytest.mark.parametrize('target', NON_STRING_ARGS + [''])
    def test_invalid_token(self, target):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(token=target))
        assert str(excinfo.value) == 'Message.token must be a non-empty string.'

    @pytest.mark.parametrize('target', NON_STRING_ARGS + [''])
    def test_invalid_topic(self, target):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(topic=target))
        assert str(excinfo.value) == 'Message.topic must be a non-empty string.'

    @pytest.mark.parametrize('target', NON_STRING_ARGS + [''])
    def test_invalid_condition(self, target):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(condition=target))
        assert str(excinfo.value) == 'Message.condition must be a non-empty string.'

    @pytest.mark.parametrize('topic', ['/topics/', '/foo/bar', 'foo bar'])
    def test_malformed_topic_name(self, topic):
        with pytest.raises(ValueError):
            check_encoding(messaging.Message(topic=topic))

    def test_empty_message(self):
        check_encoding(messaging.Message(token='value'), {'token': 'value'})
        check_encoding(messaging.Message(topic='value'), {'topic': 'value'})
        check_encoding(messaging.Message(condition='value'), {'condition': 'value'})

    @pytest.mark.parametrize('data', NON_DICT_ARGS)
    def test_invalid_data_message(self, data):
        with pytest.raises(ValueError):
            check_encoding(messaging.Message(topic='topic', data=data))

    def test_data_message(self):
        check_encoding(messaging.Message(topic='topic', data={}), {'topic': 'topic'})
        check_encoding(
            messaging.Message(topic='topic', data={'k1': 'v1', 'k2': 'v2'}),
            {'topic': 'topic', 'data': {'k1': 'v1', 'k2': 'v2'}})

    def test_prefixed_topic(self):
        check_encoding(messaging.Message(topic='/topics/topic'), {'topic': 'topic'})

    def test_fcm_options(self):
        check_encoding(
            messaging.Message(
                topic='topic', fcm_options=messaging.FCMOptions('analytics_label_v1')),
            {'topic': 'topic', 'fcm_options': {'analytics_label': 'analytics_label_v1'}})
        check_encoding(
            messaging.Message(topic='topic', fcm_options=messaging.FCMOptions()),
            {'topic': 'topic'})


class TestNotificationEncoder:

    @pytest.mark.parametrize('data', NON_OBJECT_ARGS)
    def test_invalid_notification(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', notification=data))
        expected = 'Message.notification must be an instance of Notification class.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_title(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', notification=messaging.Notification(title=data)))
        assert str(excinfo.value) == 'Notification.title must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_body(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', notification=messaging.Notification(body=data)))
        assert str(excinfo.value) == 'Notification.body must be a string.'

    def test_notification_message(self):
        check_encoding(
            messaging.Message(topic='topic', notification=messaging.Notification()),
            {'topic': 'topic'})
        check_encoding(
            messaging.Message(topic='topic', notification=messaging.Notification('t', 'b')),
            {'topic': 'topic', 'notification': {'title': 't', 'body': 'b'}})
        check_encoding(
            messaging.Message(topic='topic', notification=messaging.Notification('t')),
            {'topic': 'topic', 'notification': {'title': 't'}})


class TestFcmOptionEncoder:

    @pytest.mark.parametrize('label', [
        '!',
        'THIS_IS_LONGER_THAN_50_CHARACTERS_WHICH_IS_NOT_ALLOWED',
        '',
    ])
    def test_invalid_fcm_options(self, label):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic',
                fcm_options=messaging.FCMOptions(label)
            ))
        expected = 'Malformed FCMOptions.analytics_label.'
        assert str(excinfo.value) == expected

    def test_fcm_options(self):
        check_encoding(
            messaging.Message(
                topic='topic',
                fcm_options=messaging.FCMOptions(),
                android=messaging.AndroidConfig(fcm_options=messaging.AndroidFCMOptions()),
                apns=messaging.APNSConfig(fcm_options=messaging.APNSFCMOptions())
            ),
            {'topic': 'topic'})
        check_encoding(
            messaging.Message(
                topic='topic',
                fcm_options=messaging.FCMOptions('message-label'),
                android=messaging.AndroidConfig(
                    fcm_options=messaging.AndroidFCMOptions('android-label')),
                apns=messaging.APNSConfig(fcm_options=
                                          messaging.APNSFCMOptions(
                                              analytics_label='apns-label',
                                              image='https://images.unsplash.com/photo-14944386399'
                                                    '46-1ebd1d20bf85?fit=crop&w=900&q=60'))
            ),
            {
                'topic': 'topic',
                'fcm_options': {'analytics_label': 'message-label'},
                'android': {'fcm_options': {'analytics_label': 'android-label'}},
                'apns': {'fcm_options': {'analytics_label': 'apns-label',
                                         'image': 'https://images.unsplash.com/photo-14944386399'
                                                  '46-1ebd1d20bf85?fit=crop&w=900&q=60'}},
            })


class TestAndroidConfigEncoder:

    @pytest.mark.parametrize('data', NON_OBJECT_ARGS)
    def test_invalid_android(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', android=data))
        expected = 'Message.android must be an instance of AndroidConfig class.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_collapse_key(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', android=messaging.AndroidConfig(collapse_key=data)))
        assert str(excinfo.value) == 'AndroidConfig.collapse_key must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS + ['foo'])
    def test_invalid_priority(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', android=messaging.AndroidConfig(priority=data)))
        if isinstance(data, str):
            assert str(excinfo.value) == 'AndroidConfig.priority must be "high" or "normal".'
        else:
            assert str(excinfo.value) == 'AndroidConfig.priority must be a non-empty string.'

    @pytest.mark.parametrize('data', NON_UINT_ARGS)
    def test_invalid_ttl(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', android=messaging.AndroidConfig(ttl=data)))
        if isinstance(data, numbers.Number):
            assert str(excinfo.value) == ('AndroidConfig.ttl must not be negative.')
        else:
            assert str(excinfo.value) == ('AndroidConfig.ttl must be a duration in seconds or '
                                          'an instance of datetime.timedelta.')

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_package_name(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', android=messaging.AndroidConfig(restricted_package_name=data)))
        assert str(excinfo.value) == 'AndroidConfig.restricted_package_name must be a string.'

    @pytest.mark.parametrize('data', NON_DICT_ARGS)
    def test_invalid_data(self, data):
        with pytest.raises(ValueError):
            check_encoding(messaging.Message(
                topic='topic', android=messaging.AndroidConfig(data=data)))

    def test_android_config(self):
        msg = messaging.Message(
            topic='topic',
            android=messaging.AndroidConfig(
                collapse_key='key',
                restricted_package_name='package',
                priority='high',
                ttl=123,
                data={'k1': 'v1', 'k2': 'v2'},
                fcm_options=messaging.AndroidFCMOptions('analytics_label_v1')
            )
        )
        expected = {
            'topic': 'topic',
            'android': {
                'collapse_key': 'key',
                'restricted_package_name': 'package',
                'priority': 'high',
                'ttl': '123s',
                'data': {
                    'k1': 'v1',
                    'k2': 'v2',
                },
                'fcm_options': {
                    'analytics_label': 'analytics_label_v1',
                },
            },
        }
        check_encoding(msg, expected)

    @pytest.mark.parametrize('ttl', [
        (0.5, '0.500000000s'),
        (123, '123s'),
        (123.45, '123.450000000s'),
        (datetime.timedelta(days=1, seconds=100), '86500s'),
    ])
    def test_android_ttl(self, ttl):
        msg = messaging.Message(
            topic='topic',
            android=messaging.AndroidConfig(ttl=ttl[0])
        )
        expected = {
            'topic': 'topic',
            'android': {
                'ttl': ttl[1],
            },
        }
        check_encoding(msg, expected)


class TestAndroidNotificationEncoder:

    def _check_notification(self, notification):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', android=messaging.AndroidConfig(notification=notification)))
        return excinfo

    @pytest.mark.parametrize('data', NON_OBJECT_ARGS)
    def test_invalid_android_notification(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', android=messaging.AndroidConfig(notification=data)))
        expected = 'AndroidConfig.notification must be an instance of AndroidNotification class.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_title(self, data):
        notification = messaging.AndroidNotification(title=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.title must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_body(self, data):
        notification = messaging.AndroidNotification(body=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.body must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_icon(self, data):
        notification = messaging.AndroidNotification(icon=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.icon must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS + ['foo', '#xxyyzz', '112233', '#11223'])
    def test_invalid_color(self, data):
        notification = messaging.AndroidNotification(color=data)
        excinfo = self._check_notification(notification)
        if isinstance(data, str):
            assert str(excinfo.value) == 'AndroidNotification.color must be in the form #RRGGBB.'
        else:
            assert str(excinfo.value) == 'AndroidNotification.color must be a non-empty string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_sound(self, data):
        notification = messaging.AndroidNotification(sound=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.sound must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_tag(self, data):
        notification = messaging.AndroidNotification(tag=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.tag must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_click_action(self, data):
        notification = messaging.AndroidNotification(click_action=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.click_action must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_title_loc_key(self, data):
        notification = messaging.AndroidNotification(title_loc_key=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.title_loc_key must be a string.'

    @pytest.mark.parametrize('data', NON_LIST_ARGS)
    def test_invalid_title_loc_args(self, data):
        notification = messaging.AndroidNotification(title_loc_key='foo', title_loc_args=data)
        excinfo = self._check_notification(notification)
        if isinstance(data, list):
            expected = 'AndroidNotification.title_loc_args must not contain non-string values.'
            assert str(excinfo.value) == expected
        else:
            expected = 'AndroidNotification.title_loc_args must be a list of strings.'
            assert str(excinfo.value) == expected

    def test_no_title_loc_key(self):
        notification = messaging.AndroidNotification(title_loc_args=['foo'])
        excinfo = self._check_notification(notification)
        expected = 'AndroidNotification.title_loc_key is required when specifying title_loc_args.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_body_loc_key(self, data):
        notification = messaging.AndroidNotification(body_loc_key=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.body_loc_key must be a string.'

    @pytest.mark.parametrize('data', NON_LIST_ARGS)
    def test_invalid_body_loc_args(self, data):
        notification = messaging.AndroidNotification(body_loc_key='foo', body_loc_args=data)
        excinfo = self._check_notification(notification)
        if isinstance(data, list):
            expected = 'AndroidNotification.body_loc_args must not contain non-string values.'
            assert str(excinfo.value) == expected
        else:
            expected = 'AndroidNotification.body_loc_args must be a list of strings.'
            assert str(excinfo.value) == expected

    def test_no_body_loc_key(self):
        notification = messaging.AndroidNotification(body_loc_args=['foo'])
        excinfo = self._check_notification(notification)
        expected = 'AndroidNotification.body_loc_key is required when specifying body_loc_args.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_channel_id(self, data):
        notification = messaging.AndroidNotification(channel_id=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.channel_id must be a string.'

    @pytest.mark.parametrize('timestamp', [100, '', 'foo', {}, [], list(), dict()])
    def test_invalid_event_timestamp(self, timestamp):
        notification = messaging.AndroidNotification(event_timestamp=timestamp)
        excinfo = self._check_notification(notification)
        expected = 'AndroidNotification.event_timestamp must be a datetime.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('priority', NON_STRING_ARGS + ['foo'])
    def test_invalid_priority(self, priority):
        notification = messaging.AndroidNotification(priority=priority)
        excinfo = self._check_notification(notification)
        if isinstance(priority, str):
            if not priority:
                expected = 'AndroidNotification.priority must be a non-empty string.'
            else:
                expected = ('AndroidNotification.priority must be "default", "min", "low", "high" '
                            'or "max".')
        else:
            expected = 'AndroidNotification.priority must be a non-empty string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('visibility', NON_STRING_ARGS + ['foo'])
    def test_invalid_visibility(self, visibility):
        notification = messaging.AndroidNotification(visibility=visibility)
        excinfo = self._check_notification(notification)
        if isinstance(visibility, str):
            if not visibility:
                expected = 'AndroidNotification.visibility must be a non-empty string.'
            else:
                expected = ('AndroidNotification.visibility must be "private", "public" or'
                            ' "secret".')
        else:
            expected = 'AndroidNotification.visibility must be a non-empty string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('vibrate_timings', ['', 1, True, 'msec', ['500', 500], [0, 'abc']])
    def test_invalid_vibrate_timings_millis(self, vibrate_timings):
        notification = messaging.AndroidNotification(vibrate_timings_millis=vibrate_timings)
        excinfo = self._check_notification(notification)
        if isinstance(vibrate_timings, list):
            expected = ('AndroidNotification.vibrate_timings_millis must not contain non-number '
                        'values.')
        else:
            expected = 'AndroidNotification.vibrate_timings_millis must be a list of numbers.'
        assert str(excinfo.value) == expected

    def test_negative_vibrate_timings_millis(self):
        notification = messaging.AndroidNotification(
            vibrate_timings_millis=[100, -20, 15])
        excinfo = self._check_notification(notification)
        expected = 'AndroidNotification.vibrate_timings_millis must not be negative.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('notification_count', ['', 'foo', list(), tuple(), dict()])
    def test_invalid_notification_count(self, notification_count):
        notification = messaging.AndroidNotification(notification_count=notification_count)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.notification_count must be a number.'

    def test_android_notification(self):
        msg = messaging.Message(
            topic='topic',
            android=messaging.AndroidConfig(
                notification=messaging.AndroidNotification(
                    title='t', body='b', icon='i', color='#112233', sound='s', tag='t',
                    click_action='ca', title_loc_key='tlk', body_loc_key='blk',
                    title_loc_args=['t1', 't2'], body_loc_args=['b1', 'b2'], channel_id='c',
                    ticker='ticker', sticky=True,
                    event_timestamp=datetime.datetime(
                        2019, 10, 20, 15, 12, 23, 123,
                        tzinfo=datetime.timezone(datetime.timedelta(hours=-5))
                    ),
                    local_only=False,
                    priority='high', vibrate_timings_millis=[100, 50, 250],
                    default_vibrate_timings=False, default_sound=True,
                    light_settings=messaging.LightSettings(
                        color='#AABBCCDD', light_on_duration_millis=200,
                        light_off_duration_millis=300,
                    ),
                    default_light_settings=False, visibility='public', notification_count=1,
                )
            )
        )
        expected = {
            'topic': 'topic',
            'android': {
                'notification': {
                    'title': 't',
                    'body': 'b',
                    'icon': 'i',
                    'color': '#112233',
                    'sound': 's',
                    'tag': 't',
                    'click_action': 'ca',
                    'title_loc_key': 'tlk',
                    'body_loc_key': 'blk',
                    'title_loc_args': ['t1', 't2'],
                    'body_loc_args': ['b1', 'b2'],
                    'channel_id': 'c',
                    'ticker': 'ticker',
                    'sticky': True,
                    'event_time': '2019-10-20T20:12:23.000123Z',
                    'local_only': False,
                    'notification_priority': 'PRIORITY_HIGH',
                    'vibrate_timings': ['0.100000000s', '0.050000000s', '0.250000000s'],
                    'default_vibrate_timings': False,
                    'default_sound': 1,
                    'light_settings': {
                        'color': {
                            'red': 0.6666666666666666,
                            'green': 0.7333333333333333,
                            'blue': 0.8,
                            'alpha': 0.8666666666666667,
                        },
                        'light_on_duration': '0.200000000s',
                        'light_off_duration': '0.300000000s',
                    },
                    'default_light_settings': False,
                    'visibility': 'PUBLIC',
                    'notification_count': 1,
                },
            },
        }
        check_encoding(msg, expected)

    def test_android_notification_naive_event_timestamp(self):
        event_time = datetime.datetime.now()
        msg = messaging.Message(
            topic='topic',
            android=messaging.AndroidConfig(
                notification=messaging.AndroidNotification(
                    title='t',
                    event_timestamp=event_time,
                )
            )
        )
        expected = {
            'topic': 'topic',
            'android': {
                'notification': {
                    'title': 't',
                    'event_time': event_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                },
            },
        }
        check_encoding(msg, expected)


class TestLightSettingsEncoder:

    def _check_light_settings(self, light_settings):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', android=messaging.AndroidConfig(
                    notification=messaging.AndroidNotification(
                        light_settings=light_settings
                    ))))
        return excinfo

    @pytest.mark.parametrize('data', NON_OBJECT_ARGS)
    def test_invalid_light_settings(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', android=messaging.AndroidConfig(
                    notification=messaging.AndroidNotification(
                        light_settings=data
                    ))))
        expected = 'AndroidNotification.light_settings must be an instance of LightSettings class.'
        assert str(excinfo.value) == expected

    def test_no_color(self):
        light_settings = messaging.LightSettings(color=None, light_on_duration_millis=200,
                                                 light_off_duration_millis=200)
        excinfo = self._check_light_settings(light_settings)
        expected = 'LightSettings.color is required.'
        assert str(excinfo.value) == expected

    def test_no_light_on_duration_millis(self):
        light_settings = messaging.LightSettings(color='#aabbcc', light_on_duration_millis=None,
                                                 light_off_duration_millis=200)
        excinfo = self._check_light_settings(light_settings)
        expected = 'LightSettings.light_on_duration_millis is required.'
        assert str(excinfo.value) == expected

    def test_no_light_off_duration_millis(self):
        light_settings = messaging.LightSettings(color='#aabbcc', light_on_duration_millis=200,
                                                 light_off_duration_millis=None)
        excinfo = self._check_light_settings(light_settings)
        expected = 'LightSettings.light_off_duration_millis is required.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_UINT_ARGS)
    def test_invalid_light_off_duration_millis(self, data):
        light_settings = messaging.LightSettings(color='#aabbcc',
                                                 light_on_duration_millis=200,
                                                 light_off_duration_millis=data)
        excinfo = self._check_light_settings(light_settings)
        if isinstance(data, numbers.Number):
            assert str(excinfo.value) == ('LightSettings.light_off_duration_millis must not be '
                                          'negative.')
        else:
            assert str(excinfo.value) == ('LightSettings.light_off_duration_millis must be a '
                                          'duration in milliseconds or '
                                          'an instance of datetime.timedelta.')

    @pytest.mark.parametrize('data', NON_UINT_ARGS)
    def test_invalid_light_on_duration_millis(self, data):
        light_settings = messaging.LightSettings(color='#aabbcc',
                                                 light_on_duration_millis=data,
                                                 light_off_duration_millis=200)
        excinfo = self._check_light_settings(light_settings)
        if isinstance(data, numbers.Number):
            assert str(excinfo.value) == ('LightSettings.light_on_duration_millis must not be '
                                          'negative.')
        else:
            assert str(excinfo.value) == ('LightSettings.light_on_duration_millis must be a '
                                          'duration in milliseconds or '
                                          'an instance of datetime.timedelta.')

    @pytest.mark.parametrize('data', NON_STRING_ARGS + ['foo', '#xxyyzz', '112233', '#11223'])
    def test_invalid_color(self, data):
        notification = messaging.LightSettings(color=data, light_on_duration_millis=300,
                                               light_off_duration_millis=200)
        excinfo = self._check_light_settings(notification)
        if isinstance(data, str):
            assert str(excinfo.value) == ('LightSettings.color must be in the form #RRGGBB or '
                                          '#RRGGBBAA.')
        else:
            assert str(
                excinfo.value) == 'LightSettings.color must be a non-empty string.'

    def test_light_settings(self):
        msg = messaging.Message(
            topic='topic', android=messaging.AndroidConfig(
                notification=messaging.AndroidNotification(
                    light_settings=messaging.LightSettings(
                        color="#aabbcc",
                        light_on_duration_millis=200,
                        light_off_duration_millis=300,
                    )
                ))
        )
        expected = {
            'topic': 'topic',
            'android': {
                'notification': {
                    'light_settings': {
                        'color': {
                            'red': 0.6666666666666666,
                            'green': 0.7333333333333333,
                            'blue': 0.8,
                            'alpha': 1,
                        },
                        'light_on_duration': '0.200000000s',
                        'light_off_duration': '0.300000000s',
                    }
                },
            },
        }
        check_encoding(msg, expected)


class TestWebpushConfigEncoder:

    @pytest.mark.parametrize('data', NON_OBJECT_ARGS)
    def test_invalid_webpush(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', webpush=data))
        expected = 'Message.webpush must be an instance of WebpushConfig class.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_DICT_ARGS)
    def test_invalid_headers(self, data):
        with pytest.raises(ValueError):
            check_encoding(messaging.Message(
                topic='topic', webpush=messaging.WebpushConfig(headers=data)))

    @pytest.mark.parametrize('data', NON_DICT_ARGS)
    def test_invalid_data(self, data):
        with pytest.raises(ValueError):
            check_encoding(messaging.Message(
                topic='topic', webpush=messaging.WebpushConfig(data=data)))

    def test_webpush_config(self):
        msg = messaging.Message(
            topic='topic',
            webpush=messaging.WebpushConfig(
                headers={'h1': 'v1', 'h2': 'v2'},
                data={'k1': 'v1', 'k2': 'v2'},
            )
        )
        expected = {
            'topic': 'topic',
            'webpush': {
                'headers': {
                    'h1': 'v1',
                    'h2': 'v2',
                },
                'data': {
                    'k1': 'v1',
                    'k2': 'v2',
                },
            },
        }
        check_encoding(msg, expected)


class TestWebpushFCMOptionsEncoder:

    @pytest.mark.parametrize('data', NON_OBJECT_ARGS)
    def test_invalid_webpush_fcm_options(self, data):
        with pytest.raises(AttributeError):
            check_encoding(messaging.Message(
                topic='topic', webpush=messaging.WebpushConfig(fcm_options=data)))

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_link_type(self, data):
        options = messaging.WebpushFCMOptions(link=data)
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', webpush=messaging.WebpushConfig(fcm_options=options)))
        expected = 'WebpushConfig.fcm_options.link must be a string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', ['', 'foo', 'http://example'])
    def test_invalid_link_format(self, data):
        options = messaging.WebpushFCMOptions(link=data)
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', webpush=messaging.WebpushConfig(fcm_options=options)))
        expected = 'WebpushFCMOptions.link must be a HTTPS URL.'
        assert str(excinfo.value) == expected

    def test_webpush_options(self):
        msg = messaging.Message(
            topic='topic',
            webpush=messaging.WebpushConfig(
                fcm_options=messaging.WebpushFCMOptions(
                    link='https://example',
                ),
            )
        )
        expected = {
            'topic': 'topic',
            'webpush': {
                'fcm_options': {
                    'link': 'https://example',
                },
            },
        }
        check_encoding(msg, expected)


class TestWebpushNotificationEncoder:

    def _check_notification(self, notification):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', webpush=messaging.WebpushConfig(notification=notification)))
        return excinfo

    @pytest.mark.parametrize('data', NON_OBJECT_ARGS)
    def test_invalid_webpush_notification(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', webpush=messaging.WebpushConfig(notification=data)))
        expected = 'WebpushConfig.notification must be an instance of WebpushNotification class.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_title(self, data):
        notification = messaging.WebpushNotification(title=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotification.title must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_body(self, data):
        notification = messaging.WebpushNotification(body=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotification.body must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_icon(self, data):
        notification = messaging.WebpushNotification(icon=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotification.icon must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_badge(self, data):
        notification = messaging.WebpushNotification(badge=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotification.badge must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS + ['foo'])
    def test_invalid_direction(self, data):
        notification = messaging.WebpushNotification(direction=data)
        excinfo = self._check_notification(notification)
        if isinstance(data, str):
            assert str(excinfo.value) == ('WebpushNotification.direction must be "auto", '
                                          '"ltr" or "rtl".')
        else:
            assert str(excinfo.value) == 'WebpushNotification.direction must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_image(self, data):
        notification = messaging.WebpushNotification(image=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotification.image must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_language(self, data):
        notification = messaging.WebpushNotification(language=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotification.language must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_tag(self, data):
        notification = messaging.WebpushNotification(tag=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotification.tag must be a string.'

    @pytest.mark.parametrize('data', ['', 'foo', list(), tuple(), dict()])
    def test_invalid_timestamp(self, data):
        notification = messaging.WebpushNotification(timestamp_millis=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotification.timestamp_millis must be a number.'

    @pytest.mark.parametrize('data', ['', list(), tuple(), True, False, 1, 0])
    def test_invalid_custom_data(self, data):
        notification = messaging.WebpushNotification(custom_data=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotification.custom_data must be a dict.'

    @pytest.mark.parametrize('data', ['', dict(), tuple(), True, False, 1, 0, [1, 2]])
    def test_invalid_actions(self, data):
        notification = messaging.WebpushNotification(actions=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == ('WebpushConfig.notification.actions must be a list of '
                                      'WebpushNotificationAction instances.')

    def test_webpush_notification(self):
        msg = messaging.Message(
            topic='topic',
            webpush=messaging.WebpushConfig(
                notification=messaging.WebpushNotification(
                    badge='badge',
                    body='body',
                    data={'foo': 'bar'},
                    icon='icon',
                    image='image',
                    language='language',
                    renotify=True,
                    require_interaction=True,
                    silent=True,
                    tag='tag',
                    timestamp_millis=100,
                    title='title',
                    vibrate=[100, 200, 100],
                    custom_data={'k1': 'v1', 'k2': 'v2'},
                ),
            )
        )
        expected = {
            'topic': 'topic',
            'webpush': {
                'notification': {
                    'badge': 'badge',
                    'body': 'body',
                    'data': {'foo': 'bar'},
                    'icon': 'icon',
                    'image': 'image',
                    'lang': 'language',
                    'renotify': True,
                    'requireInteraction': True,
                    'silent': True,
                    'tag': 'tag',
                    'timestamp': 100,
                    'vibrate': [100, 200, 100],
                    'title': 'title',
                    'k1': 'v1',
                    'k2': 'v2',
                },
            },
        }
        check_encoding(msg, expected)

    def test_multiple_field_specifications(self):
        notification = messaging.WebpushNotification(
            badge='badge',
            custom_data={'badge': 'other badge'},
        )
        excinfo = self._check_notification(notification)
        expected = 'Multiple specifications for badge in WebpushNotification.'
        assert str(excinfo.value) == expected

    def test_webpush_notification_action(self):
        msg = messaging.Message(
            topic='topic',
            webpush=messaging.WebpushConfig(
                notification=messaging.WebpushNotification(
                    actions=[
                        messaging.WebpushNotificationAction(
                            action='a1',
                            title='t1',
                        ),
                        messaging.WebpushNotificationAction(
                            action='a2',
                            title='t2',
                            icon='i2',
                        ),
                    ],
                ),
            )
        )
        expected = {
            'topic': 'topic',
            'webpush': {
                'notification': {
                    'actions': [
                        {
                            'action': 'a1',
                            'title': 't1',
                        },
                        {
                            'action': 'a2',
                            'title': 't2',
                            'icon': 'i2',
                        },
                    ],
                },
            },
        }
        check_encoding(msg, expected)

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_action_name(self, data):
        action = messaging.WebpushNotificationAction(action=data, title='title')
        notification = messaging.WebpushNotification(actions=[action])
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotificationAction.action must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_action_title(self, data):
        action = messaging.WebpushNotificationAction(action='action', title=data)
        notification = messaging.WebpushNotification(actions=[action])
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotificationAction.title must be a string.'

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_action_icon(self, data):
        action = messaging.WebpushNotificationAction(action='action', title='title', icon=data)
        notification = messaging.WebpushNotification(actions=[action])
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'WebpushNotificationAction.icon must be a string.'


class TestAPNSConfigEncoder:

    @pytest.mark.parametrize('data', NON_OBJECT_ARGS)
    def test_invalid_apns(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', apns=data))
        expected = 'Message.apns must be an instance of APNSConfig class.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_DICT_ARGS)
    def test_invalid_headers(self, data):
        with pytest.raises(ValueError):
            check_encoding(messaging.Message(
                topic='topic', apns=messaging.APNSConfig(headers=data)))

    def test_apns_config(self):
        msg = messaging.Message(
            topic='topic',
            apns=messaging.APNSConfig(
                headers={'h1': 'v1', 'h2': 'v2'},
                fcm_options=messaging.APNSFCMOptions('analytics_label_v1')
            ),
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'headers': {
                    'h1': 'v1',
                    'h2': 'v2',
                },
                'fcm_options': {
                    'analytics_label': 'analytics_label_v1',
                },
            },
        }
        check_encoding(msg, expected)


class TestAPNSPayloadEncoder:

    @pytest.mark.parametrize('data', NON_OBJECT_ARGS)
    def test_invalid_payload(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', apns=messaging.APNSConfig(payload=data)))
        expected = 'APNSConfig.payload must be an instance of APNSPayload class.'
        assert str(excinfo.value) == expected

    def test_apns_payload(self):
        msg = messaging.Message(
            topic='topic',
            apns=messaging.APNSConfig(payload=messaging.APNSPayload(
                aps=messaging.Aps(alert='alert text'),
                k1='v1',
                k2=True
            ))
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'payload': {
                    'aps': {
                        'alert': 'alert text',
                    },
                    'k1': 'v1',
                    'k2': True,
                },
            },
        }
        check_encoding(msg, expected)


class TestApsEncoder:

    def _encode_aps(self, aps):
        return check_encoding(messaging.Message(
            topic='topic', apns=messaging.APNSConfig(payload=messaging.APNSPayload(aps=aps))))

    @pytest.mark.parametrize('data', NON_OBJECT_ARGS)
    def test_invalid_aps(self, data):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic',
                apns=messaging.APNSConfig(payload=messaging.APNSPayload(aps=data))))
        expected = 'APNSPayload.aps must be an instance of Aps class.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_alert(self, data):
        aps = messaging.Aps(alert=data)
        with pytest.raises(ValueError) as excinfo:
            self._encode_aps(aps)
        expected = 'Aps.alert must be a string or an instance of ApsAlert class.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', [list(), tuple(), dict(), 'foo'])
    def test_invalid_badge(self, data):
        aps = messaging.Aps(badge=data)
        with pytest.raises(ValueError) as excinfo:
            self._encode_aps(aps)
        expected = 'Aps.badge must be a number.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS + [''])
    def test_invalid_sound(self, data):
        aps = messaging.Aps(sound=data)
        with pytest.raises(ValueError) as excinfo:
            self._encode_aps(aps)
        expected = 'Aps.sound must be a non-empty string or an instance of CriticalSound class.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_category(self, data):
        aps = messaging.Aps(category=data)
        with pytest.raises(ValueError) as excinfo:
            self._encode_aps(aps)
        expected = 'Aps.category must be a string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_thread_id(self, data):
        aps = messaging.Aps(thread_id=data)
        with pytest.raises(ValueError) as excinfo:
            self._encode_aps(aps)
        expected = 'Aps.thread_id must be a string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', ['', list(), tuple(), True, False, 1, 0, ])
    def test_invalid_custom_data_dict(self, data):
        if isinstance(data, dict):
            return
        aps = messaging.Aps(custom_data=data)
        with pytest.raises(ValueError) as excinfo:
            self._encode_aps(aps)
        expected = 'Aps.custom_data must be a dict.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', [True, False, 1, 0])
    def test_invalid_custom_field_name(self, data):
        aps = messaging.Aps(custom_data={data: 'foo'})
        with pytest.raises(ValueError) as excinfo:
            self._encode_aps(aps)
        expected = 'Aps.custom_data key must be a string.'
        assert str(excinfo.value) == expected

    def test_multiple_field_specifications(self):
        aps = messaging.Aps(thread_id='foo', custom_data={'thread-id': 'foo'})
        with pytest.raises(ValueError) as excinfo:
            self._encode_aps(aps)
        expected = 'Multiple specifications for thread-id in Aps.'
        assert str(excinfo.value) == expected

    def test_aps(self):
        msg = messaging.Message(
            topic='topic',
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        alert='alert text',
                        badge=42,
                        sound='s',
                        content_available=True,
                        mutable_content=True,
                        category='c',
                        thread_id='t'
                    ),
                )
            )
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'payload': {
                    'aps': {
                        'alert': 'alert text',
                        'badge': 42,
                        'sound': 's',
                        'content-available': 1,
                        'mutable-content': 1,
                        'category': 'c',
                        'thread-id': 't',
                    },
                }
            },
        }
        check_encoding(msg, expected)

    def test_aps_custom_data(self):
        msg = messaging.Message(
            topic='topic',
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        alert='alert text',
                        custom_data={'k1': 'v1', 'k2': 1},
                    ),
                )
            )
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'payload': {
                    'aps': {
                        'alert': 'alert text',
                        'k1': 'v1',
                        'k2': 1,
                    },
                }
            },
        }
        check_encoding(msg, expected)


class TestApsSoundEncoder:

    def _check_sound(self, sound):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', apns=messaging.APNSConfig(
                    payload=messaging.APNSPayload(aps=messaging.Aps(sound=sound))
                )
            ))
        return excinfo

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_name(self, data):
        sound = messaging.CriticalSound(name=data)
        excinfo = self._check_sound(sound)
        expected = 'CriticalSound.name must be a non-empty string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', [list(), tuple(), dict(), 'foo'])
    def test_invalid_volume(self, data):
        sound = messaging.CriticalSound(name='default', volume=data)
        excinfo = self._check_sound(sound)
        expected = 'CriticalSound.volume must be a number.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', [-0.1, 1.1])
    def test_volume_out_of_range(self, data):
        sound = messaging.CriticalSound(name='default', volume=data)
        excinfo = self._check_sound(sound)
        expected = 'CriticalSound.volume must be in the interval [0,1].'
        assert str(excinfo.value) == expected

    def test_sound_string(self):
        msg = messaging.Message(
            topic='topic',
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(aps=messaging.Aps(sound='default'))
            )
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'payload': {
                    'aps': {
                        'sound': 'default',
                    },
                }
            },
        }
        check_encoding(msg, expected)

    def test_critical_sound(self):
        msg = messaging.Message(
            topic='topic',
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        sound=messaging.CriticalSound(
                            name='default',
                            critical=True,
                            volume=0.5
                        )
                    ),
                )
            )
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'payload': {
                    'aps': {
                        'sound': {
                            'name': 'default',
                            'critical': 1,
                            'volume': 0.5,
                        },
                    },
                }
            },
        }
        check_encoding(msg, expected)

    def test_critical_sound_name_only(self):
        msg = messaging.Message(
            topic='topic',
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        sound=messaging.CriticalSound(name='default')
                    ),
                )
            )
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'payload': {
                    'aps': {
                        'sound': {
                            'name': 'default',
                        },
                    },
                }
            },
        }
        check_encoding(msg, expected)


class TestApsAlertEncoder:

    def _check_alert(self, alert):
        with pytest.raises(ValueError) as excinfo:
            check_encoding(messaging.Message(
                topic='topic', apns=messaging.APNSConfig(
                    payload=messaging.APNSPayload(aps=messaging.Aps(alert=alert))
                )
            ))
        return excinfo

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_title(self, data):
        alert = messaging.ApsAlert(title=data)
        excinfo = self._check_alert(alert)
        expected = 'ApsAlert.title must be a string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_subtitle(self, data):
        alert = messaging.ApsAlert(subtitle=data)
        excinfo = self._check_alert(alert)
        expected = 'ApsAlert.subtitle must be a string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_body(self, data):
        alert = messaging.ApsAlert(body=data)
        excinfo = self._check_alert(alert)
        expected = 'ApsAlert.body must be a string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_title_loc_key(self, data):
        alert = messaging.ApsAlert(title_loc_key=data)
        excinfo = self._check_alert(alert)
        expected = 'ApsAlert.title_loc_key must be a string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_loc_key(self, data):
        alert = messaging.ApsAlert(loc_key=data)
        excinfo = self._check_alert(alert)
        expected = 'ApsAlert.loc_key must be a string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_action_loc_key(self, data):
        alert = messaging.ApsAlert(action_loc_key=data)
        excinfo = self._check_alert(alert)
        expected = 'ApsAlert.action_loc_key must be a string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_STRING_ARGS)
    def test_invalid_launch_image(self, data):
        alert = messaging.ApsAlert(launch_image=data)
        excinfo = self._check_alert(alert)
        expected = 'ApsAlert.launch_image must be a string.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_LIST_ARGS)
    def test_invalid_title_loc_args(self, data):
        alert = messaging.ApsAlert(title_loc_key='foo', title_loc_args=data)
        excinfo = self._check_alert(alert)
        if isinstance(data, list):
            expected = 'ApsAlert.title_loc_args must not contain non-string values.'
            assert str(excinfo.value) == expected
        else:
            expected = 'ApsAlert.title_loc_args must be a list of strings.'
            assert str(excinfo.value) == expected

    def test_no_title_loc_key(self):
        alert = messaging.ApsAlert(title_loc_args=['foo'])
        excinfo = self._check_alert(alert)
        expected = 'ApsAlert.title_loc_key is required when specifying title_loc_args.'
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('data', NON_LIST_ARGS)
    def test_invalid_loc_args(self, data):
        alert = messaging.ApsAlert(loc_key='foo', loc_args=data)
        excinfo = self._check_alert(alert)
        if isinstance(data, list):
            expected = 'ApsAlert.loc_args must not contain non-string values.'
            assert str(excinfo.value) == expected
        else:
            expected = 'ApsAlert.loc_args must be a list of strings.'
            assert str(excinfo.value) == expected

    def test_no_loc_key(self):
        alert = messaging.ApsAlert(loc_args=['foo'])
        excinfo = self._check_alert(alert)
        expected = 'ApsAlert.loc_key is required when specifying loc_args.'
        assert str(excinfo.value) == expected

    def test_aps_alert(self):
        msg = messaging.Message(
            topic='topic',
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        alert=messaging.ApsAlert(
                            title='t',
                            subtitle='st',
                            body='b',
                            title_loc_key='tlk',
                            title_loc_args=['t1', 't2'],
                            loc_key='lk',
                            loc_args=['l1', 'l2'],
                            action_loc_key='alk',
                            launch_image='li'
                        )
                    ),
                )
            )
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'payload': {
                    'aps': {
                        'alert': {
                            'title': 't',
                            'subtitle': 'st',
                            'body': 'b',
                            'title-loc-key': 'tlk',
                            'title-loc-args': ['t1', 't2'],
                            'loc-key': 'lk',
                            'loc-args': ['l1', 'l2'],
                            'action-loc-key': 'alk',
                            'launch-image': 'li',
                        },
                    },
                }
            },
        }
        check_encoding(msg, expected)

    def test_aps_alert_custom_data_merge(self):
        msg = messaging.Message(
            topic='topic',
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        alert=messaging.ApsAlert(
                            title='t',
                            subtitle='st',
                            custom_data={'k1': 'v1', 'k2': 'v2'}
                        )
                    ),
                )
            )
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'payload': {
                    'aps': {
                        'alert': {
                            'title': 't',
                            'subtitle': 'st',
                            'k1': 'v1',
                            'k2': 'v2'
                        },
                    },
                }
            },
        }
        check_encoding(msg, expected)

    def test_aps_alert_custom_data_override(self):
        msg = messaging.Message(
            topic='topic',
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        alert=messaging.ApsAlert(
                            title='t',
                            subtitle='st',
                            launch_image='li',
                            custom_data={'launch-image': ['li1', 'li2']}
                        )
                    ),
                )
            )
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'payload': {
                    'aps': {
                        'alert': {
                            'title': 't',
                            'subtitle': 'st',
                            'launch-image': [
                                'li1',
                                'li2'
                            ]
                        },
                    },
                }
            },
        }
        check_encoding(msg, expected)


class TestTimeout:

    def teardown(self):
        testutils.cleanup_apps()

    def _instrument_service(self, url, response):
        app = firebase_admin.get_app()
        fcm_service = messaging._get_messaging_service(app)
        recorder = []
        fcm_service._client.session.mount(
            url, testutils.MockAdapter(json.dumps(response), 200, recorder))
        return recorder

    def _check_timeout(self, recorder, timeout):
        assert len(recorder) == 1
        if timeout is None:
            assert recorder[0]._extra_kwargs['timeout'] is None
        else:
            assert recorder[0]._extra_kwargs['timeout'] == pytest.approx(timeout, 0.001)

    @pytest.mark.parametrize('options, timeout', [
        ({'httpTimeout': 4}, 4),
        ({'httpTimeout': None}, None),
        ({}, _http_client.DEFAULT_TIMEOUT_SECONDS),
    ])
    def test_send(self, options, timeout):
        cred = testutils.MockCredential()
        all_options = {'projectId': 'explicit-project-id'}
        all_options.update(options)
        firebase_admin.initialize_app(cred, all_options)
        recorder = self._instrument_service(
            'https://fcm.googleapis.com', {'name': 'message-id'})
        msg = messaging.Message(topic='foo')
        messaging.send(msg)
        self._check_timeout(recorder, timeout)

    @pytest.mark.parametrize('options, timeout', [
        ({'httpTimeout': 4}, 4),
        ({'httpTimeout': None}, None),
        ({}, _http_client.DEFAULT_TIMEOUT_SECONDS),
    ])
    def test_topic_management_custom_timeout(self, options, timeout):
        cred = testutils.MockCredential()
        all_options = {'projectId': 'explicit-project-id'}
        all_options.update(options)
        firebase_admin.initialize_app(cred, all_options)
        recorder = self._instrument_service(
            'https://iid.googleapis.com', {'results': [{}, {'error': 'error_reason'}]})
        messaging.subscribe_to_topic(['1'], 'a')
        self._check_timeout(recorder, timeout)


class TestSend:

    _DEFAULT_RESPONSE = json.dumps({'name': 'message-id'})
    _CLIENT_VERSION = 'fire-admin-python/{0}'.format(firebase_admin.__version__)

    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def _instrument_messaging_service(self, app=None, status=200, payload=_DEFAULT_RESPONSE):
        if not app:
            app = firebase_admin.get_app()
        fcm_service = messaging._get_messaging_service(app)
        recorder = []
        fcm_service._client.session.mount(
            'https://fcm.googleapis.com',
            testutils.MockAdapter(payload, status, recorder))
        return fcm_service, recorder

    def _get_url(self, project_id):
        return messaging._MessagingService.FCM_URL.format(project_id)

    def test_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
            with pytest.raises(ValueError):
                messaging.send(messaging.Message(topic='foo'), app=app)
        testutils.run_without_project_id(evaluate)

    @pytest.mark.parametrize('msg', NON_OBJECT_ARGS + [None])
    def test_invalid_send(self, msg):
        with pytest.raises(ValueError) as excinfo:
            messaging.send(msg)
        assert str(excinfo.value) == 'Message must be an instance of messaging.Message class.'

    def test_send_dry_run(self):
        _, recorder = self._instrument_messaging_service()
        msg = messaging.Message(topic='foo')
        msg_id = messaging.send(msg, dry_run=True)
        assert msg_id == 'message-id'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        assert recorder[0].headers['X-GOOG-API-FORMAT-VERSION'] == '2'
        assert recorder[0].headers['X-FIREBASE-CLIENT'] == self._CLIENT_VERSION
        body = {
            'message': messaging._MessagingService.encode_message(msg),
            'validate_only': True,
        }
        assert json.loads(recorder[0].body.decode()) == body

    def test_send(self):
        _, recorder = self._instrument_messaging_service()
        msg = messaging.Message(topic='foo')
        msg_id = messaging.send(msg)
        assert msg_id == 'message-id'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        assert recorder[0].headers['X-GOOG-API-FORMAT-VERSION'] == '2'
        assert recorder[0].headers['X-FIREBASE-CLIENT'] == self._CLIENT_VERSION
        body = {'message': messaging._MessagingService.encode_message(msg)}
        assert json.loads(recorder[0].body.decode()) == body

    @pytest.mark.parametrize('status,exc_type', HTTP_ERROR_CODES.items())
    def test_send_error(self, status, exc_type):
        _, recorder = self._instrument_messaging_service(status=status, payload='{}')
        msg = messaging.Message(topic='foo')
        with pytest.raises(exc_type) as excinfo:
            messaging.send(msg)
        expected = 'Unexpected HTTP response with status: {0}; body: {{}}'.format(status)
        check_exception(excinfo.value, expected, status)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        assert recorder[0].headers['X-GOOG-API-FORMAT-VERSION'] == '2'
        assert recorder[0].headers['X-FIREBASE-CLIENT'] == self._CLIENT_VERSION
        body = {'message': messaging._MessagingService.JSON_ENCODER.default(msg)}
        assert json.loads(recorder[0].body.decode()) == body

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_detailed_error(self, status):
        payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error'
            }
        })
        _, recorder = self._instrument_messaging_service(status=status, payload=payload)
        msg = messaging.Message(topic='foo')
        with pytest.raises(exceptions.InvalidArgumentError) as excinfo:
            messaging.send(msg)
        check_exception(excinfo.value, 'test error', status)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        body = {'message': messaging._MessagingService.JSON_ENCODER.default(msg)}
        assert json.loads(recorder[0].body.decode()) == body

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_canonical_error_code(self, status):
        payload = json.dumps({
            'error': {
                'status': 'NOT_FOUND',
                'message': 'test error'
            }
        })
        _, recorder = self._instrument_messaging_service(status=status, payload=payload)
        msg = messaging.Message(topic='foo')
        with pytest.raises(exceptions.NotFoundError) as excinfo:
            messaging.send(msg)
        check_exception(excinfo.value, 'test error', status)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        body = {'message': messaging._MessagingService.JSON_ENCODER.default(msg)}
        assert json.loads(recorder[0].body.decode()) == body

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    @pytest.mark.parametrize('fcm_error_code, exc_type', FCM_ERROR_CODES.items())
    def test_send_fcm_error_code(self, status, fcm_error_code, exc_type):
        payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error',
                'details': [
                    {
                        '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError',
                        'errorCode': fcm_error_code,
                    },
                ],
            }
        })
        _, recorder = self._instrument_messaging_service(status=status, payload=payload)
        msg = messaging.Message(topic='foo')
        with pytest.raises(exc_type) as excinfo:
            messaging.send(msg)
        check_exception(excinfo.value, 'test error', status)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        body = {'message': messaging._MessagingService.JSON_ENCODER.default(msg)}
        assert json.loads(recorder[0].body.decode()) == body

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_unknown_fcm_error_code(self, status):
        payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error',
                'details': [
                    {
                        '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError',
                        'errorCode': 'SOME_UNKNOWN_CODE',
                    },
                ],
            }
        })
        _, recorder = self._instrument_messaging_service(status=status, payload=payload)
        msg = messaging.Message(topic='foo')
        with pytest.raises(exceptions.InvalidArgumentError) as excinfo:
            messaging.send(msg)
        check_exception(excinfo.value, 'test error', status)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        body = {'message': messaging._MessagingService.JSON_ENCODER.default(msg)}
        assert json.loads(recorder[0].body.decode()) == body


class _HttpMockException:

    def __init__(self, exc):
        self._exc = exc

    def request(self, url, **kwargs):
        raise self._exc


class TestBatch:

    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def _instrument_batch_messaging_service(self, app=None, status=200, payload='', exc=None):
        def build_mock_transport(_):
            if exc:
                return _HttpMockException(exc)

            if status == 200:
                content_type = 'multipart/mixed; boundary=boundary'
            else:
                content_type = 'application/json'
            return http.HttpMockSequence([
                ({'status': str(status), 'content-type': content_type}, payload),
            ])

        if not app:
            app = firebase_admin.get_app()

        fcm_service = messaging._get_messaging_service(app)
        fcm_service._build_transport = build_mock_transport
        return fcm_service

    def _batch_payload(self, payloads):
        # payloads should be a list of (status_code, content) tuples
        payload = ''
        _playload_format = """--boundary\r\nContent-Type: application/http\r\n\
Content-ID: <uuid + {}>\r\n\r\nHTTP/1.1 {} Success\r\n\
Content-Type: application/json; charset=UTF-8\r\n\r\n{}\r\n\r\n"""
        for (index, (status_code, content)) in enumerate(payloads):
            payload += _playload_format.format(str(index + 1), str(status_code), content)
        payload += '--boundary--'
        return payload


class TestSendAll(TestBatch):

    def test_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
            with pytest.raises(ValueError):
                messaging.send_all([messaging.Message(topic='foo')], app=app)
        testutils.run_without_project_id(evaluate)

    @pytest.mark.parametrize('msg', NON_LIST_ARGS)
    def test_invalid_send_all(self, msg):
        with pytest.raises(ValueError) as excinfo:
            messaging.send_all(msg)
        if isinstance(msg, list):
            expected = 'Message must be an instance of messaging.Message class.'
            assert str(excinfo.value) == expected
        else:
            expected = 'messages must be a list of messaging.Message instances.'
            assert str(excinfo.value) == expected

    def test_invalid_over_500(self):
        msg = messaging.Message(topic='foo')
        with pytest.raises(ValueError) as excinfo:
            messaging.send_all([msg for _ in range(0, 501)])
        expected = 'messages must not contain more than 500 elements.'
        assert str(excinfo.value) == expected

    def test_send_all(self):
        payload = json.dumps({'name': 'message-id'})
        _ = self._instrument_batch_messaging_service(
            payload=self._batch_payload([(200, payload), (200, payload)]))
        msg = messaging.Message(topic='foo')
        batch_response = messaging.send_all([msg, msg], dry_run=True)
        assert batch_response.success_count == 2
        assert batch_response.failure_count == 0
        assert len(batch_response.responses) == 2
        assert [r.message_id for r in batch_response.responses] == ['message-id', 'message-id']
        assert all([r.success for r in batch_response.responses])
        assert not any([r.exception for r in batch_response.responses])

    def test_send_all_with_positional_param_enforcement(self):
        payload = json.dumps({'name': 'message-id'})
        _ = self._instrument_batch_messaging_service(
            payload=self._batch_payload([(200, payload), (200, payload)]))
        msg = messaging.Message(topic='foo')

        enforcement = _helpers.positional_parameters_enforcement
        _helpers.positional_parameters_enforcement = _helpers.POSITIONAL_EXCEPTION
        try:
            batch_response = messaging.send_all([msg, msg], dry_run=True)
            assert batch_response.success_count == 2
        finally:
            _helpers.positional_parameters_enforcement = enforcement

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_all_detailed_error(self, status):
        success_payload = json.dumps({'name': 'message-id'})
        error_payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error'
            }
        })
        _ = self._instrument_batch_messaging_service(
            payload=self._batch_payload([(200, success_payload), (status, error_payload)]))
        msg = messaging.Message(topic='foo')
        batch_response = messaging.send_all([msg, msg])
        assert batch_response.success_count == 1
        assert batch_response.failure_count == 1
        assert len(batch_response.responses) == 2
        success_response = batch_response.responses[0]
        assert success_response.message_id == 'message-id'
        assert success_response.success is True
        assert success_response.exception is None
        error_response = batch_response.responses[1]
        assert error_response.message_id is None
        assert error_response.success is False
        exception = error_response.exception
        assert isinstance(exception, exceptions.InvalidArgumentError)
        check_exception(exception, 'test error', status)

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_all_canonical_error_code(self, status):
        success_payload = json.dumps({'name': 'message-id'})
        error_payload = json.dumps({
            'error': {
                'status': 'NOT_FOUND',
                'message': 'test error'
            }
        })
        _ = self._instrument_batch_messaging_service(
            payload=self._batch_payload([(200, success_payload), (status, error_payload)]))
        msg = messaging.Message(topic='foo')
        batch_response = messaging.send_all([msg, msg])
        assert batch_response.success_count == 1
        assert batch_response.failure_count == 1
        assert len(batch_response.responses) == 2
        success_response = batch_response.responses[0]
        assert success_response.message_id == 'message-id'
        assert success_response.success is True
        assert success_response.exception is None
        error_response = batch_response.responses[1]
        assert error_response.message_id is None
        assert error_response.success is False
        exception = error_response.exception
        assert isinstance(exception, exceptions.NotFoundError)
        check_exception(exception, 'test error', status)

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    @pytest.mark.parametrize('fcm_error_code, exc_type', FCM_ERROR_CODES.items())
    def test_send_all_fcm_error_code(self, status, fcm_error_code, exc_type):
        success_payload = json.dumps({'name': 'message-id'})
        error_payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error',
                'details': [
                    {
                        '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError',
                        'errorCode': fcm_error_code,
                    },
                ],
            }
        })
        _ = self._instrument_batch_messaging_service(
            payload=self._batch_payload([(200, success_payload), (status, error_payload)]))
        msg = messaging.Message(topic='foo')
        batch_response = messaging.send_all([msg, msg])
        assert batch_response.success_count == 1
        assert batch_response.failure_count == 1
        assert len(batch_response.responses) == 2
        success_response = batch_response.responses[0]
        assert success_response.message_id == 'message-id'
        assert success_response.success is True
        assert success_response.exception is None
        error_response = batch_response.responses[1]
        assert error_response.message_id is None
        assert error_response.success is False
        exception = error_response.exception
        assert isinstance(exception, exc_type)
        check_exception(exception, 'test error', status)

    @pytest.mark.parametrize('status, exc_type', HTTP_ERROR_CODES.items())
    def test_send_all_batch_error(self, status, exc_type):
        _ = self._instrument_batch_messaging_service(status=status, payload='{}')
        msg = messaging.Message(topic='foo')
        with pytest.raises(exc_type) as excinfo:
            messaging.send_all([msg])
        expected = 'Unexpected HTTP response with status: {0}; body: {{}}'.format(status)
        check_exception(excinfo.value, expected, status)

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_all_batch_detailed_error(self, status):
        payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error'
            }
        })
        _ = self._instrument_batch_messaging_service(status=status, payload=payload)
        msg = messaging.Message(topic='foo')
        with pytest.raises(exceptions.InvalidArgumentError) as excinfo:
            messaging.send_all([msg])
        check_exception(excinfo.value, 'test error', status)

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_all_batch_canonical_error_code(self, status):
        payload = json.dumps({
            'error': {
                'status': 'NOT_FOUND',
                'message': 'test error'
            }
        })
        _ = self._instrument_batch_messaging_service(status=status, payload=payload)
        msg = messaging.Message(topic='foo')
        with pytest.raises(exceptions.NotFoundError) as excinfo:
            messaging.send_all([msg])
        check_exception(excinfo.value, 'test error', status)

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_all_batch_fcm_error_code(self, status):
        payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error',
                'details': [
                    {
                        '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError',
                        'errorCode': 'UNREGISTERED',
                    },
                ],
            }
        })
        _ = self._instrument_batch_messaging_service(status=status, payload=payload)
        msg = messaging.Message(topic='foo')
        with pytest.raises(messaging.UnregisteredError) as excinfo:
            messaging.send_all([msg])
        check_exception(excinfo.value, 'test error', status)

    def test_send_all_runtime_exception(self):
        exc = BrokenPipeError('Test error')
        _ = self._instrument_batch_messaging_service(exc=exc)
        msg = messaging.Message(topic='foo')

        with pytest.raises(exceptions.UnknownError) as excinfo:
            messaging.send_all([msg])

        expected = 'Unknown error while making a remote service call: Test error'
        assert str(excinfo.value) == expected
        assert excinfo.value.cause is exc
        assert excinfo.value.http_response is None

    def test_send_transport_init(self):
        def track_call_count(build_transport):
            def wrapper(credential):
                wrapper.calls += 1
                return build_transport(credential)
            wrapper.calls = 0
            return wrapper

        payload = json.dumps({'name': 'message-id'})
        fcm_service = self._instrument_batch_messaging_service(
            payload=self._batch_payload([(200, payload), (200, payload)]))
        build_mock_transport = fcm_service._build_transport
        fcm_service._build_transport = track_call_count(build_mock_transport)
        msg = messaging.Message(topic='foo')

        batch_response = messaging.send_all([msg, msg], dry_run=True)
        assert batch_response.success_count == 2
        assert fcm_service._build_transport.calls == 1

        batch_response = messaging.send_all([msg, msg], dry_run=True)
        assert batch_response.success_count == 2
        assert fcm_service._build_transport.calls == 2


class TestSendMulticast(TestBatch):

    def test_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
            with pytest.raises(ValueError):
                messaging.send_all([messaging.Message(topic='foo')], app=app)
        testutils.run_without_project_id(evaluate)

    @pytest.mark.parametrize('msg', NON_LIST_ARGS)
    def test_invalid_send_multicast(self, msg):
        with pytest.raises(ValueError) as excinfo:
            messaging.send_multicast(msg)
        expected = 'Message must be an instance of messaging.MulticastMessage class.'
        assert str(excinfo.value) == expected

    def test_send_multicast(self):
        payload = json.dumps({'name': 'message-id'})
        _ = self._instrument_batch_messaging_service(
            payload=self._batch_payload([(200, payload), (200, payload)]))
        msg = messaging.MulticastMessage(tokens=['foo', 'foo'])
        batch_response = messaging.send_multicast(msg, dry_run=True)
        assert batch_response.success_count == 2
        assert batch_response.failure_count == 0
        assert len(batch_response.responses) == 2
        assert [r.message_id for r in batch_response.responses] == ['message-id', 'message-id']
        assert all([r.success for r in batch_response.responses])
        assert not any([r.exception for r in batch_response.responses])

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_multicast_detailed_error(self, status):
        success_payload = json.dumps({'name': 'message-id'})
        error_payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error'
            }
        })
        _ = self._instrument_batch_messaging_service(
            payload=self._batch_payload([(200, success_payload), (status, error_payload)]))
        msg = messaging.MulticastMessage(tokens=['foo', 'foo'])
        batch_response = messaging.send_multicast(msg)
        assert batch_response.success_count == 1
        assert batch_response.failure_count == 1
        assert len(batch_response.responses) == 2
        success_response = batch_response.responses[0]
        assert success_response.message_id == 'message-id'
        assert success_response.success is True
        assert success_response.exception is None
        error_response = batch_response.responses[1]
        assert error_response.message_id is None
        assert error_response.success is False
        assert error_response.exception is not None
        exception = error_response.exception
        assert isinstance(exception, exceptions.InvalidArgumentError)
        check_exception(exception, 'test error', status)

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_multicast_canonical_error_code(self, status):
        success_payload = json.dumps({'name': 'message-id'})
        error_payload = json.dumps({
            'error': {
                'status': 'NOT_FOUND',
                'message': 'test error'
            }
        })
        _ = self._instrument_batch_messaging_service(
            payload=self._batch_payload([(200, success_payload), (status, error_payload)]))
        msg = messaging.MulticastMessage(tokens=['foo', 'foo'])
        batch_response = messaging.send_multicast(msg)
        assert batch_response.success_count == 1
        assert batch_response.failure_count == 1
        assert len(batch_response.responses) == 2
        success_response = batch_response.responses[0]
        assert success_response.message_id == 'message-id'
        assert success_response.success is True
        assert success_response.exception is None
        error_response = batch_response.responses[1]
        assert error_response.message_id is None
        assert error_response.success is False
        assert error_response.exception is not None
        exception = error_response.exception
        assert isinstance(exception, exceptions.NotFoundError)
        check_exception(exception, 'test error', status)

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_multicast_fcm_error_code(self, status):
        success_payload = json.dumps({'name': 'message-id'})
        error_payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error',
                'details': [
                    {
                        '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError',
                        'errorCode': 'UNREGISTERED',
                    },
                ],
            }
        })
        _ = self._instrument_batch_messaging_service(
            payload=self._batch_payload([(200, success_payload), (status, error_payload)]))
        msg = messaging.MulticastMessage(tokens=['foo', 'foo'])
        batch_response = messaging.send_multicast(msg)
        assert batch_response.success_count == 1
        assert batch_response.failure_count == 1
        assert len(batch_response.responses) == 2
        success_response = batch_response.responses[0]
        assert success_response.message_id == 'message-id'
        assert success_response.success is True
        assert success_response.exception is None
        error_response = batch_response.responses[1]
        assert error_response.message_id is None
        assert error_response.success is False
        assert error_response.exception is not None
        exception = error_response.exception
        assert isinstance(exception, messaging.UnregisteredError)
        check_exception(exception, 'test error', status)

    @pytest.mark.parametrize('status, exc_type', HTTP_ERROR_CODES.items())
    def test_send_multicast_batch_error(self, status, exc_type):
        _ = self._instrument_batch_messaging_service(status=status, payload='{}')
        msg = messaging.MulticastMessage(tokens=['foo'])
        with pytest.raises(exc_type) as excinfo:
            messaging.send_multicast(msg)
        expected = 'Unexpected HTTP response with status: {0}; body: {{}}'.format(status)
        check_exception(excinfo.value, expected, status)

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_multicast_batch_detailed_error(self, status):
        payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error'
            }
        })
        _ = self._instrument_batch_messaging_service(status=status, payload=payload)
        msg = messaging.MulticastMessage(tokens=['foo'])
        with pytest.raises(exceptions.InvalidArgumentError) as excinfo:
            messaging.send_multicast(msg)
        check_exception(excinfo.value, 'test error', status)

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_multicast_batch_canonical_error_code(self, status):
        payload = json.dumps({
            'error': {
                'status': 'NOT_FOUND',
                'message': 'test error'
            }
        })
        _ = self._instrument_batch_messaging_service(status=status, payload=payload)
        msg = messaging.MulticastMessage(tokens=['foo'])
        with pytest.raises(exceptions.NotFoundError) as excinfo:
            messaging.send_multicast(msg)
        check_exception(excinfo.value, 'test error', status)

    @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    def test_send_multicast_batch_fcm_error_code(self, status):
        payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error',
                'details': [
                    {
                        '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError',
                        'errorCode': 'UNREGISTERED',
                    },
                ],
            }
        })
        _ = self._instrument_batch_messaging_service(status=status, payload=payload)
        msg = messaging.MulticastMessage(tokens=['foo'])
        with pytest.raises(messaging.UnregisteredError) as excinfo:
            messaging.send_multicast(msg)
        check_exception(excinfo.value, 'test error', status)

    def test_send_multicast_runtime_exception(self):
        exc = BrokenPipeError('Test error')
        _ = self._instrument_batch_messaging_service(exc=exc)
        msg = messaging.MulticastMessage(tokens=['foo'])

        with pytest.raises(exceptions.UnknownError) as excinfo:
            messaging.send_multicast(msg)

        expected = 'Unknown error while making a remote service call: Test error'
        assert str(excinfo.value) == expected
        assert excinfo.value.cause is exc
        assert excinfo.value.http_response is None


class TestTopicManagement:

    _DEFAULT_RESPONSE = json.dumps({'results': [{}, {'error': 'error_reason'}]})
    _DEFAULT_ERROR_RESPONSE = json.dumps({'error': 'error_reason'})
    _VALID_ARGS = [
        # (tokens, topic, expected)
        (
            ['foo', 'bar'],
            'test-topic',
            {'to': '/topics/test-topic', 'registration_tokens': ['foo', 'bar']}
        ),
        (
            'foo',
            '/topics/test-topic',
            {'to': '/topics/test-topic', 'registration_tokens': ['foo']}
        ),
    ]

    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def _instrument_iid_service(self, app=None, status=200, payload=_DEFAULT_RESPONSE):
        if not app:
            app = firebase_admin.get_app()
        fcm_service = messaging._get_messaging_service(app)
        recorder = []
        fcm_service._client.session.mount(
            'https://iid.googleapis.com',
            testutils.MockAdapter(payload, status, recorder))
        return fcm_service, recorder

    def _get_url(self, path):
        return '{0}/{1}'.format(messaging._MessagingService.IID_URL, path)

    @pytest.mark.parametrize('tokens', [None, '', list(), dict(), tuple()])
    def test_invalid_tokens(self, tokens):
        expected = 'Tokens must be a string or a non-empty list of strings.'
        if isinstance(tokens, str):
            expected = 'Tokens must be non-empty strings.'

        with pytest.raises(ValueError) as excinfo:
            messaging.subscribe_to_topic(tokens, 'test-topic')
        assert str(excinfo.value) == expected

        with pytest.raises(ValueError) as excinfo:
            messaging.unsubscribe_from_topic(tokens, 'test-topic')
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('topic', NON_STRING_ARGS + [None, ''])
    def test_invalid_topic(self, topic):
        expected = 'Topic must be a non-empty string.'
        with pytest.raises(ValueError) as excinfo:
            messaging.subscribe_to_topic('test-token', topic)
        assert str(excinfo.value) == expected

        with pytest.raises(ValueError) as excinfo:
            messaging.unsubscribe_from_topic('test-tokens', topic)
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('args', _VALID_ARGS)
    def test_subscribe_to_topic(self, args):
        _, recorder = self._instrument_iid_service()
        resp = messaging.subscribe_to_topic(args[0], args[1])
        self._check_response(resp)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('iid/v1:batchAdd')
        assert json.loads(recorder[0].body.decode()) == args[2]

    @pytest.mark.parametrize('status, exc_type', HTTP_ERROR_CODES.items())
    def test_subscribe_to_topic_error(self, status, exc_type):
        _, recorder = self._instrument_iid_service(
            status=status, payload=self._DEFAULT_ERROR_RESPONSE)
        with pytest.raises(exc_type) as excinfo:
            messaging.subscribe_to_topic('foo', 'test-topic')
        assert str(excinfo.value) == 'Error while calling the IID service: error_reason'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('iid/v1:batchAdd')

    @pytest.mark.parametrize('status, exc_type', HTTP_ERROR_CODES.items())
    def test_subscribe_to_topic_non_json_error(self, status, exc_type):
        _, recorder = self._instrument_iid_service(status=status, payload='not json')
        with pytest.raises(exc_type) as excinfo:
            messaging.subscribe_to_topic('foo', 'test-topic')
        reason = 'Unexpected HTTP response with status: {0}; body: not json'.format(status)
        assert str(excinfo.value) == reason
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('iid/v1:batchAdd')

    @pytest.mark.parametrize('args', _VALID_ARGS)
    def test_unsubscribe_from_topic(self, args):
        _, recorder = self._instrument_iid_service()
        resp = messaging.unsubscribe_from_topic(args[0], args[1])
        self._check_response(resp)
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('iid/v1:batchRemove')
        assert json.loads(recorder[0].body.decode()) == args[2]

    @pytest.mark.parametrize('status, exc_type', HTTP_ERROR_CODES.items())
    def test_unsubscribe_from_topic_error(self, status, exc_type):
        _, recorder = self._instrument_iid_service(
            status=status, payload=self._DEFAULT_ERROR_RESPONSE)
        with pytest.raises(exc_type) as excinfo:
            messaging.unsubscribe_from_topic('foo', 'test-topic')
        assert str(excinfo.value) == 'Error while calling the IID service: error_reason'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('iid/v1:batchRemove')

    @pytest.mark.parametrize('status, exc_type', HTTP_ERROR_CODES.items())
    def test_unsubscribe_from_topic_non_json_error(self, status, exc_type):
        _, recorder = self._instrument_iid_service(status=status, payload='not json')
        with pytest.raises(exc_type) as excinfo:
            messaging.unsubscribe_from_topic('foo', 'test-topic')
        reason = 'Unexpected HTTP response with status: {0}; body: not json'.format(status)
        assert str(excinfo.value) == reason
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('iid/v1:batchRemove')

    def _check_response(self, resp):
        assert resp.success_count == 1
        assert resp.failure_count == 1
        assert len(resp.errors) == 1
        assert resp.errors[0].index == 1
        assert resp.errors[0].reason == 'error_reason'
