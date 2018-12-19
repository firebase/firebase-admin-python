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

import pytest
import six

import firebase_admin
from firebase_admin import messaging
from tests import testutils


NON_STRING_ARGS = [list(), tuple(), dict(), True, False, 1, 0]
NON_DICT_ARGS = ['', list(), tuple(), True, False, 1, 0, {1: 'foo'}, {'foo': 1}]
NON_OBJECT_ARGS = [list(), tuple(), dict(), 'foo', 0, 1, True, False]
NON_LIST_ARGS = ['', tuple(), dict(), True, False, 1, 0, [1], ['foo', 1]]
HTTP_ERRORS = [400, 404, 500]


def check_encoding(msg, expected=None):
    encoded = messaging._MessagingService.encode_message(msg)
    if expected:
        assert encoded == expected


class TestMessageEncoder(object):

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


class TestNotificationEncoder(object):

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


class TestAndroidConfigEncoder(object):

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
        if isinstance(data, six.string_types):
            assert str(excinfo.value) == 'AndroidConfig.priority must be "high" or "normal".'
        else:
            assert str(excinfo.value) == 'AndroidConfig.priority must be a non-empty string.'

    @pytest.mark.parametrize('data', ['1.23s', list(), tuple(), dict(), -1.23])
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
                data={'k1': 'v1', 'k2': 'v2'}
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


class TestAndroidNotificationEncoder(object):

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
        if isinstance(data, six.string_types):
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
    def test_invalid_channek_id(self, data):
        notification = messaging.AndroidNotification(channel_id=data)
        excinfo = self._check_notification(notification)
        assert str(excinfo.value) == 'AndroidNotification.channel_id must be a string.'

    def test_android_notification(self):
        msg = messaging.Message(
            topic='topic',
            android=messaging.AndroidConfig(
                notification=messaging.AndroidNotification(
                    title='t', body='b', icon='i', color='#112233', sound='s', tag='t',
                    click_action='ca', title_loc_key='tlk', body_loc_key='blk',
                    title_loc_args=['t1', 't2'], body_loc_args=['b1', 'b2'], channel_id='c'
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
                    'channel_id' : 'c',
                },
            },
        }
        check_encoding(msg, expected)


class TestWebpushConfigEncoder(object):

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
                data={'k1': 'v1', 'k2': 'v2'}
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


class TestWebpushNotificationEncoder(object):

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
        if isinstance(data, six.string_types):
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


class TestAPNSConfigEncoder(object):

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
            apns=messaging.APNSConfig(headers={'h1': 'v1', 'h2': 'v2'})
        )
        expected = {
            'topic': 'topic',
            'apns': {
                'headers': {
                    'h1': 'v1',
                    'h2': 'v2',
                },
            },
        }
        check_encoding(msg, expected)


class TestAPNSPayloadEncoder(object):

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


class TestApsEncoder(object):

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


class TestApsSoundEncoder(object):

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


class TestApsAlertEncoder(object):

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


class TestTimeout(object):

    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'httpTimeout': 4, 'projectId': 'explicit-project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def setup(self):
        app = firebase_admin.get_app()
        self.fcm_service = messaging._get_messaging_service(app)
        self.recorder = []

    def test_send(self):
        self.fcm_service._client.session.mount(
            'https://fcm.googleapis.com',
            testutils.MockAdapter(json.dumps({'name': 'message-id'}), 200, self.recorder))
        msg = messaging.Message(topic='foo')
        messaging.send(msg)
        assert len(self.recorder) == 1
        assert self.recorder[0]._extra_kwargs['timeout'] == 4

    def test_topic_management_timeout(self):
        self.fcm_service._client.session.mount(
            'https://iid.googleapis.com',
            testutils.MockAdapter(
                json.dumps({'results': [{}, {'error': 'error_reason'}]}),
                200,
                self.recorder)
        )
        messaging.subscribe_to_topic(['1'], 'a')
        assert len(self.recorder) == 1
        assert self.recorder[0]._extra_kwargs['timeout'] == 4


class TestSend(object):

    _DEFAULT_RESPONSE = json.dumps({'name': 'message-id'})

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
        assert recorder[0]._extra_kwargs['timeout'] is None
        body = {'message': messaging._MessagingService.encode_message(msg)}
        assert json.loads(recorder[0].body.decode()) == body

    @pytest.mark.parametrize('status', HTTP_ERRORS)
    def test_send_error(self, status):
        _, recorder = self._instrument_messaging_service(status=status, payload='{}')
        msg = messaging.Message(topic='foo')
        with pytest.raises(messaging.ApiCallError) as excinfo:
            messaging.send(msg)
        expected = 'Unexpected HTTP response with status: {0}; body: {{}}'.format(status)
        assert str(excinfo.value) == expected
        assert str(excinfo.value.code) == messaging._MessagingService.UNKNOWN_ERROR
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        assert recorder[0].headers['X-GOOG-API-FORMAT-VERSION'] == '2'
        body = {'message': messaging._MessagingService.JSON_ENCODER.default(msg)}
        assert json.loads(recorder[0].body.decode()) == body

    @pytest.mark.parametrize('status', HTTP_ERRORS)
    def test_send_detailed_error(self, status):
        payload = json.dumps({
            'error': {
                'status': 'INVALID_ARGUMENT',
                'message': 'test error'
            }
        })
        _, recorder = self._instrument_messaging_service(status=status, payload=payload)
        msg = messaging.Message(topic='foo')
        with pytest.raises(messaging.ApiCallError) as excinfo:
            messaging.send(msg)
        assert str(excinfo.value) == 'test error'
        assert str(excinfo.value.code) == 'invalid-argument'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        body = {'message': messaging._MessagingService.JSON_ENCODER.default(msg)}
        assert json.loads(recorder[0].body.decode()) == body

    @pytest.mark.parametrize('status', HTTP_ERRORS)
    def test_send_canonical_error_code(self, status):
        payload = json.dumps({
            'error': {
                'status': 'NOT_FOUND',
                'message': 'test error'
            }
        })
        _, recorder = self._instrument_messaging_service(status=status, payload=payload)
        msg = messaging.Message(topic='foo')
        with pytest.raises(messaging.ApiCallError) as excinfo:
            messaging.send(msg)
        assert str(excinfo.value) == 'test error'
        assert str(excinfo.value.code) == 'registration-token-not-registered'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        body = {'message': messaging._MessagingService.JSON_ENCODER.default(msg)}
        assert json.loads(recorder[0].body.decode()) == body

    @pytest.mark.parametrize('status', HTTP_ERRORS)
    def test_send_fcm_error_code(self, status):
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
        _, recorder = self._instrument_messaging_service(status=status, payload=payload)
        msg = messaging.Message(topic='foo')
        with pytest.raises(messaging.ApiCallError) as excinfo:
            messaging.send(msg)
        assert str(excinfo.value) == 'test error'
        assert str(excinfo.value.code) == 'registration-token-not-registered'
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('explicit-project-id')
        body = {'message': messaging._MessagingService.JSON_ENCODER.default(msg)}
        assert json.loads(recorder[0].body.decode()) == body


class TestTopicManagement(object):

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
        if isinstance(tokens, six.string_types):
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

    @pytest.mark.parametrize('status', HTTP_ERRORS)
    def test_subscribe_to_topic_error(self, status):
        _, recorder = self._instrument_iid_service(
            status=status, payload=self._DEFAULT_ERROR_RESPONSE)
        with pytest.raises(messaging.ApiCallError) as excinfo:
            messaging.subscribe_to_topic('foo', 'test-topic')
        assert str(excinfo.value) == 'error_reason'
        code = messaging._MessagingService.IID_ERROR_CODES.get(
            status, messaging._MessagingService.UNKNOWN_ERROR)
        assert excinfo.value.code == code
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('iid/v1:batchAdd')

    @pytest.mark.parametrize('status', HTTP_ERRORS)
    def test_subscribe_to_topic_non_json_error(self, status):
        _, recorder = self._instrument_iid_service(status=status, payload='not json')
        with pytest.raises(messaging.ApiCallError) as excinfo:
            messaging.subscribe_to_topic('foo', 'test-topic')
        reason = 'Unexpected HTTP response with status: {0}; body: not json'.format(status)
        code = messaging._MessagingService.IID_ERROR_CODES.get(
            status, messaging._MessagingService.UNKNOWN_ERROR)
        assert str(excinfo.value) == reason
        assert excinfo.value.code == code
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

    @pytest.mark.parametrize('status', HTTP_ERRORS)
    def test_unsubscribe_from_topic_error(self, status):
        _, recorder = self._instrument_iid_service(
            status=status, payload=self._DEFAULT_ERROR_RESPONSE)
        with pytest.raises(messaging.ApiCallError) as excinfo:
            messaging.unsubscribe_from_topic('foo', 'test-topic')
        assert str(excinfo.value) == 'error_reason'
        code = messaging._MessagingService.IID_ERROR_CODES.get(
            status, messaging._MessagingService.UNKNOWN_ERROR)
        assert excinfo.value.code == code
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('iid/v1:batchRemove')

    @pytest.mark.parametrize('status', HTTP_ERRORS)
    def test_unsubscribe_from_topic_non_json_error(self, status):
        _, recorder = self._instrument_iid_service(status=status, payload='not json')
        with pytest.raises(messaging.ApiCallError) as excinfo:
            messaging.unsubscribe_from_topic('foo', 'test-topic')
        reason = 'Unexpected HTTP response with status: {0}; body: not json'.format(status)
        code = messaging._MessagingService.IID_ERROR_CODES.get(
            status, messaging._MessagingService.UNKNOWN_ERROR)
        assert str(excinfo.value) == reason
        assert excinfo.value.code == code
        assert len(recorder) == 1
        assert recorder[0].method == 'POST'
        assert recorder[0].url == self._get_url('iid/v1:batchRemove')

    def _check_response(self, resp):
        assert resp.success_count == 1
        assert resp.failure_count == 1
        assert len(resp.errors) == 1
        assert resp.errors[0].index == 1
        assert resp.errors[0].reason == 'error_reason'
