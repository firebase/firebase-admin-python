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

"""Types and utilities used by the messaging (FCM) module."""

import datetime
import json
import math
import numbers
import re

import six


class Message(object):
    """A message that can be sent via Firebase Cloud Messaging.

    Contains payload information as well as recipient information. In particular, the message must
    contain exactly one of token, topic or condition fields.

    Args:
        data: A dictionary of data fields (optional). All keys and values in the dictionary must be
            strings.
        notification: An instance of ``messaging.Notification`` (optional).
        android: An instance of ``messaging.AndroidConfig`` (optional).
        webpush: An instance of ``messaging.WebpushConfig`` (optional).
        apns: An instance of ``messaging.ApnsConfig`` (optional).
        token: The registration token of the device to which the message should be sent (optional).
        topic: Name of the FCM topic to which the message should be sent (optional). Topic name
            may contain the ``/topics/`` prefix.
        condition: The FCM condition to which the message should be sent (optional).
    """

    def __init__(self, data=None, notification=None, android=None, webpush=None, apns=None,
                 token=None, topic=None, condition=None):
        self.data = data
        self.notification = notification
        self.android = android
        self.webpush = webpush
        self.apns = apns
        self.token = token
        self.topic = topic
        self.condition = condition


class Notification(object):
    """A notification that can be included in a message.

    Args:
        title: Title of the notification (optional).
        body: Body of the notification (optional).
    """

    def __init__(self, title=None, body=None):
        self.title = title
        self.body = body


class AndroidConfig(object):
    """Android-specific options that can be included in a message.

    Args:
        collapse_key: Collapse key string for the message (optional). This is an identifier for a
            group of messages that can be collapsed, so that only the last message is sent when
            delivery can be resumed. A maximum of 4 different collapse keys may be active at a
            given time.
        priority: Priority of the message (optional). Must be one of ``high`` or ``normal``.
        ttl: The time-to-live duration of the message (optional). This can be specified
            as a numeric seconds value or a ``datetime.timedelta`` instance.
        restricted_package_name: The package name of the application where the registration tokens
            must match in order to receive the message (optional).
        data: A dictionary of data fields (optional). All keys and values in the dictionary must be
            strings. When specified, overrides any data fields set via ``Message.data``.
        notification: A ``messaging.AndroidNotification`` to be included in the message (optional).
    """

    def __init__(self, collapse_key=None, priority=None, ttl=None, restricted_package_name=None,
                 data=None, notification=None):
        self.collapse_key = collapse_key
        self.priority = priority
        self.ttl = ttl
        self.restricted_package_name = restricted_package_name
        self.data = data
        self.notification = notification


class AndroidNotification(object):
    """Android-specific notification parameters.

    Args:
        title: Title of the notification (optional). If specified, overrides the title set via
            ``messaging.Notification``.
        body: Body of the notification (optional). If specified, overrides the body set via
            ``messaging.Notification``.
        icon: Icon of the notification (optional).
        color: Color of the notification icon expressed in ``#rrggbb`` form (optional).
        sound: Sound to be played when the device receives the notification (optional). This is
            usually the file name of the sound resource.
        tag: Tag of the notification (optional). This is an identifier used to replace existing
            notifications in the notification drawer. If not specified, each request creates a new
            notification.
        click_action: The action associated with a user click on the notification (optional). If
            specified, an activity with a matching intent filter is launched when a user clicks on
            the notification.
        body_loc_key: Key of the body string in the app's string resources to use to localize the
            body text (optional).
        body_loc_args: A list of resource keys that will be used in place of the format specifiers
            in ``body_loc_key`` (optional).
        title_loc_key: Key of the title string in the app's string resources to use to localize the
            title text (optional).
        title_loc_args: A list of resource keys that will be used in place of the format specifiers
            in ``title_loc_key`` (optional).
        channel_id: channel_id of the notification (optional).
    """

    def __init__(self, title=None, body=None, icon=None, color=None, sound=None, tag=None,
                 click_action=None, body_loc_key=None, body_loc_args=None, title_loc_key=None,
                 title_loc_args=None, channel_id=None):
        self.title = title
        self.body = body
        self.icon = icon
        self.color = color
        self.sound = sound
        self.tag = tag
        self.click_action = click_action
        self.body_loc_key = body_loc_key
        self.body_loc_args = body_loc_args
        self.title_loc_key = title_loc_key
        self.title_loc_args = title_loc_args
        self.channel_id = channel_id


class WebpushConfig(object):
    """Webpush-specific options that can be included in a message.

    Args:
        headers: A dictionary of headers (optional). Refer `Webpush Specification`_ for supported
            headers.
        data: A dictionary of data fields (optional). All keys and values in the dictionary must be
            strings. When specified, overrides any data fields set via ``Message.data``.
        notification: A ``messaging.WebpushNotification`` to be included in the message (optional).
        fcm_options: A ``messaging.WebpushFcmOptions`` instance to be included in the messsage
            (optional).

    .. _Webpush Specification: https://tools.ietf.org/html/rfc8030#section-5
    """

    def __init__(self, headers=None, data=None, notification=None, fcm_options=None):
        self.headers = headers
        self.data = data
        self.notification = notification
        self.fcm_options = fcm_options


class WebpushNotificationAction(object):
    """An action available to the users when the notification is presented.

    Args:
        action: Action string.
        title: Title string.
        icon: Icon URL for the action (optional).
    """

    def __init__(self, action, title, icon=None):
        self.action = action
        self.title = title
        self.icon = icon


class WebpushNotification(object):
    """Webpush-specific notification parameters.

    Refer to the `Notification Reference`_ for more information.

    Args:
        title: Title of the notification (optional). If specified, overrides the title set via
            ``messaging.Notification``.
        body: Body of the notification (optional). If specified, overrides the body set via
            ``messaging.Notification``.
        icon: Icon URL of the notification (optional).
        actions: A list of ``messaging.WebpushNotificationAction`` instances (optional).
        badge: URL of the image used to represent the notification when there is
            not enough space to display the notification itself (optional).
        data: Any arbitrary JSON data that should be associated with the notification (optional).
        direction: The direction in which to display the notification (optional). Must be either
            'auto', 'ltr' or 'rtl'.
        image: The URL of an image to be displayed in the notification (optional).
        language: Notification language (optional).
        renotify: A boolean indicating whether the user should be notified after a new
            notification replaces an old one (optional).
        require_interaction: A boolean indicating whether a notification should remain active
            until the user clicks or dismisses it, rather than closing automatically (optional).
        silent: ``True`` to indicate that the notification should be silent (optional).
        tag: An identifying tag on the notification (optional).
        timestamp_millis: A timestamp value in milliseconds on the notification (optional).
        vibrate: A vibration pattern for the device's vibration hardware to emit when the
            notification fires (optional). The pattern is specified as an integer array.
        custom_data: A dict of custom key-value pairs to be included in the notification
            (optional)

    .. _Notification Reference: https://developer.mozilla.org/en-US/docs/Web/API\
        /notification/Notification
    """

    def __init__(self, title=None, body=None, icon=None, actions=None, badge=None, data=None,
                 direction=None, image=None, language=None, renotify=None,
                 require_interaction=None, silent=None, tag=None, timestamp_millis=None,
                 vibrate=None, custom_data=None):
        self.title = title
        self.body = body
        self.icon = icon
        self.actions = actions
        self.badge = badge
        self.data = data
        self.direction = direction
        self.image = image
        self.language = language
        self.renotify = renotify
        self.require_interaction = require_interaction
        self.silent = silent
        self.tag = tag
        self.timestamp_millis = timestamp_millis
        self.vibrate = vibrate
        self.custom_data = custom_data


class WebpushFcmOptions(object):
    """Options for features provided by the FCM SDK for Web.

    Args:
        link: The link to open when the user clicks on the notification. Must be an HTTPS URL
            (optional).
    """

    def __init__(self, link=None):
        self.link = link


class APNSConfig(object):
    """APNS-specific options that can be included in a message.

    Refer to `APNS Documentation`_ for more information.

    Args:
        headers: A dictionary of headers (optional).
        payload: A ``messaging.APNSPayload`` to be included in the message (optional).

    .. _APNS Documentation: https://developer.apple.com/library/content/documentation\
        /NetworkingInternet/Conceptual/RemoteNotificationsPG/CommunicatingwithAPNs.html
    """

    def __init__(self, headers=None, payload=None):
        self.headers = headers
        self.payload = payload


class APNSPayload(object):
    """Payload of an APNS message.

    Args:
        aps: A ``messaging.Aps`` instance to be included in the payload.
        kwargs: Arbitrary keyword arguments to be included as custom fields in the payload
            (optional).
    """

    def __init__(self, aps, **kwargs):
        self.aps = aps
        self.custom_data = kwargs


class Aps(object):
    """Aps dictionary to be included in an APNS payload.

    Args:
        alert: A string or a ``messaging.ApsAlert`` instance (optional).
        badge: A number representing the badge to be displayed with the message (optional).
        sound: Name of the sound file to be played with the message or a
            ``messaging.CriticalSound`` instance (optional).
        content_available: A boolean indicating whether to configure a background update
            notification (optional).
        category: String identifier representing the message type (optional).
        thread_id: An app-specific string identifier for grouping messages (optional).
        mutable_content: A boolean indicating whether to support mutating notifications at
            the client using app extensions (optional).
        custom_data: A dict of custom key-value pairs to be included in the Aps dictionary
            (optional).
    """

    def __init__(self, alert=None, badge=None, sound=None, content_available=None, category=None,
                 thread_id=None, mutable_content=None, custom_data=None):
        self.alert = alert
        self.badge = badge
        self.sound = sound
        self.content_available = content_available
        self.category = category
        self.thread_id = thread_id
        self.mutable_content = mutable_content
        self.custom_data = custom_data


class CriticalSound(object):
    """Critical alert sound configuration that can be included in ``messaging.Aps``.

    Args:
        name: The name of a sound file in your app's main bundle or in the ``Library/Sounds``
            folder of your app's container directory. Specify the string ``default`` to play the
            system sound.
        critical: Set to ``True`` to set the critical alert flag on the sound configuration
            (optional).
        volume: The volume for the critical alert's sound. Must be a value between 0.0 (silent)
            and 1.0 (full volume) (optional).
    """

    def __init__(self, name, critical=None, volume=None):
        self.name = name
        self.critical = critical
        self.volume = volume


class ApsAlert(object):
    """An alert that can be included in ``messaging.Aps``.

    Args:
        title: Title of the alert (optional). If specified, overrides the title set via
            ``messaging.Notification``.
        subtitle: Subtitle of the alert (optional).
        body: Body of the alert (optional). If specified, overrides the body set via
            ``messaging.Notification``.
        loc_key: Key of the body string in the app's string resources to use to localize the
            body text (optional).
        loc_args: A list of resource keys that will be used in place of the format specifiers
            in ``loc_key`` (optional).
        title_loc_key: Key of the title string in the app's string resources to use to localize the
            title text (optional).
        title_loc_args: A list of resource keys that will be used in place of the format specifiers
            in ``title_loc_key`` (optional).
        action_loc_key: Key of the text in the app's string resources to use to localize the
            action button text (optional).
        launch_image: Image for the notification action (optional).
    """

    def __init__(self, title=None, subtitle=None, body=None, loc_key=None, loc_args=None,
                 title_loc_key=None, title_loc_args=None, action_loc_key=None, launch_image=None):
        self.title = title
        self.subtitle = subtitle
        self.body = body
        self.loc_key = loc_key
        self.loc_args = loc_args
        self.title_loc_key = title_loc_key
        self.title_loc_args = title_loc_args
        self.action_loc_key = action_loc_key
        self.launch_image = launch_image


class _Validators(object):
    """A collection of data validation utilities.

    Methods provided in this class raise ValueErrors if any validations fail.
    """

    @classmethod
    def check_string(cls, label, value, non_empty=False):
        """Checks if the given value is a string."""
        if value is None:
            return None
        if not isinstance(value, six.string_types):
            if non_empty:
                raise ValueError('{0} must be a non-empty string.'.format(label))
            else:
                raise ValueError('{0} must be a string.'.format(label))
        if non_empty and not value:
            raise ValueError('{0} must be a non-empty string.'.format(label))
        return value

    @classmethod
    def check_number(cls, label, value):
        if value is None:
            return None
        if not isinstance(value, numbers.Number):
            raise ValueError('{0} must be a number.'.format(label))
        return value

    @classmethod
    def check_string_dict(cls, label, value):
        """Checks if the given value is a dictionary comprised only of string keys and values."""
        if value is None or value == {}:
            return None
        if not isinstance(value, dict):
            raise ValueError('{0} must be a dictionary.'.format(label))
        non_str = [k for k in value if not isinstance(k, six.string_types)]
        if non_str:
            raise ValueError('{0} must not contain non-string keys.'.format(label))
        non_str = [v for v in value.values() if not isinstance(v, six.string_types)]
        if non_str:
            raise ValueError('{0} must not contain non-string values.'.format(label))
        return value

    @classmethod
    def check_string_list(cls, label, value):
        """Checks if the given value is a list comprised only of strings."""
        if value is None or value == []:
            return None
        if not isinstance(value, list):
            raise ValueError('{0} must be a list of strings.'.format(label))
        non_str = [k for k in value if not isinstance(k, six.string_types)]
        if non_str:
            raise ValueError('{0} must not contain non-string values.'.format(label))
        return value


class MessageEncoder(json.JSONEncoder):
    """A custom JSONEncoder implementation for serializing Message instances into JSON."""

    @classmethod
    def remove_null_values(cls, dict_value):
        return {k: v for k, v in dict_value.items() if v not in [None, [], {}]}

    @classmethod
    def encode_android(cls, android):
        """Encodes an AndroidConfig instance into JSON."""
        if android is None:
            return None
        if not isinstance(android, AndroidConfig):
            raise ValueError('Message.android must be an instance of AndroidConfig class.')
        result = {
            'collapse_key': _Validators.check_string(
                'AndroidConfig.collapse_key', android.collapse_key),
            'data': _Validators.check_string_dict(
                'AndroidConfig.data', android.data),
            'notification': cls.encode_android_notification(android.notification),
            'priority': _Validators.check_string(
                'AndroidConfig.priority', android.priority, non_empty=True),
            'restricted_package_name': _Validators.check_string(
                'AndroidConfig.restricted_package_name', android.restricted_package_name),
            'ttl': cls.encode_ttl(android.ttl),
        }
        result = cls.remove_null_values(result)
        priority = result.get('priority')
        if priority and priority not in ('high', 'normal'):
            raise ValueError('AndroidConfig.priority must be "high" or "normal".')
        return result

    @classmethod
    def encode_ttl(cls, ttl):
        """Encodes a AndroidConfig TTL duration into a string."""
        if ttl is None:
            return None
        if isinstance(ttl, numbers.Number):
            ttl = datetime.timedelta(seconds=ttl)
        if not isinstance(ttl, datetime.timedelta):
            raise ValueError('AndroidConfig.ttl must be a duration in seconds or an instance of '
                             'datetime.timedelta.')
        total_seconds = ttl.total_seconds()
        if total_seconds < 0:
            raise ValueError('AndroidConfig.ttl must not be negative.')
        seconds = int(math.floor(total_seconds))
        nanos = int((total_seconds - seconds) * 1e9)
        if nanos:
            return '{0}.{1}s'.format(seconds, str(nanos).zfill(9))
        return '{0}s'.format(seconds)

    @classmethod
    def encode_android_notification(cls, notification):
        """Encodes an AndroidNotification instance into JSON."""
        if notification is None:
            return None
        if not isinstance(notification, AndroidNotification):
            raise ValueError('AndroidConfig.notification must be an instance of '
                             'AndroidNotification class.')
        result = {
            'body': _Validators.check_string(
                'AndroidNotification.body', notification.body),
            'body_loc_args': _Validators.check_string_list(
                'AndroidNotification.body_loc_args', notification.body_loc_args),
            'body_loc_key': _Validators.check_string(
                'AndroidNotification.body_loc_key', notification.body_loc_key),
            'click_action': _Validators.check_string(
                'AndroidNotification.click_action', notification.click_action),
            'color': _Validators.check_string(
                'AndroidNotification.color', notification.color, non_empty=True),
            'icon': _Validators.check_string(
                'AndroidNotification.icon', notification.icon),
            'sound': _Validators.check_string(
                'AndroidNotification.sound', notification.sound),
            'tag': _Validators.check_string(
                'AndroidNotification.tag', notification.tag),
            'title': _Validators.check_string(
                'AndroidNotification.title', notification.title),
            'title_loc_args': _Validators.check_string_list(
                'AndroidNotification.title_loc_args', notification.title_loc_args),
            'title_loc_key': _Validators.check_string(
                'AndroidNotification.title_loc_key', notification.title_loc_key),
            'channel_id': _Validators.check_string(
                'AndroidNotification.channel_id', notification.channel_id),
        }
        result = cls.remove_null_values(result)
        color = result.get('color')
        if color and not re.match(r'^#[0-9a-fA-F]{6}$', color):
            raise ValueError('AndroidNotification.color must be in the form #RRGGBB.')
        if result.get('body_loc_args') and not result.get('body_loc_key'):
            raise ValueError(
                'AndroidNotification.body_loc_key is required when specifying body_loc_args.')
        if result.get('title_loc_args') and not result.get('title_loc_key'):
            raise ValueError(
                'AndroidNotification.title_loc_key is required when specifying title_loc_args.')
        return result

    @classmethod
    def encode_webpush(cls, webpush):
        """Encodes a WebpushConfig instance into JSON."""
        if webpush is None:
            return None
        if not isinstance(webpush, WebpushConfig):
            raise ValueError('Message.webpush must be an instance of WebpushConfig class.')
        result = {
            'data': _Validators.check_string_dict(
                'WebpushConfig.data', webpush.data),
            'headers': _Validators.check_string_dict(
                'WebpushConfig.headers', webpush.headers),
            'notification': cls.encode_webpush_notification(webpush.notification),
            'fcmOptions': cls.encode_webpush_fcm_options(webpush.fcm_options),
        }
        return cls.remove_null_values(result)

    @classmethod
    def encode_webpush_notification(cls, notification):
        """Encodes a WebpushNotification instance into JSON."""
        if notification is None:
            return None
        if not isinstance(notification, WebpushNotification):
            raise ValueError('WebpushConfig.notification must be an instance of '
                             'WebpushNotification class.')
        result = {
            'actions': cls.encode_webpush_notification_actions(notification.actions),
            'badge': _Validators.check_string(
                'WebpushNotification.badge', notification.badge),
            'body': _Validators.check_string(
                'WebpushNotification.body', notification.body),
            'data': notification.data,
            'dir': _Validators.check_string(
                'WebpushNotification.direction', notification.direction),
            'icon': _Validators.check_string(
                'WebpushNotification.icon', notification.icon),
            'image': _Validators.check_string(
                'WebpushNotification.image', notification.image),
            'lang': _Validators.check_string(
                'WebpushNotification.language', notification.language),
            'renotify': notification.renotify,
            'requireInteraction': notification.require_interaction,
            'silent': notification.silent,
            'tag': _Validators.check_string(
                'WebpushNotification.tag', notification.tag),
            'timestamp': _Validators.check_number(
                'WebpushNotification.timestamp_millis', notification.timestamp_millis),
            'title': _Validators.check_string(
                'WebpushNotification.title', notification.title),
            'vibrate': notification.vibrate,
        }
        direction = result.get('dir')
        if direction and direction not in ('auto', 'ltr', 'rtl'):
            raise ValueError('WebpushNotification.direction must be "auto", "ltr" or "rtl".')
        if notification.custom_data is not None:
            if not isinstance(notification.custom_data, dict):
                raise ValueError('WebpushNotification.custom_data must be a dict.')
            for key, value in notification.custom_data.items():
                if key in result:
                    raise ValueError(
                        'Multiple specifications for {0} in WebpushNotification.'.format(key))
                result[key] = value
        return cls.remove_null_values(result)

    @classmethod
    def encode_webpush_notification_actions(cls, actions):
        """Encodes a list of WebpushNotificationActions into JSON."""
        if actions is None:
            return None
        if not isinstance(actions, list):
            raise ValueError('WebpushConfig.notification.actions must be a list of '
                             'WebpushNotificationAction instances.')
        results = []
        for action in actions:
            if not isinstance(action, WebpushNotificationAction):
                raise ValueError('WebpushConfig.notification.actions must be a list of '
                                 'WebpushNotificationAction instances.')
            result = {
                'action': _Validators.check_string(
                    'WebpushNotificationAction.action', action.action),
                'title': _Validators.check_string(
                    'WebpushNotificationAction.title', action.title),
                'icon': _Validators.check_string(
                    'WebpushNotificationAction.icon', action.icon),
            }
            results.append(cls.remove_null_values(result))
        return results

    @classmethod
    def encode_webpush_fcm_options(cls, options):
        """Encodes a WebpushFcmOptions instance into JSON."""
        if options is None:
            return None
        result = {
            'link': _Validators.check_string('WebpushConfig.fcm_options.link', options.link),
        }
        result = cls.remove_null_values(result)
        link = result.get('link')
        if link is not None and not link.startswith('https://'):
            raise ValueError('WebpushFcmOptions.link must be a HTTPS URL.')
        return result

    @classmethod
    def encode_apns(cls, apns):
        """Encodes an APNSConfig instance into JSON."""
        if apns is None:
            return None
        if not isinstance(apns, APNSConfig):
            raise ValueError('Message.apns must be an instance of APNSConfig class.')
        result = {
            'headers': _Validators.check_string_dict(
                'APNSConfig.headers', apns.headers),
            'payload': cls.encode_apns_payload(apns.payload),
        }
        return cls.remove_null_values(result)

    @classmethod
    def encode_apns_payload(cls, payload):
        """Encodes an APNSPayload instance into JSON."""
        if payload is None:
            return None
        if not isinstance(payload, APNSPayload):
            raise ValueError('APNSConfig.payload must be an instance of APNSPayload class.')
        result = {
            'aps': cls.encode_aps(payload.aps)
        }
        for key, value in payload.custom_data.items():
            result[key] = value
        return cls.remove_null_values(result)

    @classmethod
    def encode_aps(cls, aps):
        """Encodes an Aps instance into JSON."""
        if not isinstance(aps, Aps):
            raise ValueError('APNSPayload.aps must be an instance of Aps class.')
        result = {
            'alert': cls.encode_aps_alert(aps.alert),
            'badge': _Validators.check_number('Aps.badge', aps.badge),
            'sound': cls.encode_aps_sound(aps.sound),
            'category': _Validators.check_string('Aps.category', aps.category),
            'thread-id': _Validators.check_string('Aps.thread_id', aps.thread_id),
        }
        if aps.content_available is True:
            result['content-available'] = 1
        if aps.mutable_content is True:
            result['mutable-content'] = 1
        if aps.custom_data is not None:
            if not isinstance(aps.custom_data, dict):
                raise ValueError('Aps.custom_data must be a dict.')
            for key, val in aps.custom_data.items():
                _Validators.check_string('Aps.custom_data key', key)
                if key in result:
                    raise ValueError('Multiple specifications for {0} in Aps.'.format(key))
                result[key] = val
        return cls.remove_null_values(result)

    @classmethod
    def encode_aps_sound(cls, sound):
        """Encodes an APNs sound configuration into JSON."""
        if sound is None:
            return None
        if sound and isinstance(sound, six.string_types):
            return sound
        if not isinstance(sound, CriticalSound):
            raise ValueError(
                'Aps.sound must be a non-empty string or an instance of CriticalSound class.')
        result = {
            'name': _Validators.check_string('CriticalSound.name', sound.name, non_empty=True),
            'volume': _Validators.check_number('CriticalSound.volume', sound.volume),
        }
        if sound.critical:
            result['critical'] = 1
        if not result['name']:
            raise ValueError('CriticalSond.name must be a non-empty string.')
        volume = result['volume']
        if volume is not None and (volume < 0 or volume > 1):
            raise ValueError('CriticalSound.volume must be in the interval [0,1].')
        return cls.remove_null_values(result)

    @classmethod
    def encode_aps_alert(cls, alert):
        """Encodes an ApsAlert instance into JSON."""
        if alert is None:
            return None
        if isinstance(alert, six.string_types):
            return alert
        if not isinstance(alert, ApsAlert):
            raise ValueError('Aps.alert must be a string or an instance of ApsAlert class.')
        result = {
            'title': _Validators.check_string('ApsAlert.title', alert.title),
            'subtitle': _Validators.check_string('ApsAlert.subtitle', alert.subtitle),
            'body': _Validators.check_string('ApsAlert.body', alert.body),
            'title-loc-key': _Validators.check_string(
                'ApsAlert.title_loc_key', alert.title_loc_key),
            'title-loc-args': _Validators.check_string_list(
                'ApsAlert.title_loc_args', alert.title_loc_args),
            'loc-key': _Validators.check_string(
                'ApsAlert.loc_key', alert.loc_key),
            'loc-args': _Validators.check_string_list(
                'ApsAlert.loc_args', alert.loc_args),
            'action-loc-key': _Validators.check_string(
                'ApsAlert.action_loc_key', alert.action_loc_key),
            'launch-image': _Validators.check_string(
                'ApsAlert.launch_image', alert.launch_image),
        }
        if result.get('loc-args') and not result.get('loc-key'):
            raise ValueError(
                'ApsAlert.loc_key is required when specifying loc_args.')
        if result.get('title-loc-args') and not result.get('title-loc-key'):
            raise ValueError(
                'ApsAlert.title_loc_key is required when specifying title_loc_args.')
        return cls.remove_null_values(result)

    @classmethod
    def encode_notification(cls, notification):
        if notification is None:
            return None
        if not isinstance(notification, Notification):
            raise ValueError('Message.notification must be an instance of Notification class.')
        result = {
            'body': _Validators.check_string('Notification.body', notification.body),
            'title': _Validators.check_string('Notification.title', notification.title),
        }
        return cls.remove_null_values(result)

    @classmethod
    def sanitize_topic_name(cls, topic):
        if not topic:
            return None
        prefix = '/topics/'
        if topic.startswith(prefix):
            topic = topic[len(prefix):]
        # Checks for illegal characters and empty string.
        if not re.match(r'^[a-zA-Z0-9-_\.~%]+$', topic):
            raise ValueError('Malformed topic name.')
        return topic

    def default(self, obj): # pylint: disable=method-hidden
        if not isinstance(obj, Message):
            return json.JSONEncoder.default(self, obj)
        result = {
            'android': MessageEncoder.encode_android(obj.android),
            'apns': MessageEncoder.encode_apns(obj.apns),
            'condition': _Validators.check_string(
                'Message.condition', obj.condition, non_empty=True),
            'data': _Validators.check_string_dict('Message.data', obj.data),
            'notification': MessageEncoder.encode_notification(obj.notification),
            'token': _Validators.check_string('Message.token', obj.token, non_empty=True),
            'topic': _Validators.check_string('Message.topic', obj.topic, non_empty=True),
            'webpush': MessageEncoder.encode_webpush(obj.webpush),
        }
        result['topic'] = MessageEncoder.sanitize_topic_name(result.get('topic'))
        result = MessageEncoder.remove_null_values(result)
        target_count = sum([t in result for t in ['token', 'topic', 'condition']])
        if target_count != 1:
            raise ValueError('Exactly one of token, topic or condition must be specified.')
        return result
