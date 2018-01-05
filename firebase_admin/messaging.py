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

"""Firebase Cloud Messaging module."""

import json
import re

import six

from firebase_admin import _http_client
from firebase_admin import _utils


_MESSAGING_ATTRIBUTE = '_messaging'


def _get_messaging_service(app):
    return _utils.get_app_service(app, _MESSAGING_ATTRIBUTE, _MessagingService)

def send(message, dry_run=False, app=None):
    return _get_messaging_service(app).send(message, dry_run)


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
            raise ValueError('{0} must be a list.'.format(label))
        non_str = [k for k in value if not isinstance(k, six.string_types)]
        if non_str:
            raise ValueError('{0} must not contain non-string values.'.format(label))
        return value


class Message(object):

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

    def __init__(self, title=None, body=None):
        self.title = title
        self.body = body


class AndroidConfig(object):

    def __init__(self, collapse_key=None, priority=None, ttl=None, restricted_package_name=None,
                 data=None, notification=None):
        self.collapse_key = collapse_key
        self.priority = priority
        self.ttl = ttl
        self.restricted_package_name = restricted_package_name
        self.data = data
        self.notification = notification


class AndroidNotification(object):

    def __init__(self, title=None, body=None, icon=None, color=None, sound=None, tag=None,
                 click_action=None, body_loc_key=None, body_loc_args=None, title_loc_key=None,
                 title_loc_args=None):
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


class WebpushConfig(object):

    def __init__(self, headers=None, data=None, notification=None):
        self.headers = headers
        self.data = data
        self.notification = notification


class WebpushNotification(object):

    def __init__(self, title=None, body=None, icon=None):
        self.title = title
        self.body = body
        self.icon = icon


class _MessageEncoder(json.JSONEncoder):
    """A custom JSONEncoder implementation for serializing Message instances into JSON."""

    @classmethod
    def remove_null_values(cls, dict_value):
        return {k: v for k, v in dict_value.items() if v not in [None, {}]}

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
            'ttl': _Validators.check_string(
                'AndroidConfig.ttl', android.ttl, non_empty=True),
        }
        result = cls.remove_null_values(result)
        priority = result.get('priority')
        if priority and priority not in ('high', 'normal'):
            raise ValueError('AndroidConfig.priority must be "high" or "normal".')
        ttl = result.get('ttl')
        if ttl and not re.match(r'^\d+(\.\d+)?s$', ttl):
            raise ValueError('AndroidConfig.ttl must contain a non-negative numeric value '
                             'followed by the "s" suffix.')
        return result

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
        }
        result = cls.remove_null_values(result)
        color = result.get('color')
        if color and not re.match(r'^#[0-9a-fA-F]{6}$', color):
            raise ValueError('AndroidNotification.color must be in the form #RRGGBB.')
        if result.get('body_loc_args') and not result.get('body_loc_key'):
            raise ValueError(
                'AndroidNotification.body_loc_key is required when specofying body_loc_args.')
        if result.get('title_loc_args') and not result.get('title_loc_key'):
            raise ValueError(
                'AndroidNotification.title_loc_key is required when specofying title_loc_args.')
        return result

    @classmethod
    def encode_webpush(cls, webpush):
        """Encodes an WebpushConfig instance into JSON."""
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
        }
        return cls.remove_null_values(result)

    @classmethod
    def encode_webpush_notification(cls, notification):
        """Encodes an WebpushNotification instance into JSON."""
        if notification is None:
            return None
        if not isinstance(notification, WebpushNotification):
            raise ValueError('WebpushConfig.notification must be an instance of '
                             'WebpushNotification class.')
        result = {
            'body': _Validators.check_string(
                'WebpushNotification.body', notification.body),
            'icon': _Validators.check_string(
                'WebpushNotification.icon', notification.icon),
            'title': _Validators.check_string(
                'WebpushNotification.title', notification.title),
        }
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

    def default(self, obj): # pylint: disable=method-hidden
        if not isinstance(obj, Message):
            return json.JSONEncoder.default(self, obj)
        result = {
            'android': _MessageEncoder.encode_android(obj.android),
            'condition': _Validators.check_string(
                'Message.condition', obj.condition, non_empty=True),
            'data': _Validators.check_string_dict('Message.data', obj.data),
            'notification': _MessageEncoder.encode_notification(obj.notification),
            'token': _Validators.check_string('Message.token', obj.token, non_empty=True),
            'topic': _Validators.check_string('Message.topic', obj.topic, non_empty=True),
            'webpush': _MessageEncoder.encode_webpush(obj.webpush),
        }
        result = _MessageEncoder.remove_null_values(result)
        target_count = sum([t in result for t in ['token', 'topic', 'condition']])
        if target_count != 1:
            raise ValueError('Exactly one of token, topic or condition must be specified.')
        topic = result.get('topic')
        if topic:
            if topic.startswith('/topics/'):
                raise ValueError('Topic name must not contain the /topics/ prefix.')
            if not re.match(r'^[a-zA-Z0-9-_\.~%]+$', topic):
                raise ValueError('Illegal characters in topic name.')
        return result


class _MessagingService(object):
    """Service class that implements Firebase Cloud Messaging (FCM) functionality."""

    _FCM_URL = 'https://fcm.googleapis.com/v1/projects/{0}/messages:send'
    _JSON_ENCODER = _MessageEncoder()

    def __init__(self, app):
        project_id = app.project_id
        if not project_id:
            raise ValueError(
                'Project ID is required to access Cloud Messaging service. Either set the'
                ' projectId option, or use service account credentials. Alternatively, set the '
                'GCLOUD_PROJECT environment variable.')
        if not isinstance(project_id, six.string_types):
            raise ValueError(
                'Invalid project ID: "{0}". project ID must be a string.'.format(project_id))
        self._fcm_url = _MessagingService._FCM_URL.format(project_id)
        self._client = _http_client.JsonHttpClient(credential=app.credential.get_credential())

    @classmethod
    def encode_message(cls, message):
        if not isinstance(message, Message):
            raise ValueError('message must be an instance of Message class.')
        return cls._JSON_ENCODER.default(message)

    def send(self, message, dry_run=False):
        data = {'message': _MessagingService.encode_message(message)}
        if dry_run:
            data['validate_only'] = True
        resp = self._client.body('post', url=self._fcm_url, json=data)
        return resp['name']
