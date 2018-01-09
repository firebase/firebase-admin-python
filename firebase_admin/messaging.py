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

import requests
import six

from firebase_admin import _http_client
from firebase_admin import _utils


_MESSAGING_ATTRIBUTE = '_messaging'


def _get_messaging_service(app):
    return _utils.get_app_service(app, _MESSAGING_ATTRIBUTE, _MessagingService)

def send(message, dry_run=False, app=None):
    return _get_messaging_service(app).send(message, dry_run)

def subscribe_to_topic(tokens, topic, app=None):
    return _get_messaging_service(app).make_topic_management_request(
        tokens, topic, 'iid/v1:batchAdd')

def unsubscribe_from_topic(tokens, topic, app=None):
    return _get_messaging_service(app).make_topic_management_request(
        tokens, topic, 'iid/v1:batchRemove')


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
    def check_dict(cls, label, value):
        """Checks if the given value is a dictionary."""
        if value is None or value == {}:
            return None
        if not isinstance(value, dict):
            raise ValueError('{0} must be a dictionary.'.format(label))
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


class APNSConfig(object):

    def __init__(self, headers=None, payload=None):
        self.headers = headers
        self.payload = payload


class ErrorInfo(object):

    def __init__(self, index, reason):
        self._index = index
        self._reason = reason

    @property
    def index(self):
        return self._index

    @property
    def reason(self):
        return self._reason


class TopicManagementResponse(object):
    """The response received from a topic management operation."""

    def __init__(self, resp):
        if not isinstance(resp, dict) or 'results' not in resp:
            raise ValueError('Unexpected topic management response: {0}.'.format(resp))
        self._success_count = 0
        self._failure_count = 0
        self._errors = []
        for index, result in enumerate(resp['results']):
            if 'error' in result:
                self._failure_count += 1
                self._errors.append(ErrorInfo(index, result['error']))
            else:
                self._success_count += 1

    @property
    def success_count(self):
        return self._success_count

    @property
    def failure_count(self):
        return self._failure_count

    @property
    def errors(self):
        return self._errors


class ApiCallError(Exception):

    def __init__(self, code, message, detail=None):
        Exception.__init__(self, message)
        self.code = code
        self.detail = detail


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
    def encode_apns(cls, apns):
        """Encodes an APNSConfig instance into JSON."""
        if apns is None:
            return None
        if not isinstance(apns, APNSConfig):
            raise ValueError('Message.apns must be an instance of APNSConfig class.')
        result = {
            'headers': _Validators.check_string_dict(
                'APNSConfig.headers', apns.headers),
            'payload': _Validators.check_dict(
                'APNSConfig.payload', apns.payload),
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
            'apns': _MessageEncoder.encode_apns(obj.apns),
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

    FCM_URL = 'https://fcm.googleapis.com/v1/projects/{0}/messages:send'
    IID_URL = 'https://iid.googleapis.com'
    IID_HEADERS = {'access_token_auth': 'true'}
    JSON_ENCODER = _MessageEncoder()

    FCM_ERROR_CODES = {
        'INVALID_ARGUMENT': 'invalid-argument',
        'NOT_FOUND': 'registration-token-not-registered',
        'PERMISSION_DENIED': 'authentication-error',
        'RESOURCE_EXHAUSTED': 'message-rate-exceeded',
        'UNAUTHENTICATED': 'authentication-error',
        'UNAVAILABLE': 'server-unavailable',
    }
    UNKNOWN_ERROR = 'unknown-error'

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
        self._fcm_url = _MessagingService.FCM_URL.format(project_id)
        self._client = _http_client.JsonHttpClient(credential=app.credential.get_credential())

    @classmethod
    def encode_message(cls, message):
        if not isinstance(message, Message):
            raise ValueError('Message must be an instance of messaging.Message class.')
        return cls.JSON_ENCODER.default(message)

    def send(self, message, dry_run=False):
        data = {'message': _MessagingService.encode_message(message)}
        if dry_run:
            data['validate_only'] = True
        try:
            resp = self._client.body('post', url=self._fcm_url, json=data)
        except requests.exceptions.RequestException as error:
            self._handle_fcm_error(error)
        else:
            return resp['name']

    def make_topic_management_request(self, tokens, topic, operation):
        """Invokes the IID service for topic management functionality."""
        if isinstance(tokens, six.string_types):
            tokens = [tokens]
        if not isinstance(tokens, list) or not tokens:
            raise ValueError('Tokens must be a string or a non-empty list of strings.')
        invalid_str = [t for t in tokens if not isinstance(t, six.string_types) or not t]
        if invalid_str:
            raise ValueError('Tokens must be non-empty strings.')

        if not isinstance(topic, six.string_types) or not topic:
            raise ValueError('Topic must be a non-empty string.')
        if not topic.startswith('/topics/'):
            topic = '/topics/{0}'.format(topic)
        data = {
            'to': topic,
            'registration_tokens': tokens,
        }
        url = '{0}/{1}'.format(_MessagingService.IID_URL, operation)
        resp = self._client.body(
            'post', url=url, json=data, headers=_MessagingService.IID_HEADERS)
        return TopicManagementResponse(resp)

    def _handle_fcm_error(self, error):
        """Handles errors encountered when calling the FCM API."""
        data = {}
        try:
            parsed_body = error.response.json()
            if isinstance(parsed_body, dict):
                data = parsed_body
        except ValueError:
            pass

        error_details = data.get('error', {})
        code = _MessagingService.FCM_ERROR_CODES.get(
            error_details.get('status'), _MessagingService.UNKNOWN_ERROR)
        msg = error_details.get('message')
        if not msg:
            msg = 'Unexpected HTTP response with status: {0}; body: {1}'.format(
                error.response.status_code, error.response.content.decode())
        raise ApiCallError(code, msg, error)
