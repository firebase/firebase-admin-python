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

import requests
import six

from firebase_admin import _http_client
from firebase_admin import _messaging_utils
from firebase_admin import _utils


_MESSAGING_ATTRIBUTE = '_messaging'


__all__ = [
    'AndroidConfig',
    'AndroidNotification',
    'APNSConfig',
    'APNSPayload',
    'ApiCallError',
    'Aps',
    'ApsAlert',
    'CriticalSound',
    'ErrorInfo',
    'Message',
    'Notification',
    'TopicManagementResponse',
    'WebpushConfig',
    'WebpushFcmOptions',
    'WebpushNotification',
    'WebpushNotificationAction',

    'send',
    'subscribe_to_topic',
    'unsubscribe_from_topic',
]


AndroidConfig = _messaging_utils.AndroidConfig
AndroidNotification = _messaging_utils.AndroidNotification
APNSConfig = _messaging_utils.APNSConfig
APNSPayload = _messaging_utils.APNSPayload
Aps = _messaging_utils.Aps
ApsAlert = _messaging_utils.ApsAlert
CriticalSound = _messaging_utils.CriticalSound
Message = _messaging_utils.Message
Notification = _messaging_utils.Notification
WebpushConfig = _messaging_utils.WebpushConfig
WebpushFcmOptions = _messaging_utils.WebpushFcmOptions
WebpushNotification = _messaging_utils.WebpushNotification
WebpushNotificationAction = _messaging_utils.WebpushNotificationAction


def _get_messaging_service(app):
    return _utils.get_app_service(app, _MESSAGING_ATTRIBUTE, _MessagingService)

def send(message, dry_run=False, app=None):
    """Sends the given message via Firebase Cloud Messaging (FCM).

    If the ``dry_run`` mode is enabled, the message will not be actually delivered to the
    recipients. Instead FCM performs all the usual validations, and emulates the send operation.

    Args:
        message: An instance of ``messaging.Message``.
        dry_run: A boolean indicating whether to run the operation in dry run mode (optional).
        app: An App instance (optional).

    Returns:
        string: A message ID string that uniquely identifies the sent the message.

    Raises:
        ApiCallError: If an error occurs while sending the message to FCM service.
        ValueError: If the input arguments are invalid.
    """
    return _get_messaging_service(app).send(message, dry_run)

def subscribe_to_topic(tokens, topic, app=None):
    """Subscribes a list of registration tokens to an FCM topic.

    Args:
        tokens: A non-empty list of device registration tokens. List may not have more than 1000
            elements.
        topic: Name of the topic to subscribe to. May contain the ``/topics/`` prefix.
        app: An App instance (optional).

    Returns:
        TopicManagementResponse: A ``TopicManagementResponse`` instance.

    Raises:
        ApiCallError: If an error occurs while communicating with instance ID service.
        ValueError: If the input arguments are invalid.
    """
    return _get_messaging_service(app).make_topic_management_request(
        tokens, topic, 'iid/v1:batchAdd')

def unsubscribe_from_topic(tokens, topic, app=None):
    """Unsubscribes a list of registration tokens from an FCM topic.

    Args:
        tokens: A non-empty list of device registration tokens. List may not have more than 1000
            elements.
        topic: Name of the topic to unsubscribe from. May contain the ``/topics/`` prefix.
        app: An App instance (optional).

    Returns:
        TopicManagementResponse: A ``TopicManagementResponse`` instance.

    Raises:
        ApiCallError: If an error occurs while communicating with instance ID service.
        ValueError: If the input arguments are invalid.
    """
    return _get_messaging_service(app).make_topic_management_request(
        tokens, topic, 'iid/v1:batchRemove')


class ErrorInfo(object):
    """An error encountered when performing a topic management operation."""

    def __init__(self, index, reason):
        self._index = index
        self._reason = reason

    @property
    def index(self):
        """Index of the registration token to which this error is related to."""
        return self._index

    @property
    def reason(self):
        """String describing the nature of the error."""
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
        """Number of tokens that were successfully subscribed or unsubscribed."""
        return self._success_count

    @property
    def failure_count(self):
        """Number of tokens that could not be subscribed or unsubscribed due to errors."""
        return self._failure_count

    @property
    def errors(self):
        """A list of ``messaging.ErrorInfo`` objects (possibly empty)."""
        return self._errors


class ApiCallError(Exception):
    """Represents an Exception encountered while invoking the FCM API.

    Attributes:
        code: A string error code.
        message: A error message string.
        detail: Original low-level exception.
    """

    def __init__(self, code, message, detail=None):
        Exception.__init__(self, message)
        self.code = code
        self.detail = detail


class _MessagingService(object):
    """Service class that implements Firebase Cloud Messaging (FCM) functionality."""

    FCM_URL = 'https://fcm.googleapis.com/v1/projects/{0}/messages:send'
    IID_URL = 'https://iid.googleapis.com'
    IID_HEADERS = {'access_token_auth': 'true'}
    JSON_ENCODER = _messaging_utils.MessageEncoder()

    INTERNAL_ERROR = 'internal-error'
    UNKNOWN_ERROR = 'unknown-error'
    FCM_ERROR_CODES = {
        # FCM v1 canonical error codes
        'NOT_FOUND': 'registration-token-not-registered',
        'PERMISSION_DENIED': 'mismatched-credential',
        'RESOURCE_EXHAUSTED': 'message-rate-exceeded',
        'UNAUTHENTICATED': 'invalid-apns-credentials',

        # FCM v1 new error codes
        'APNS_AUTH_ERROR': 'invalid-apns-credentials',
        'INTERNAL': INTERNAL_ERROR,
        'INVALID_ARGUMENT': 'invalid-argument',
        'QUOTA_EXCEEDED': 'message-rate-exceeded',
        'SENDER_ID_MISMATCH': 'mismatched-credential',
        'UNAVAILABLE': 'server-unavailable',
        'UNREGISTERED': 'registration-token-not-registered',
    }
    IID_ERROR_CODES = {
        400: 'invalid-argument',
        401: 'authentication-error',
        403: 'authentication-error',
        500: INTERNAL_ERROR,
        503: 'server-unavailable',
    }

    def __init__(self, app):
        project_id = app.project_id
        if not project_id:
            raise ValueError(
                'Project ID is required to access Cloud Messaging service. Either set the '
                'projectId option, or use service account credentials. Alternatively, set the '
                'GOOGLE_CLOUD_PROJECT environment variable.')
        self._fcm_url = _MessagingService.FCM_URL.format(project_id)
        self._client = _http_client.JsonHttpClient(credential=app.credential.get_credential())
        self._timeout = app.options.get('httpTimeout')

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
            headers = {'X-GOOG-API-FORMAT-VERSION': '2'}
            resp = self._client.body(
                'post', url=self._fcm_url, headers=headers, json=data, timeout=self._timeout)
        except requests.exceptions.RequestException as error:
            if error.response is not None:
                self._handle_fcm_error(error)
            else:
                msg = 'Failed to call messaging API: {0}'.format(error)
                raise ApiCallError(self.INTERNAL_ERROR, msg, error)
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
        try:
            resp = self._client.body(
                'post',
                url=url,
                json=data,
                headers=_MessagingService.IID_HEADERS,
                timeout=self._timeout
            )
        except requests.exceptions.RequestException as error:
            if error.response is not None:
                self._handle_iid_error(error)
            else:
                raise ApiCallError(self.INTERNAL_ERROR, 'Failed to call instance ID API.', error)
        else:
            return TopicManagementResponse(resp)

    def _handle_fcm_error(self, error):
        """Handles errors received from the FCM API."""
        data = {}
        try:
            parsed_body = error.response.json()
            if isinstance(parsed_body, dict):
                data = parsed_body
        except ValueError:
            pass

        error_dict = data.get('error', {})
        server_code = None
        for detail in error_dict.get('details', []):
            if detail.get('@type') == 'type.googleapis.com/google.firebase.fcm.v1.FcmError':
                server_code = detail.get('errorCode')
                break
        if not server_code:
            server_code = error_dict.get('status')
        code = _MessagingService.FCM_ERROR_CODES.get(server_code, _MessagingService.UNKNOWN_ERROR)

        msg = error_dict.get('message')
        if not msg:
            msg = 'Unexpected HTTP response with status: {0}; body: {1}'.format(
                error.response.status_code, error.response.content.decode())
        raise ApiCallError(code, msg, error)

    def _handle_iid_error(self, error):
        """Handles errors received from the Instance ID API."""
        data = {}
        try:
            parsed_body = error.response.json()
            if isinstance(parsed_body, dict):
                data = parsed_body
        except ValueError:
            pass

        code = _MessagingService.IID_ERROR_CODES.get(
            error.response.status_code, _MessagingService.UNKNOWN_ERROR)
        msg = data.get('error')
        if not msg:
            msg = 'Unexpected HTTP response with status: {0}; body: {1}'.format(
                error.response.status_code, error.response.content.decode())
        raise ApiCallError(code, msg, error)
