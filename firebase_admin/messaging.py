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

from __future__ import annotations
import asyncio
import concurrent.futures
import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional, cast
import urllib.parse
import warnings

import httpx
import requests

import firebase_admin
from firebase_admin import (
    _http_client,
    _messaging_encoder,
    _messaging_utils,
    _utils,
    exceptions,
    App
)

logger = logging.getLogger(__name__)

_MESSAGING_ATTRIBUTE = '_messaging'


__all__ = [
    'AndroidConfig',
    'AndroidFCMOptions',
    'AndroidNotification',
    'APNSConfig',
    'APNSFCMOptions',
    'APNSPayload',
    'Aps',
    'ApsAlert',
    'BatchResponse',
    'CriticalSound',
    'ErrorInfo',
    'FCMOptions',
    'LightSettings',
    'Message',
    'MulticastMessage',
    'Notification',
    'QuotaExceededError',
    'SenderIdMismatchError',
    'SendResponse',
    'ThirdPartyAuthError',
    'TopicManagementResponse',
    'UnregisteredError',
    'WebpushConfig',
    'WebpushFCMOptions',
    'WebpushNotification',
    'WebpushNotificationAction',

    'send',
    'send_each',
    'send_each_async',
    'send_each_for_multicast',
    'send_each_for_multicast_async',
    'subscribe_to_topic',
    'subscribe_to_topic_async',
    'subscribe_to_topic_legacy',
    'unsubscribe_from_topic',
    'unsubscribe_from_topic_async',
    'unsubscribe_from_topic_legacy',
]


AndroidConfig = _messaging_utils.AndroidConfig
AndroidFCMOptions = _messaging_utils.AndroidFCMOptions
AndroidNotification = _messaging_utils.AndroidNotification
APNSConfig = _messaging_utils.APNSConfig
APNSFCMOptions = _messaging_utils.APNSFCMOptions
APNSPayload = _messaging_utils.APNSPayload
Aps = _messaging_utils.Aps
ApsAlert = _messaging_utils.ApsAlert
CriticalSound = _messaging_utils.CriticalSound
FCMOptions = _messaging_utils.FCMOptions
LightSettings = _messaging_utils.LightSettings
Message = _messaging_encoder.Message
MulticastMessage = _messaging_encoder.MulticastMessage
Notification = _messaging_utils.Notification
WebpushConfig = _messaging_utils.WebpushConfig
WebpushFCMOptions = _messaging_utils.WebpushFCMOptions
WebpushNotification = _messaging_utils.WebpushNotification
WebpushNotificationAction = _messaging_utils.WebpushNotificationAction

QuotaExceededError = _messaging_utils.QuotaExceededError
SenderIdMismatchError = _messaging_utils.SenderIdMismatchError
ThirdPartyAuthError = _messaging_utils.ThirdPartyAuthError
UnregisteredError = _messaging_utils.UnregisteredError


def _get_messaging_service(app: Optional[App]) -> _MessagingService:
    return _utils.get_app_service(app, _MESSAGING_ATTRIBUTE, _MessagingService)

def send(message: Message, dry_run: bool = False, app: Optional[App] = None) -> str:
    """Sends the given message via Firebase Cloud Messaging (FCM).

    If the ``dry_run`` mode is enabled, the message will not be actually delivered to the
    recipients. Instead, FCM performs all the usual validations and emulates the send operation.

    Args:
        message: An instance of ``messaging.Message``.
        dry_run: A boolean indicating whether to run the operation in dry run mode (optional).
        app: An App instance (optional).

    Returns:
        string: A message ID string that uniquely identifies the sent message.

    Raises:
        FirebaseError: If an error occurs while sending the message to the FCM service.
        ValueError: If the input arguments are invalid.
    """
    return _get_messaging_service(app).send(message, dry_run)

def send_each(
        messages: List[Message],
        dry_run: bool = False,
        app: Optional[App] = None
    ) -> BatchResponse:
    """Sends each message in the given list via Firebase Cloud Messaging.

    If the ``dry_run`` mode is enabled, the message will not be actually delivered to the
    recipients. Instead, FCM performs all the usual validations and emulates the send operation.

    Args:
        messages: A list of ``messaging.Message`` instances.
        dry_run: A boolean indicating whether to run the operation in dry run mode (optional).
        app: An App instance (optional).

    Returns:
        BatchResponse: A ``messaging.BatchResponse`` instance.

    Raises:
        FirebaseError: If an error occurs while sending the message to the FCM service.
        ValueError: If the input arguments are invalid.
    """
    return _get_messaging_service(app).send_each(messages, dry_run)

async def send_each_async(
        messages: List[Message],
        dry_run: bool = False,
        app: Optional[App] = None
    ) -> BatchResponse:
    """Sends each message in the given list asynchronously via Firebase Cloud Messaging.

    If the ``dry_run`` mode is enabled, the message will not be actually delivered to the
    recipients. Instead, FCM performs all the usual validations and emulates the send operation.

    Args:
        messages: A list of ``messaging.Message`` instances.
        dry_run: A boolean indicating whether to run the operation in dry run mode (optional).
        app: An App instance (optional).

    Returns:
        BatchResponse: A ``messaging.BatchResponse`` instance.

    Raises:
        FirebaseError: If an error occurs while sending the message to the FCM service.
        ValueError: If the input arguments are invalid.
    """
    return await _get_messaging_service(app).send_each_async(messages, dry_run)

def _get_messages_from_multicast(multicast_message: MulticastMessage) -> List[Message]:
    """Extracts individual Message objects from a MulticastMessage."""
    if not isinstance(multicast_message, MulticastMessage):
        raise ValueError('Message must be an instance of messaging.MulticastMessage class.')

    messages = []
    if multicast_message.tokens is not None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            messages.extend([Message(
                data=multicast_message.data,
                notification=multicast_message.notification,
                android=multicast_message.android,
                webpush=multicast_message.webpush,
                apns=multicast_message.apns,
                fcm_options=multicast_message.fcm_options,
                token=token
            ) for token in multicast_message.tokens])

    if multicast_message.fids is not None:
        messages.extend([Message(
            data=multicast_message.data,
            notification=multicast_message.notification,
            android=multicast_message.android,
            webpush=multicast_message.webpush,
            apns=multicast_message.apns,
            fcm_options=multicast_message.fcm_options,
            fid=fid
        ) for fid in multicast_message.fids])

    return messages

async def send_each_for_multicast_async(
        multicast_message: MulticastMessage,
        dry_run: bool = False,
        app: Optional[App] = None
    ) -> BatchResponse:
    """Sends the given multicast message to each token or fid asynchronously via
    Firebase Cloud Messaging (FCM).

    If the ``dry_run`` mode is enabled, the message will not be actually delivered to the
    recipients. Instead, FCM performs all the usual validations and emulates the send operation.

    Args:
        multicast_message: An instance of ``messaging.MulticastMessage``.
        dry_run: A boolean indicating whether to run the operation in dry run mode (optional).
        app: An App instance (optional).

    Returns:
        BatchResponse: A ``messaging.BatchResponse`` instance.

    Raises:
        FirebaseError: If an error occurs while sending the message to the FCM service.
        ValueError: If the input arguments are invalid.
    """
    messages = _get_messages_from_multicast(multicast_message)
    return await _get_messaging_service(app).send_each_async(messages, dry_run)

def send_each_for_multicast(multicast_message, dry_run=False, app=None):
    """Sends the given multicast message to each token or fid via Firebase Cloud Messaging (FCM).

    If the ``dry_run`` mode is enabled, the message will not be actually delivered to the
    recipients. Instead, FCM performs all the usual validations and emulates the send operation.

    Args:
        multicast_message: An instance of ``messaging.MulticastMessage``.
        dry_run: A boolean indicating whether to run the operation in dry run mode (optional).
        app: An App instance (optional).

    Returns:
        BatchResponse: A ``messaging.BatchResponse`` instance.

    Raises:
        FirebaseError: If an error occurs while sending the message to the FCM service.
        ValueError: If the input arguments are invalid.
    """
    messages = _get_messages_from_multicast(multicast_message)
    return _get_messaging_service(app).send_each(messages, dry_run)

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
        FirebaseError: If an error occurs while communicating with the FCM service.
        ValueError: If the input arguments are invalid.
    """
    return _get_messaging_service(app).subscribe_to_topic(tokens, topic)

async def subscribe_to_topic_async(tokens, topic, app=None):
    """Subscribes a list of registration tokens to an FCM topic asynchronously.

    Args:
        tokens: A non-empty list of device registration tokens. List may not have more than 1000
            elements.
        topic: Name of the topic to subscribe to. May contain the ``/topics/`` prefix.
        app: An App instance (optional).

    Returns:
        TopicManagementResponse: A ``TopicManagementResponse`` instance.

    Raises:
        FirebaseError: If an error occurs while communicating with the FCM service.
        ValueError: If the input arguments are invalid.
    """
    return await _get_messaging_service(app).subscribe_to_topic_async(tokens, topic)

def subscribe_to_topic_legacy(tokens, topic, app=None):
    """Subscribes a list of registration tokens to an FCM topic using the legacy Instance ID API.

    subscribe_to_topic_legacy is deprecated. Use subscribe_to_topic instead.

    Args:
        tokens: A non-empty list of device registration tokens. List may not have more than 1000
            elements.
        topic: Name of the topic to subscribe to. May contain the ``/topics/`` prefix.
        app: An App instance (optional).

    Returns:
        TopicManagementResponse: A ``TopicManagementResponse`` instance.

    Raises:
        FirebaseError: If an error occurs while communicating with instance ID service.
        ValueError: If the input arguments are invalid.
    """
    warnings.warn(
        'subscribe_to_topic_legacy is deprecated. Use subscribe_to_topic instead.',
        DeprecationWarning,
        stacklevel=2)
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
        FirebaseError: If an error occurs while communicating with the FCM service.
        ValueError: If the input arguments are invalid.
    """
    return _get_messaging_service(app).unsubscribe_from_topic(tokens, topic)

async def unsubscribe_from_topic_async(tokens, topic, app=None):
    """Unsubscribes a list of registration tokens from an FCM topic asynchronously.

    Args:
        tokens: A non-empty list of device registration tokens. List may not have more than 1000
            elements.
        topic: Name of the topic to unsubscribe from. May contain the ``/topics/`` prefix.
        app: An App instance (optional).

    Returns:
        TopicManagementResponse: A ``TopicManagementResponse`` instance.

    Raises:
        FirebaseError: If an error occurs while communicating with the FCM service.
        ValueError: If the input arguments are invalid.
    """
    return await _get_messaging_service(app).unsubscribe_from_topic_async(tokens, topic)

def unsubscribe_from_topic_legacy(tokens, topic, app=None):
    """Unsubscribes a list of registration tokens from an FCM topic using the legacy
    Instance ID API.

    unsubscribe_from_topic_legacy is deprecated. Use unsubscribe_from_topic instead.

    Args:
        tokens: A non-empty list of device registration tokens. List may not have more than 1000
            elements.
        topic: Name of the topic to unsubscribe from. May contain the ``/topics/`` prefix.
        app: An App instance (optional).

    Returns:
        TopicManagementResponse: A ``TopicManagementResponse`` instance.

    Raises:
        FirebaseError: If an error occurs while communicating with instance ID service.
        ValueError: If the input arguments are invalid.
    """
    warnings.warn(
        'unsubscribe_from_topic_legacy is deprecated. Use unsubscribe_from_topic instead.',
        DeprecationWarning,
        stacklevel=2)
    return _get_messaging_service(app).make_topic_management_request(
        tokens, topic, 'iid/v1:batchRemove')


class ErrorInfo:
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


class TopicManagementResponse:
    """The response received from a topic management operation."""

    def __init__(self, resp):
        if not isinstance(resp, dict) or 'results' not in resp:
            raise ValueError(f'Unexpected topic management response: {resp}.')
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


class BatchResponse:
    """The response received from a batch request to the FCM API."""

    def __init__(self, responses: List[SendResponse]) -> None:
        self._responses = responses
        self._success_count = sum(1 for resp in responses if resp.success)

    @property
    def responses(self) -> List[SendResponse]:
        """A list of ``messaging.SendResponse`` objects (possibly empty)."""
        return self._responses

    @property
    def success_count(self) -> int:
        return self._success_count

    @property
    def failure_count(self) -> int:
        return len(self.responses) - self.success_count


class SendResponse:
    """The response received from an individual batched request to the FCM API."""

    def __init__(self, resp, exception):
        self._exception = exception
        self._message_id = None
        if resp:
            self._message_id = resp.get('name', None)

    @property
    def message_id(self):
        """A message ID string that uniquely identifies the message."""
        return self._message_id

    @property
    def success(self):
        """A boolean indicating if the request was successful."""
        return self._message_id is not None and not self._exception

    @property
    def exception(self):
        """A ``FirebaseError`` if an error occurs while sending the message to the FCM service."""
        return self._exception

class _MessagingService:
    """Service class that implements Firebase Cloud Messaging (FCM) functionality."""

    FCM_URL = 'https://fcm.googleapis.com/v1/projects/{0}/messages:send'
    FCM_BATCH_URL = 'https://fcm.googleapis.com/batch'
    IID_URL = 'https://iid.googleapis.com'
    IID_HEADERS = {'access_token_auth': 'true'}
    JSON_ENCODER = _messaging_encoder.MessageEncoder()

    FCM_ERROR_TYPES = {
        'APNS_AUTH_ERROR': ThirdPartyAuthError,
        'QUOTA_EXCEEDED': QuotaExceededError,
        'SENDER_ID_MISMATCH': SenderIdMismatchError,
        'THIRD_PARTY_AUTH_ERROR': ThirdPartyAuthError,
        'UNREGISTERED': UnregisteredError,
    }

    def __init__(self, app: App) -> None:
        project_id = app.project_id
        if not project_id:
            raise ValueError(
                'Project ID is required to access Cloud Messaging service. Either set the '
                'projectId option, or use service account credentials. Alternatively, set the '
                'GOOGLE_CLOUD_PROJECT environment variable.')
        self._project_id = project_id
        self._fcm_url = _MessagingService.FCM_URL.format(project_id)
        self._fcm_topic_url = f'https://fcm.googleapis.com/v1/projects/{project_id}/registrations'
        self._fcm_headers = {
            'X-GOOG-API-FORMAT-VERSION': '2',
            'X-FIREBASE-CLIENT': f'fire-admin-python/{firebase_admin.__version__}',
        }
        timeout = app.options.get('httpTimeout', _http_client.DEFAULT_TIMEOUT_SECONDS)
        self._credential = app.credential.get_credential()
        self._client = _http_client.JsonHttpClient(credential=self._credential, timeout=timeout)
        self._async_client = _http_client.HttpxAsyncClient(
            credential=self._credential, timeout=timeout)

    @classmethod
    def encode_message(cls, message):
        if not isinstance(message, Message):
            raise ValueError('Message must be an instance of messaging.Message class.')
        return cls.JSON_ENCODER.default(message)

    def send(self, message: Message, dry_run: bool = False) -> str:
        """Sends the given message to FCM via the FCM v1 API."""
        data = self._message_data(message, dry_run)
        try:
            resp = self._client.body(
                'post',
                url=self._fcm_url,
                headers=self._fcm_headers,
                json=data
            )
        except requests.exceptions.RequestException as error:
            raise self._handle_fcm_error(error)
        return cast(str, resp['name'])

    def send_each(self, messages: List[Message], dry_run: bool = False) -> BatchResponse:
        """Sends the given messages to FCM via the FCM v1 API."""
        if not isinstance(messages, list):
            raise ValueError('messages must be a list of messaging.Message instances.')
        if len(messages) > 500:
            raise ValueError('messages must not contain more than 500 elements.')

        def send_data(data):
            try:
                resp = self._client.body(
                    'post',
                    url=self._fcm_url,
                    headers=self._fcm_headers,
                    json=data)
            except requests.exceptions.RequestException as exception:
                return SendResponse(resp=None, exception=self._handle_fcm_error(exception))
            return SendResponse(resp, exception=None)

        message_data = [self._message_data(message, dry_run) for message in messages]
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(message_data)) as executor:
                responses = list(executor.map(send_data, message_data))
                return BatchResponse(responses)
        except Exception as error:
            raise exceptions.UnknownError(
                message=f'Unknown error while making remote service calls: {error}',
                cause=error)

    async def send_each_async(self, messages: List[Message], dry_run: bool = True) -> BatchResponse:
        """Sends the given messages to FCM via the FCM v1 API."""
        if not isinstance(messages, list):
            raise ValueError('messages must be a list of messaging.Message instances.')
        if len(messages) > 500:
            raise ValueError('messages must not contain more than 500 elements.')

        async def send_data(data):
            try:
                resp = await self._async_client.request(
                    'post',
                    url=self._fcm_url,
                    headers=self._fcm_headers,
                    json=data)
            except httpx.HTTPError as exception:
                return SendResponse(resp=None, exception=self._handle_fcm_httpx_error(exception))
            # Catch errors caused by the requests library during authorization
            except requests.exceptions.RequestException as exception:
                return SendResponse(resp=None, exception=self._handle_fcm_error(exception))
            return SendResponse(resp.json(), exception=None)

        message_data = [self._message_data(message, dry_run) for message in messages]
        try:
            responses = await asyncio.gather(*[send_data(message) for message in message_data])
            return BatchResponse(responses)
        except Exception as error:
            raise exceptions.UnknownError(
                message=f'Unknown error while making remote service calls: {error}',
                cause=error)

    def _validate_topic_management_args(self, tokens, topic):
        """Validates and formats topic management arguments."""
        if isinstance(tokens, str):
            tokens = [tokens]
        if not isinstance(tokens, list) or not tokens:
            raise ValueError('Tokens must be a string or a non-empty list of strings.')
        invalid_str = [t for t in tokens if not isinstance(t, str) or not t]
        if invalid_str:
            raise ValueError('Tokens must be non-empty strings.')
        if len(tokens) > 1000:
            raise ValueError('tokens must not contain more than 1000 elements.')

        if not isinstance(topic, str) or not topic:
            raise ValueError('Topic must be a non-empty string.')
        topic_name = topic
        if topic_name.startswith('/topics/'):
            topic_name = topic_name[len('/topics/'):]
        if not topic_name or not re.match(r'^[a-zA-Z0-9-_\.~%]+$', topic_name):
            raise ValueError('Malformed topic name.')

        return tokens, topic_name

    def subscribe_to_topic(self, tokens, topic) -> TopicManagementResponse:
        """Subscribes a list of registration tokens to an FCM topic via the FCM v1 API."""
        return self._make_topic_management_request_v1(tokens, topic, is_subscribe=True)

    def unsubscribe_from_topic(self, tokens, topic) -> TopicManagementResponse:
        """Unsubscribes a list of registration tokens from an FCM topic via the FCM v1 API."""
        return self._make_topic_management_request_v1(tokens, topic, is_subscribe=False)

    async def subscribe_to_topic_async(self, tokens, topic) -> TopicManagementResponse:
        """Subscribes a list of registration tokens to an FCM topic asynchronously
        via the FCM v1 API."""
        return await self._make_topic_management_request_v1_async(
            tokens, topic, is_subscribe=True)

    async def unsubscribe_from_topic_async(self, tokens, topic) -> TopicManagementResponse:
        """Unsubscribes a list of registration tokens from an FCM topic asynchronously
        via the FCM v1 API."""
        return await self._make_topic_management_request_v1_async(
            tokens, topic, is_subscribe=False)

    def _make_topic_management_request_v1(
        self, tokens, topic, is_subscribe: bool
    ) -> TopicManagementResponse:
        """Helper method that sends topic subscription requests via FCM v1 API."""
        tokens_list, topic_name = self._validate_topic_management_args(tokens, topic)

        def send_request(token: str):
            encoded_token = urllib.parse.quote(token, safe='')
            encoded_topic = urllib.parse.quote(topic_name, safe='')
            base_url = f'{self._fcm_topic_url}/{encoded_token}/topicSubscriptions'
            if is_subscribe:
                url = f'{base_url}?topic_name={encoded_topic}'
                method = 'post'
                json_data = {}
            else:
                url = f'{base_url}/{encoded_topic}?allow_missing=true'
                method = 'delete'
                json_data = None

            try:
                self._client.request(
                    method,
                    url=url,
                    headers=self._fcm_headers,
                    json=json_data,
                )
                return {'success': True}
            except requests.exceptions.RequestException as error:
                return self._build_topic_subscription_result_from_requests_error(
                    error, is_subscribe)

        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(len(tokens_list), 100)
            ) as executor:
                results = list(executor.map(send_request, tokens_list))
                return self._parse_topic_management_results(results)
        except Exception as error:
            raise exceptions.UnknownError(
                message=f'Unknown error while making remote service calls: {error}',
                cause=error)

    async def _make_topic_management_request_v1_async(
        self, tokens, topic, is_subscribe: bool
    ) -> TopicManagementResponse:
        """Helper method that sends topic subscription requests asynchronously via FCM v1 API."""
        tokens_list, topic_name = self._validate_topic_management_args(tokens, topic)
        semaphore = asyncio.Semaphore(100)

        async def send_request_async(token: str):
            encoded_token = urllib.parse.quote(token, safe='')
            encoded_topic = urllib.parse.quote(topic_name, safe='')
            base_url = f'{self._fcm_topic_url}/{encoded_token}/topicSubscriptions'
            if is_subscribe:
                url = f'{base_url}?topic_name={encoded_topic}'
                method = 'post'
                json_data = {}
            else:
                url = f'{base_url}/{encoded_topic}?allow_missing=true'
                method = 'delete'
                json_data = None

            async with semaphore:
                try:
                    await self._async_client.request(
                        method,
                        url=url,
                        headers=self._fcm_headers,
                        json=json_data,
                    )
                    return {'success': True}
                except httpx.HTTPError as error:
                    return self._build_topic_subscription_result_from_httpx_error(
                        error, is_subscribe)
                except requests.exceptions.RequestException as error:
                    return self._build_topic_subscription_result_from_requests_error(
                        error, is_subscribe)

        try:
            results = await asyncio.gather(*[send_request_async(token) for token in tokens_list])
            return self._parse_topic_management_results(results)
        except Exception as error:
            raise exceptions.UnknownError(
                message=f'Unknown error while making remote service calls: {error}',
                cause=error)

    @classmethod
    def _get_topic_error_code(cls, error_dict: dict, status_code: int) -> str:
        """Extracts the error code for a topic subscription error response."""
        error_data = error_dict.get('error')
        if isinstance(error_data, str) and error_data:
            return error_data
        if isinstance(error_data, dict):
            details = error_data.get('details')
            if isinstance(details, list):
                fcm_error_type = 'type.googleapis.com/google.firebase.fcm.v1.FcmError'
                for element in details:
                    if isinstance(element, dict) and element.get('@type') == fcm_error_type:
                        code = element.get('errorCode')
                        if code:
                            return code
            status = error_data.get('status')
            if status:
                return status
            message = error_data.get('message')
            if message:
                return message

        status_map = {
            400: 'INVALID_ARGUMENT',
            401: 'PERMISSION_DENIED',
            403: 'PERMISSION_DENIED',
            404: 'NOT_FOUND',
            429: 'RESOURCE_EXHAUSTED',
            500: 'INTERNAL',
            503: 'DEADLINE_EXCEEDED',
        }
        return status_map.get(status_code, 'UNKNOWN_ERROR')

    def _build_topic_subscription_result_from_requests_error(self, error, is_subscribe):
        """Constructs a result dict from a requests error."""
        if error.response is not None:
            if is_subscribe and error.response.status_code == 409:
                return {'success': True}
            error_dict = {}
            try:
                parsed = error.response.json()
                if isinstance(parsed, dict):
                    error_dict = parsed
            except ValueError:
                pass

            error_data = error_dict.get('error')
            if is_subscribe and isinstance(error_data, dict) and (
                error_data.get('status') == 'ALREADY_EXISTS'
            ):
                return {'success': True}

            error_code = self._get_topic_error_code(error_dict, error.response.status_code)
            return {'success': False, 'error': error_code}

        return {'success': False, 'error': 'UNKNOWN_ERROR'}

    def _build_topic_subscription_result_from_httpx_error(self, error, is_subscribe):
        """Constructs a result dict from an httpx error."""
        if isinstance(error, httpx.HTTPStatusError):
            if is_subscribe and error.response.status_code == 409:
                return {'success': True}
            error_dict = {}
            try:
                parsed = error.response.json()
                if isinstance(parsed, dict):
                    error_dict = parsed
            except ValueError:
                pass

            error_data = error_dict.get('error')
            if is_subscribe and isinstance(error_data, dict) and (
                error_data.get('status') == 'ALREADY_EXISTS'
            ):
                return {'success': True}

            error_code = self._get_topic_error_code(error_dict, error.response.status_code)
            return {'success': False, 'error': error_code}

        return {'success': False, 'error': 'UNKNOWN_ERROR'}

    def _parse_topic_management_results(self, results) -> TopicManagementResponse:
        """Parses individual request results into a TopicManagementResponse."""
        formatted_results = []
        for result in results:
            if result.get('success'):
                formatted_results.append({})
            else:
                formatted_results.append({'error': result.get('error', 'UNKNOWN_ERROR')})
        return TopicManagementResponse({'results': formatted_results})

    def make_topic_management_request(self, tokens, topic, operation):
        """Invokes the IID service for topic management functionality."""
        if isinstance(tokens, str):
            tokens = [tokens]
        if not isinstance(tokens, list) or not tokens:
            raise ValueError('Tokens must be a string or a non-empty list of strings.')
        invalid_str = [t for t in tokens if not isinstance(t, str) or not t]
        if invalid_str:
            raise ValueError('Tokens must be non-empty strings.')

        if not isinstance(topic, str) or not topic:
            raise ValueError('Topic must be a non-empty string.')
        if not topic.startswith('/topics/'):
            topic = f'/topics/{topic}'
        data = {
            'to': topic,
            'registration_tokens': tokens,
        }
        url = f'{_MessagingService.IID_URL}/{operation}'
        try:
            resp = self._client.body(
                'post',
                url=url,
                json=data,
                headers=_MessagingService.IID_HEADERS
            )
        except requests.exceptions.RequestException as error:
            raise self._handle_iid_error(error)
        return TopicManagementResponse(resp)

    def _message_data(self, message, dry_run):
        data = {'message': _MessagingService.encode_message(message)}
        if dry_run:
            data['validate_only'] = True
        return data

    def _postproc(self, _, body):
        """Handle response from batch API request."""
        # This only gets called for 2xx responses.
        return json.loads(body.decode())

    def _handle_fcm_error(self, error):
        """Handles errors received from the FCM API."""
        return _utils.handle_platform_error_from_requests(
            error, _MessagingService._build_fcm_error_requests)

    def _handle_fcm_httpx_error(self, error: httpx.HTTPError) -> exceptions.FirebaseError:
        """Handles errors received from the FCM API."""
        return _utils.handle_platform_error_from_httpx(
            error, _MessagingService._build_fcm_error_httpx)

    def _handle_iid_error(self, error):
        """Handles errors received from the Instance ID API."""
        if error.response is None:
            raise _utils.handle_requests_error(error)

        data = {}
        try:
            parsed_body = error.response.json()
            if isinstance(parsed_body, dict):
                data = parsed_body
        except ValueError:
            pass

        # IID error response format: {"error": "ErrorCode"}
        code = data.get('error')
        msg = None
        if code:
            msg = f'Error while calling the IID service: {code}'
        else:
            msg = (
                f'Unexpected HTTP response with status: {error.response.status_code}; body: '
                f'{error.response.content.decode()}'
            )

        return _utils.handle_requests_error(error, msg)

    def close(self) -> None:
        asyncio.run(self._async_client.aclose())

    @classmethod
    def _build_fcm_error_requests(cls, error, message, error_dict):
        """Parses an error response from the FCM API and creates a FCM-specific exception if
        appropriate."""
        exc_type = cls._build_fcm_error(error_dict)
        # pylint: disable=not-callable
        return exc_type(message, cause=error, http_response=error.response) if exc_type else None

    @classmethod
    def _build_fcm_error_httpx(
            cls,
            error: httpx.HTTPError,
            message: str,
            error_dict: Optional[Dict[str, Any]]
        ) -> Optional[exceptions.FirebaseError]:
        """Parses a httpx error response from the FCM API and creates a FCM-specific exception if
        appropriate."""
        exc_type = cls._build_fcm_error(error_dict)
        if isinstance(error, httpx.HTTPStatusError):
            # pylint: disable=not-callable
            return exc_type(
                message, cause=error, http_response=error.response) if exc_type else None
        # pylint: disable=not-callable
        return exc_type(message, cause=error) if exc_type else None

    @classmethod
    def _build_fcm_error(
            cls,
            error_dict: Optional[Dict[str, Any]]
        ) -> Optional[Callable[..., exceptions.FirebaseError]]:
        """Parses an error response to determine the appropriate FCM-specific error type."""
        if not error_dict:
            return None
        fcm_code = None
        for detail in error_dict.get('details', []):
            if detail.get('@type') == 'type.googleapis.com/google.firebase.fcm.v1.FcmError':
                fcm_code = detail.get('errorCode')
                break
        return _MessagingService.FCM_ERROR_TYPES.get(fcm_code) if fcm_code else None
