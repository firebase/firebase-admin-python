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

"""Firebase Cloud Messaging Async module."""

import asyncio

from typing import (
    Optional,
    Any,
    Type,
    List,
    Dict
)

import firebase_admin
from firebase_admin.exceptions import FirebaseError
from firebase_admin import (
    App
)
from firebase_admin.messaging import TopicManagementResponse
from firebase_admin._http_client_async import (
    JsonHttpClientAsync,
    ClientResponseWithBodyError,
    DEFAULT_TIMEOUT_SECONDS
)
from firebase_admin._messaging_encoder import (
    Message,
    MessageEncoder
)
from firebase_admin._messaging_utils import (
    QuotaExceededError,
    SenderIdMismatchError,
    ThirdPartyAuthError,
    UnregisteredError
)
from firebase_admin import _utils



_MESSAGING_ATTRIBUTE = '_messaging_async'


__all__: List[str] = [
    'send',
    # 'send_all',
    # 'send_multicast',
    'subscribe_to_topic',
    'unsubscribe_from_topic',
]

# pylint: disable=unsubscriptable-object
# TODO:(/b)Remove false positive unsubscriptable-object lint warnings caused by type hints Optional type.
# This is fixed in pylint 2.7.0 but this version introduces new lint rules and requires multiple
# file changes.
def _get_messaging_service(app: Optional[App]) -> "_MessagingServiceAsync":
    return _utils.get_app_service(app, _MESSAGING_ATTRIBUTE, _MessagingServiceAsync)

async def send(message: Message, dry_run: bool = False, app: Optional[App] = None) -> str:
    """Sends the given message via Firebase Cloud Messaging (FCM).

    If the ``dry_run`` mode is enabled, the message will not be actually delivered to the
    recipients. Instead FCM performs all the usual validations, and emulates the send operation.

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
    return await _get_messaging_service(app).send(message, dry_run)

async def subscribe_to_topic(
        tokens: List[str],
        topic: str, app: Optional[App] = None
    ) -> TopicManagementResponse:
    """Subscribes a list of registration tokens to an FCM topic.

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
    return await _get_messaging_service(app).make_topic_management_request(
        tokens, topic, 'iid/v1:batchAdd')

async def unsubscribe_from_topic(
        tokens: List[str],
        topic: str,
        app: Optional[App] = None
    ) -> TopicManagementResponse:
    """Unsubscribes a list of registration tokens from an FCM topic.

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
    return await _get_messaging_service(app).make_topic_management_request(
        tokens, topic, 'iid/v1:batchRemove')


class _MessagingServiceAsync:
    """Service class that implements Firebase Cloud Messaging (FCM) functionality asynchronously."""

    FCM_URL: str = 'https://fcm.googleapis.com/v1/projects/{0}/messages:send'
    FCM_BATCH_URL: str = 'https://fcm.googleapis.com/batch'
    IID_URL: str = 'https://iid.googleapis.com'
    IID_HEADERS: Dict[str, str] = {'access_token_auth': 'true'}
    JSON_ENCODER: MessageEncoder = MessageEncoder()

    FCM_ERROR_TYPES: Dict[str, Type[FirebaseError]] = {
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
        self._fcm_url = _MessagingServiceAsync.FCM_URL.format(project_id)
        self._fcm_headers = {
            'X-GOOG-API-FORMAT-VERSION': '2',
            'X-FIREBASE-CLIENT': 'fire-admin-python/{0}'.format(firebase_admin.__version__),
        }
        timeout = app.options.get('httpTimeout', DEFAULT_TIMEOUT_SECONDS)
        self._credential = app.credential.get_credential_async()
        self._client = JsonHttpClientAsync(credential=self._credential, timeout=timeout)
        self._loop = asyncio.get_event_loop()

    def close(self) -> None:
        if self._client is not None:
            self._loop.run_until_complete(self._client.close())
            self._client = None # type: ignore[assignment]

    @classmethod
    def encode_message(cls, message: Message) -> Dict[str, Any]:
        if not isinstance(message, Message):
            raise ValueError('Message must be an instance of messaging.Message class.')
        return cls.JSON_ENCODER.default(message)

    async def send(self, message: Message, dry_run: bool = False) -> str:
        """Sends the given message to FCM via the FCM v1 API."""
        data = self._message_data(message, dry_run)
        try:
            resp = await self._client.body(
                'post',
                url=self._fcm_url,
                headers=self._fcm_headers,
                json=data
            )
        except ClientResponseWithBodyError as error:
            raise await self._handle_fcm_error(error)
        else:
            return resp['name']

    async def make_topic_management_request(self, tokens, topic, operation):
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
            topic = '/topics/{0}'.format(topic)
        data = {
            'to': topic,
            'registration_tokens': tokens,
        }
        url = '{0}/{1}'.format(_MessagingServiceAsync.IID_URL, operation)
        try:
            resp = await self._client.body(
                'post',
                url=url,
                json=data,
                headers=_MessagingServiceAsync.IID_HEADERS
            )
        except ClientResponseWithBodyError as error:
            raise self._handle_iid_error(error)
        else:
            return TopicManagementResponse(resp)

    def _message_data(self, message: Message, dry_run: bool) -> Dict[str, Any]:
        data = {'message': _MessagingServiceAsync.encode_message(message)}
        if dry_run:
            data['validate_only'] = True # type: ignore[assignment]
        return data

    async def _handle_fcm_error(self, error: ClientResponseWithBodyError) -> FirebaseError:
        """Handles errors received from the FCM API."""
        return await _utils.handle_platform_error_from_aiohttp(
            error, _MessagingServiceAsync._build_fcm_error_aiohttp)

    def _handle_iid_error(self, error: ClientResponseWithBodyError) -> FirebaseError:
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
            msg = 'Error while calling the IID service: {0}'.format(code)
        else:
            msg = 'Unexpected HTTP response with status: {0}; body: {1}'.format(
                error.response.status_code, error.response.content.decode())

        return _utils.handle_requests_error(error, msg)

    @classmethod
    def _build_fcm_error_aiohttp(
            cls,
            error: ClientResponseWithBodyError,
            message: Message,
            error_dict: Dict[Any, Any]
        ) -> Optional[FirebaseError]:
        """Parses an aiohttp error response from the FCM API and creates a FCM-specific exception if
        appropriate."""
        exc_type: Optional[Type[FirebaseError]] = cls._build_fcm_error(error_dict)
        return exc_type( # type: ignore[call-arg]
            message,
            cause=error,
            http_response=error.request_info
        ) if exc_type else None

    @classmethod
    def _build_fcm_error(cls, error_dict: Dict[str, Any]) -> Optional[Type[FirebaseError]]:
        if not error_dict:
            return None
        fcm_code: Optional[str] = None
        for detail in error_dict.get('details', []):
            if detail.get('@type') == 'type.googleapis.com/google.firebase.fcm.v1.FcmError':
                fcm_code = detail.get('errorCode')
                break
        return _MessagingServiceAsync.FCM_ERROR_TYPES.get(fcm_code) # type: ignore[arg-type]
