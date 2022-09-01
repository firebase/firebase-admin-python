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

"""Test cases for the firebase_admin.messaging module."""
import json

import pytest

import firebase_admin
from firebase_admin import exceptions
from firebase_admin import messaging
from firebase_admin import messaging_async
from firebase_admin import _http_client_async
from tests import testutils


NON_STRING_ARGS = [[], tuple(), {}, True, False, 1, 0]
NON_DICT_ARGS = ['', [], tuple(), True, False, 1, 0, {1: 'foo'}, {'foo': 1}]
NON_OBJECT_ARGS = [[], tuple(), {}, 'foo', 0, 1, True, False]
NON_LIST_ARGS = ['', tuple(), {}, True, False, 1, 0, [1], ['foo', 1]]
NON_UINT_ARGS = ['1.23s', [], tuple(), {}, -1.23]
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


def check_exception(exception, message, status):
    assert isinstance(exception, exceptions.FirebaseError)
    assert str(exception) == message
    assert exception.cause is not None
    assert exception.http_response is not None
    assert exception.http_response.status_code == status


class TestTimeoutAsync:

    def teardown(self):
        testutils.cleanup_apps()

    def _instrument_service(self, response):
        app = firebase_admin.get_app()
        fcm_service_async = messaging_async._get_messaging_service(app)
        recorder = []
        credentials = fcm_service_async._client.session.credentials
        session = testutils.MockAuthorizedSession(json.dumps(response), 200, recorder, credentials)
        fcm_service_async._client._session = session
        return recorder

    def _check_timeout(self, recorder, timeout):
        assert len(recorder) == 1
        if timeout is None:
            assert recorder[0].extra_kwargs['timeout'] is None
        else:
            assert recorder[0].extra_kwargs['timeout'] == pytest.approx(timeout, 0.001)

    @pytest.mark.parametrize('options, timeout', [
        ({'httpTimeout': 4}, 4),
        ({'httpTimeout': None}, None),
        ({}, _http_client_async.DEFAULT_TIMEOUT_SECONDS),
    ])
    @pytest.mark.asyncio
    async def test_send_async(self, options, timeout):
        cred = testutils.MockCredentialAsync()
        all_options = {'projectId': 'explicit-project-id'}
        all_options.update(options)
        firebase_admin.initialize_app(cred, all_options)
        recorder = self._instrument_service({'name': 'message-id'})
        msg = messaging.Message(topic='foo')
        await messaging_async.send(msg)
        self._check_timeout(recorder, timeout)

    @pytest.mark.parametrize('options, timeout', [
        ({'httpTimeout': 4}, 4),
        ({'httpTimeout': None}, None),
        ({}, _http_client_async.DEFAULT_TIMEOUT_SECONDS),
    ])
    @pytest.mark.asyncio
    async def test_topic_management_custom_timeout(self, options, timeout):
        cred = testutils.MockCredentialAsync()
        all_options = {'projectId': 'explicit-project-id'}
        all_options.update(options)
        firebase_admin.initialize_app(cred, all_options)
        recorder = self._instrument_service({'results': [{}, {'error': 'error_reason'}]})
        await messaging_async.subscribe_to_topic(['1'], 'a')
        self._check_timeout(recorder, timeout)


class TestSendAsync:

    _DEFAULT_RESPONSE = json.dumps({'name': 'message-id'})
    _CLIENT_VERSION = f'fire-admin-python/{firebase_admin.__version__}'

    def setup(self):
        cred = testutils.MockCredentialAsync()
        firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})

    def teardown(self):
        testutils.cleanup_apps()

    def _instrument_messaging_service(self, app=None, status=200, payload=_DEFAULT_RESPONSE):
        if not app:
            app = firebase_admin.get_app()
        fcm_service_async = messaging_async._get_messaging_service(app)
        recorder = []

        credentials = fcm_service_async._client.session.credentials
        session = testutils.MockAuthorizedSession(payload, status, recorder, credentials)
        fcm_service_async._client._session = session

        return fcm_service_async, recorder

    def _get_url(self, project_id):
        return messaging_async._MessagingServiceAsync.FCM_URL.format(project_id)

    @pytest.mark.asyncio
    async def test_no_project_id(self):
        async def evaluate():
            app = firebase_admin.initialize_app(
                testutils.MockCredentialAsync(),
                name='no_project_id'
            )
            with pytest.raises(ValueError):
                await messaging_async.send(messaging.Message(topic='foo'), app=app)
        await testutils.run_without_project_id_async(evaluate)

    @pytest.mark.parametrize('msg', NON_OBJECT_ARGS + [None])
    @pytest.mark.asyncio
    async def test_invalid_send(self, msg):
        with pytest.raises(ValueError) as excinfo:
            await messaging_async.send(msg)
        assert str(excinfo.value) == 'Message must be an instance of messaging.Message class.'

    @pytest.mark.asyncio
    async def test_send_dry_run(self):
        _, recorder = self._instrument_messaging_service()
        msg = messaging.Message(topic='foo')
        msg_id = await messaging_async.send(msg, dry_run=True)
        assert msg_id == 'message-id'
        assert len(recorder) == 1
        assert recorder[0].method == 'post'
        assert recorder[0].url == self._get_url('explicit-project-id')
        assert recorder[0].extra_kwargs['headers']['X-GOOG-API-FORMAT-VERSION'] == '2'
        assert recorder[0].extra_kwargs['headers']['X-FIREBASE-CLIENT'] == self._CLIENT_VERSION
        body = {
            'message': messaging_async._MessagingServiceAsync.encode_message(msg),
            'validate_only': True,
        }
        assert recorder[0].extra_kwargs['json'] == body

    @pytest.mark.asyncio
    async def test_send(self):
        _, recorder = self._instrument_messaging_service()
        msg = messaging.Message(topic='foo')
        msg_id = await messaging_async.send(msg)
        assert msg_id == 'message-id'
        assert len(recorder) == 1
        assert recorder[0].method == 'post'
        assert recorder[0].url == self._get_url('explicit-project-id')
        assert recorder[0].extra_kwargs['headers']['X-GOOG-API-FORMAT-VERSION'] == '2'
        assert recorder[0].extra_kwargs['headers']['X-FIREBASE-CLIENT'] == self._CLIENT_VERSION
        body = {'message': messaging_async._MessagingServiceAsync.encode_message(msg)}
        assert recorder[0].extra_kwargs['json'] == body

    # # TODO: Implement remainding FCM error handling for aiohttp requests
    # @pytest.mark.parametrize('status,exc_type', HTTP_ERROR_CODES.items())
    # @pytest.mark.asyncio
    # async def test_send_error(self, status, exc_type):
    #     _, recorder = self._instrument_messaging_service(status=status, payload='{}')
    #     msg = messaging.Message(topic='foo')
    #     with pytest.raises(exc_type) as excinfo:
    #         await messaging_async.send(msg)
    #     expected = f'Unexpected HTTP response with status: {status}; body: {{}}'
    #     check_exception(excinfo.value, expected, status)
    #     assert len(recorder) == 1
    #     assert recorder[0].method == 'POST'
    #     assert recorder[0].url == self._get_url('explicit-project-id')
    #     assert recorder[0].extra_kwargs['headers']['X-GOOG-API-FORMAT-VERSION'] == '2'
    #     assert recorder[0].extra_kwargs['headers']['X-FIREBASE-CLIENT'] == self._CLIENT_VERSION
    #     body = {'message': messaging_async._MessagingServiceAsync.JSON_ENCODER.default(msg)}
    #     assert recorder[0].extra_kwargs['json'] == body

    # @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    # @pytest.mark.asyncio
    # async def test_send_detailed_error(self, status):
    #     payload = json.dumps({
    #         'error': {
    #             'status': 'INVALID_ARGUMENT',
    #             'message': 'test error'
    #         }
    #     })
    #     _, recorder = self._instrument_messaging_service(status=status, payload=payload)
    #     msg = messaging.Message(topic='foo')
    #     with pytest.raises(exceptions.InvalidArgumentError) as excinfo:
    #         await messaging_async.send(msg)
    #     check_exception(excinfo.value, 'test error', status)
    #     assert len(recorder) == 1
    #     assert recorder[0].method == 'post'
    #     assert recorder[0].url == self._get_url('explicit-project-id')
    #     body = {'message': messaging_async._MessagingServiceAsync.JSON_ENCODER.default(msg)}
    #     assert recorder[0].extra_kwargs['json'] == body

    # @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    # @pytest.mark.asyncio
    # async def test_send_canonical_error_code(self, status):
    #     payload = json.dumps({
    #         'error': {
    #             'status': 'NOT_FOUND',
    #             'message': 'test error'
    #         }
    #     })
    #     _, recorder = self._instrument_messaging_service(status=status, payload=payload)
    #     msg = messaging.Message(topic='foo')
    #     with pytest.raises(exceptions.NotFoundError) as excinfo:
    #         await messaging_async.send(msg)
    #     check_exception(excinfo.value, 'test error', status)
    #     assert len(recorder) == 1
    #     assert recorder[0].method == 'post'
    #     assert recorder[0].url == self._get_url('explicit-project-id')
    #     body = {'message': messaging_async._MessagingServiceAsync.JSON_ENCODER.default(msg)}
    #     assert recorder[0].extra_kwargs['json'] == body

    # @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    # @pytest.mark.parametrize('fcm_error_code, exc_type', FCM_ERROR_CODES.items())
    # @pytest.mark.asyncio
    # async def test_send_fcm_error_code(self, status, fcm_error_code, exc_type):
    #     payload = json.dumps({
    #         'error': {
    #             'status': 'INVALID_ARGUMENT',
    #             'message': 'test error',
    #             'details': [
    #                 {
    #                     '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError',
    #                     'errorCode': fcm_error_code,
    #                 },
    #             ],
    #         }
    #     })
    #     _, recorder = self._instrument_messaging_service(status=status, payload=payload)
    #     msg = messaging.Message(topic='foo')
    #     with pytest.raises(exc_type) as excinfo:
    #         await messaging_async.send(msg)
    #     check_exception(excinfo.value, 'test error', status)
    #     assert len(recorder) == 1
    #     assert recorder[0].method == 'post'
    #     assert recorder[0].url == self._get_url('explicit-project-id')
    #     body = {'message': messaging_async._MessagingServiceAsync.JSON_ENCODER.default(msg)}
    #     assert recorder[0].extra_kwargs['json'] == body

    # @pytest.mark.parametrize('status', HTTP_ERROR_CODES)
    # @pytest.mark.asyncio
    # async def test_send_unknown_fcm_error_code(self, status):
    #     payload = json.dumps({
    #         'error': {
    #             'status': 'INVALID_ARGUMENT',
    #             'message': 'test error',
    #             'details': [
    #                 {
    #                     '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError',
    #                     'errorCode': 'SOME_UNKNOWN_CODE',
    #                 },
    #             ],
    #         }
    #     })
    #     _, recorder = self._instrument_messaging_service(status=status, payload=payload)
    #     msg = messaging.Message(topic='foo')
    #     with pytest.raises(exceptions.InvalidArgumentError) as excinfo:
    #         await messaging_async.send(msg)
    #     check_exception(excinfo.value, 'test error', status)
    #     assert len(recorder) == 1
    #     assert recorder[0].method == 'post'
    #     assert recorder[0].url == self._get_url('explicit-project-id')
    #     body = {'message': messaging_async._MessagingServiceAsync.JSON_ENCODER.default(msg)}
    #     assert recorder[0].extra_kwargs['json'] == body


class TestTopicManagementAsync:

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

    def setup(self):
        cred = testutils.MockCredentialAsync()
        firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})

    def teardown(self):
        testutils.cleanup_apps()

    def _instrument_iid_service(self, app=None, status=200, payload=_DEFAULT_RESPONSE):
        if not app:
            app = firebase_admin.get_app()
        fcm_service_async = messaging_async._get_messaging_service(app)
        recorder = []

        credentials = fcm_service_async._client.session.credentials
        session = testutils.MockAuthorizedSession(payload, status, recorder, credentials)
        fcm_service_async._client._session = session

        return fcm_service_async, recorder

    def _get_url(self, path):
        return f'{messaging_async._MessagingServiceAsync.IID_URL}/{path}'

    @pytest.mark.parametrize('tokens', [None, '', [], {}, tuple()])
    @pytest.mark.asyncio
    async def test_invalid_tokens(self, tokens):
        expected = 'Tokens must be a string or a non-empty list of strings.'
        if isinstance(tokens, str):
            expected = 'Tokens must be non-empty strings.'

        with pytest.raises(ValueError) as excinfo:
            await messaging_async.subscribe_to_topic(tokens, 'test-topic')
        assert str(excinfo.value) == expected

        with pytest.raises(ValueError) as excinfo:
            await messaging_async.unsubscribe_from_topic(tokens, 'test-topic')
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('topic', NON_STRING_ARGS + [None, ''])
    @pytest.mark.asyncio
    async def test_invalid_topic(self, topic):
        expected = 'Topic must be a non-empty string.'
        with pytest.raises(ValueError) as excinfo:
            await messaging_async.subscribe_to_topic('test-token', topic)
        assert str(excinfo.value) == expected

        with pytest.raises(ValueError) as excinfo:
            await messaging_async.unsubscribe_from_topic('test-tokens', topic)
        assert str(excinfo.value) == expected

    @pytest.mark.parametrize('args', _VALID_ARGS)
    @pytest.mark.asyncio
    async def test_subscribe_to_topic(self, args):
        _, recorder = self._instrument_iid_service()
        resp = await messaging_async.subscribe_to_topic(args[0], args[1])
        self._check_response(resp)
        assert len(recorder) == 1
        assert recorder[0].method == 'post'
        assert recorder[0].url == self._get_url('iid/v1:batchAdd')
        assert recorder[0].extra_kwargs['json'] == args[2]

    # @pytest.mark.parametrize('status, exc_type', HTTP_ERROR_CODES.items())
    # @pytest.mark.asyncio
    # async def test_subscribe_to_topic_error(self, status, exc_type):
    #     _, recorder = self._instrument_iid_service(
    #         status=status, payload=self._DEFAULT_ERROR_RESPONSE)
    #     with pytest.raises(exc_type) as excinfo:
    #         await messaging_async.subscribe_to_topic('foo', 'test-topic')
    #     assert str(excinfo.value) == 'Error while calling the IID service: error_reason'
    #     assert len(recorder) == 1
    #     assert recorder[0].method == 'POST'
    #     assert recorder[0].url == self._get_url('iid/v1:batchAdd')

    # @pytest.mark.parametrize('status, exc_type', HTTP_ERROR_CODES.items())
    # @pytest.mark.asyncio
    # async def test_subscribe_to_topic_non_json_error(self, status, exc_type):
    #     _, recorder = self._instrument_iid_service(status=status, payload='not json')
    #     with pytest.raises(exc_type) as excinfo:
    #         await messaging_async.subscribe_to_topic('foo', 'test-topic')
    #     reason = f'Unexpected HTTP response with status: {status}; body: not json'
    #     assert str(excinfo.value) == reason
    #     assert len(recorder) == 1
    #     assert recorder[0].method == 'POST'
    #     assert recorder[0].url == self._get_url('iid/v1:batchAdd')

    @pytest.mark.parametrize('args', _VALID_ARGS)
    @pytest.mark.asyncio
    async def test_unsubscribe_from_topic(self, args):
        _, recorder = self._instrument_iid_service()
        resp = await messaging_async.unsubscribe_from_topic(args[0], args[1])
        self._check_response(resp)
        assert len(recorder) == 1
        assert recorder[0].method == 'post'
        assert recorder[0].url == self._get_url('iid/v1:batchRemove')
        assert recorder[0].extra_kwargs['json'] == args[2]

    # @pytest.mark.parametrize('status, exc_type', HTTP_ERROR_CODES.items())
    # @pytest.mark.asyncio
    # async def test_unsubscribe_from_topic_error(self, status, exc_type):
    #     _, recorder = self._instrument_iid_service(
    #         status=status, payload=self._DEFAULT_ERROR_RESPONSE)
    #     with pytest.raises(exc_type) as excinfo:
    #         await messaging_async.unsubscribe_from_topic('foo', 'test-topic')
    #     assert str(excinfo.value) == 'Error while calling the IID service: error_reason'
    #     assert len(recorder) == 1
    #     assert recorder[0].method == 'POST'
    #     assert recorder[0].url == self._get_url('iid/v1:batchRemove')

    # @pytest.mark.parametrize('status, exc_type', HTTP_ERROR_CODES.items())
    # @pytest.mark.asyncio
    # async def test_unsubscribe_from_topic_non_json_error(self, status, exc_type):
    #     _, recorder = self._instrument_iid_service(status=status, payload='not json')
    #     with pytest.raises(exc_type) as excinfo:
    #         await messaging_async.unsubscribe_from_topic('foo', 'test-topic')
    #     reason = f'Unexpected HTTP response with status: {status}; body: not json'
    #     assert str(excinfo.value) == reason
    #     assert len(recorder) == 1
    #     assert recorder[0].method == 'POST'
    #     assert recorder[0].url == self._get_url('iid/v1:batchRemove')

    def _check_response(self, resp):
        assert resp.success_count == 1
        assert resp.failure_count == 1
        assert len(resp.errors) == 1
        assert resp.errors[0].index == 1
        assert resp.errors[0].reason == 'error_reason'
