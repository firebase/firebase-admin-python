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

"""Tests for firebase_admin.instance_id."""

import pytest

import firebase_admin
from firebase_admin import exceptions
from firebase_admin import instance_id
from firebase_admin import _http_client
from tests import testutils


http_errors = {
    400: (
        'Instance ID "test_iid": Malformed instance ID argument.',
        exceptions.InvalidArgumentError),
    401: (
        'Instance ID "test_iid": Request not authorized.',
        exceptions.UnauthenticatedError),
    403: (
        ('Instance ID "test_iid": Project does not match instance ID or the client does not have '
         'sufficient privileges.'),
        exceptions.PermissionDeniedError),
    404: (
        'Instance ID "test_iid": Failed to find the instance ID.',
        exceptions.NotFoundError),
    409: (
        'Instance ID "test_iid": Already deleted.',
        exceptions.ConflictError),
    429: (
        'Instance ID "test_iid": Request throttled out by the backend server.',
        exceptions.ResourceExhaustedError),
    500: (
        'Instance ID "test_iid": Internal server error.',
        exceptions.InternalError),
    503: (
        'Instance ID "test_iid": Backend servers are over capacity. Try again later.',
        exceptions.UnavailableError),
}

class TestDeleteInstanceId:

    def teardown_method(self):
        testutils.cleanup_apps()

    def _instrument_iid_service(self, app, status=200, payload='True'):
        iid_service = instance_id._get_iid_service(app)
        recorder = []
        iid_service._client.session.mount(
            instance_id._IID_SERVICE_URL,
            testutils.MockAdapter(payload, status, recorder))
        return iid_service, recorder

    def _get_url(self, project_id, iid):
        return instance_id._IID_SERVICE_URL + 'project/{0}/instanceId/{1}'.format(project_id, iid)

    def test_no_project_id(self):
        def evaluate():
            firebase_admin.initialize_app(testutils.MockCredential())
            with pytest.raises(ValueError):
                instance_id.delete_instance_id('test')
        testutils.run_without_project_id(evaluate)

    def test_default_timeout(self):
        cred = testutils.MockCredential()
        app = firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        iid_service = instance_id._get_iid_service(app)
        assert iid_service._client.timeout == _http_client.DEFAULT_TIMEOUT_SECONDS

    def test_delete_instance_id(self):
        cred = testutils.MockCredential()
        app = firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        _, recorder = self._instrument_iid_service(app)
        instance_id.delete_instance_id('test_iid')
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == self._get_url('explicit-project-id', 'test_iid')

    def test_delete_instance_id_with_explicit_app(self):
        cred = testutils.MockCredential()
        app = firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        _, recorder = self._instrument_iid_service(app)
        instance_id.delete_instance_id('test_iid', app)
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == self._get_url('explicit-project-id', 'test_iid')

    @pytest.mark.parametrize('status', http_errors.keys())
    def test_delete_instance_id_error(self, status):
        cred = testutils.MockCredential()
        app = firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        _, recorder = self._instrument_iid_service(app, status, 'some error')
        msg, exc = http_errors.get(status)
        with pytest.raises(exc) as excinfo:
            instance_id.delete_instance_id('test_iid')
        assert str(excinfo.value) == msg
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        if status != 401:
            assert len(recorder) == 1
        else:
            # 401 responses are automatically retried by google-auth
            assert len(recorder) == 3
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == self._get_url('explicit-project-id', 'test_iid')

    def test_delete_instance_id_unexpected_error(self):
        cred = testutils.MockCredential()
        app = firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        _, recorder = self._instrument_iid_service(app, 501, 'some error')
        with pytest.raises(exceptions.UnknownError) as excinfo:
            instance_id.delete_instance_id('test_iid')
        url = self._get_url('explicit-project-id', 'test_iid')
        message = 'Instance ID "test_iid": 501 Server Error: None for url: {0}'.format(url)
        assert str(excinfo.value) == message
        assert excinfo.value.cause is not None
        assert excinfo.value.http_response is not None
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == url

    @pytest.mark.parametrize('iid', [None, '', 0, 1, True, False, list(), dict(), tuple()])
    def test_invalid_instance_id(self, iid):
        cred = testutils.MockCredential()
        app = firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        _, recorder = self._instrument_iid_service(app)
        with pytest.raises(ValueError):
            instance_id.delete_instance_id(iid)
        assert len(recorder) == 0
