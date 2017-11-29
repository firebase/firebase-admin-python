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

import os

import pytest

import firebase_admin
from firebase_admin import instance_id
from tests import testutils


http_errors = {
    404: 'Failed to find the specified instance ID',
    429: 'Request throttled out by the backend server',
    500: 'Internal server error',
}

class TestDeleteInstanceId(object):

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
        env_var = 'GCLOUD_PROJECT'
        gcloud_project = os.environ.get(env_var)
        if gcloud_project:
            del os.environ[env_var]
        try:
            firebase_admin.initialize_app(testutils.MockCredential())
            with pytest.raises(ValueError):
                instance_id.delete_instance_id('test')
        finally:
            if gcloud_project:
                os.environ[env_var] = gcloud_project

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
        with pytest.raises(instance_id.ApiCallError) as excinfo:
            instance_id.delete_instance_id('test_iid')
        assert str(excinfo.value) == http_errors.get(status)
        assert excinfo.value.detail is not None
        assert len(recorder) == 1
        assert recorder[0].method == 'DELETE'
        assert recorder[0].url == self._get_url('explicit-project-id', 'test_iid')

    def test_delete_instance_id_unexpected_error(self):
        cred = testutils.MockCredential()
        app = firebase_admin.initialize_app(cred, {'projectId': 'explicit-project-id'})
        _, recorder = self._instrument_iid_service(app, 501, 'some error')
        with pytest.raises(instance_id.ApiCallError) as excinfo:
            instance_id.delete_instance_id('test_iid')
        url = self._get_url('explicit-project-id', 'test_iid')
        message = '501 Server Error: None for url: {0}'.format(url)
        assert str(excinfo.value) == message
        assert excinfo.value.detail is not None
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
        assert len(recorder) is 0
