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

"""Tests for firebase_admin.remote_config."""
import json
import pytest
import firebase_admin
from firebase_admin import remote_config
from firebase_admin.remote_config import _REMOTE_CONFIG_ATTRIBUTE
from firebase_admin.remote_config import _RemoteConfigService, ServerTemplateData

from firebase_admin import _utils
from tests import testutils

class MockAdapter(testutils.MockAdapter):
    """A Mock HTTP Adapter that Firebase Remote Config with ETag in header."""

    ETAG = 'etag'

    def __init__(self, data, status, recorder, etag=ETAG):
        testutils.MockAdapter.__init__(self, data, status, recorder)
        self._etag = etag

    def send(self, request, **kwargs):
        resp = super(MockAdapter, self).send(request, **kwargs)
        resp.headers = {'etag': self._etag}
        return resp


class TestRemoteConfigServiceClient:
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def test_rc_instance_get_server_template(self):
        recorder = []
        response = json.dumps({
            'parameters': {
                'test_key': 'test_value'
            },
            'conditions': [],
            'parameterGroups': {},
            'version': 'test'
            })

        rc_instance = _utils.get_app_service(firebase_admin.get_app(),
                                             _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)
        rc_instance._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(response, 200, recorder))

        template = rc_instance.get_server_template()

        assert template.parameters == dict(test_key="test_value")
        assert str(template.version) == 'test'
        assert str(template.etag) == 'etag'

    def test_rc_instance_get_server_template_empty_params(self):
        recorder = []
        response = json.dumps({
            'conditions': [],
            'parameterGroups': {},
            'version': 'test'
            })

        rc_instance = _utils.get_app_service(firebase_admin.get_app(),
                                             _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)
        rc_instance._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(response, 200, recorder))

        template = rc_instance.get_server_template()

        assert template.parameters == {}
        assert str(template.version) == 'test'
        assert str(template.etag) == 'etag'


class TestRemoteConfigService:
    @classmethod
    def setup_class(cls):
        cred = testutils.MockCredential()
        firebase_admin.initialize_app(cred, {'projectId': 'project-id'})

    @classmethod
    def teardown_class(cls):
        testutils.cleanup_apps()

    def test_init_server_template(self):
        app = firebase_admin.get_app()
        template_data = {
            'conditions': [],
            'parameters': {
                'test_key': 'test_value'
            },
            'parameterGroups': '',
            'version': '',
        }

        template = remote_config.init_server_template(
            app=app,
            template_data=ServerTemplateData('etag', template_data)  # Use ServerTemplateData here
        )

        config = template.evaluate()
        assert config.get_string('test_key') == 'test_value'

    @pytest.mark.asyncio
    async def test_get_server_template(self):
        app = firebase_admin.get_app()
        rc_instance = _utils.get_app_service(app,
                                             _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)

        recorder = []
        response = json.dumps({
            'parameters': {
                'test_key': 'test_value'
            },
            'conditions': [],
            'parameterGroups': {},
            'version': 'test'
            })

        rc_instance._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(response, 200, recorder))

        template = await remote_config.get_server_template(app=app)

        config = template.evaluate()
        assert config.get_string('test_key') == 'test_value'
