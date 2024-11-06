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
import firebase_admin
from firebase_admin.remote_config import _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService

from firebase_admin import _utils
from tests import testutils

class MockAdapter(testutils.MockAdapter):
    """A Mock HTTP Adapter that Firebase Remote Config with ETag in header."""

    ETAG = '0'

    def __init__(self, data, status, recorder, etag=ETAG):
        testutils.MockAdapter.__init__(self, data, status, recorder)
        self._etag = etag

    def send(self, request, **kwargs):
        resp = super(MockAdapter, self).send(request, **kwargs)
        resp.headers = {'etag': self._etag}
        return resp


class TestGetServerTemplate:
    _DEFAULT_APP = firebase_admin.initialize_app(testutils.MockCredential(), name='no_project_id')
    _RC_INSTANCE = _utils.get_app_service(_DEFAULT_APP,
                                          _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)

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
        self._RC_INSTANCE._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(response, 200, recorder))

        template = self._RC_INSTANCE.get_server_template()

        assert template.parameters == dict(test_key="test_value")
        assert str(template.version) == 'test'
        assert str(template.etag) == '0'

    def test_rc_instance_get_server_template_empty_params(self):
        recorder = []
        response = json.dumps({
            'conditions': [],
            'parameterGroups': {},
            'version': 'test'
            })

        self._RC_INSTANCE._client.session.mount(
            'https://firebaseremoteconfig.googleapis.com',
            MockAdapter(response, 200, recorder))

        template = self._RC_INSTANCE.get_server_template()

        assert template.parameters == {}
        assert str(template.version) == 'test'
        assert str(template.etag) == '0'
