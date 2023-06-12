# Copyright 2023 Google Inc.
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

"""Test cases for the firebase_admin.project_config_mgt module."""

import json

import pytest

from tests import testutils

import firebase_admin
from firebase_admin import project_config_mgt
from firebase_admin import multi_factor_config_mgt


ADJACENT_INTERVALS = 5

GET_PROJECT_RESPONSE = """{
    "mfaConfig":{
        "providerConfigs":[
            {
                "state":"ENABLED",
                "totpProviderConfig": {
                    "adjacentIntervals": 5
                }
            }
        ]
    }
}"""

MOCK_GET_USER_RESPONSE = testutils.resource('get_user.json')
INVALID_BOOLEANS = ['', 1, 0, list(), tuple(), dict()]

PROJECT_CONFIG_MGT_URL_PREFIX = 'https://identitytoolkit.googleapis.com/v2/projects'


@pytest.fixture(scope='module')
def project_config_mgt_app():
    app = firebase_admin.initialize_app(
        testutils.MockCredential(), name='projectMgt', options={'projectId': 'project-id'})
    yield app
    firebase_admin.delete_app(app)


def _instrument_project_config_mgt(app, status, payload):
    service = project_config_mgt._get_project_config_mgt_service(app)
    recorder = []
    service.client.session.mount(
        project_config_mgt._ProjectConfigManagementService.PROJECT_CONFIG_MGT_URL,
        testutils.MockAdapter(payload, status, recorder))
    return service, recorder


class TestProjectConfig:

    @pytest.mark.parametrize('data', [None, 'foo', 0, 1, True, False, list(), tuple()])
    def test_invalid_data(self, data):
        with pytest.raises(ValueError):
            project_config_mgt.ProjectConfig(data)

    def test_project_config(self):
        data = {
            'mfa': {
                'providerConfigs': [
                    {
                        'state': 'ENABLED',
                        'totpProviderConfig': {
                            'adjacentIntervals': ADJACENT_INTERVALS,
                        }
                    }
                ]
            }
        }
        project_config = project_config_mgt.ProjectConfig(data)
        _assert_project_config(project_config)

    def test_project_optional_params(self):
        data = {
            'name': 'test-project',
        }
        project = project_config_mgt.ProjectConfig(data)
        assert project.multi_factor_config is None


class TestGetProjectConfig:

    def test_get_project_config(self, project_config_mgt_app):
        _, recorder = _instrument_project_config_mgt(
            project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
        project_config = project_config_mgt.get_project_config(app=project_config_mgt_app)

        _assert_project_config(project_config)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/project-id/config'.format(PROJECT_CONFIG_MGT_URL_PREFIX)


class TestUpdateProjectConfig:

    def test_update_project_no_args(self, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project_config(app=project_config_mgt_app)
        assert str(excinfo.value).startswith('At least one parameter must be specified for update')

    @pytest.mark.parametrize('multi_factor_config', ['foo', 0, 1, True, False, list(), tuple()])
    def test_invalid_multi_factor_config_type(self, multi_factor_config, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project_config(multi_factor_config=multi_factor_config,
                                                     app=project_config_mgt_app)
        assert str(excinfo.value).startswith(
            'multi_factor_config must be of type MultiFactorConfig.')

    def test_update_project_config(self, project_config_mgt_app):
        _, recorder = _instrument_project_config_mgt(
            project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
        mfa_object = multi_factor_config_mgt.MultiFactorConfig(
            provider_configs=[
                multi_factor_config_mgt.ProviderConfig(
                    state=multi_factor_config_mgt.ProviderConfig.State.ENABLED,
                    totp_provider_config=multi_factor_config_mgt.TOTPProviderConfig(
                        adjacent_intervals=ADJACENT_INTERVALS
                    )
                )
            ]
        )
        project_config = project_config_mgt.update_project_config(
            multi_factor_config=mfa_object, app=project_config_mgt_app)

        mask = ['mfa.providerConfigs']

        _assert_project_config(project_config)
        self._assert_request(recorder, {
            'mfa': {
                'providerConfigs': [
                    {
                        'state': 'ENABLED',
                        'totpProviderConfig': {
                            'adjacentIntervals': ADJACENT_INTERVALS,
                        }
                    }
                ]
            }
        }, mask)

    def _assert_request(self, recorder, body, mask):
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'PATCH'
        assert req.url == '{0}/project-id/config?updateMask={1}'.format(
            PROJECT_CONFIG_MGT_URL_PREFIX, ','.join(mask))
        got = json.loads(req.body.decode())
        assert got == body

def _assert_multi_factor_config(multi_factor_config):
    assert isinstance(multi_factor_config, multi_factor_config_mgt.MultiFactorServerConfig)
    assert len(multi_factor_config.provider_configs) == 1
    assert isinstance(multi_factor_config.provider_configs, list)
    for provider_config in multi_factor_config.provider_configs:
        assert isinstance(provider_config, multi_factor_config_mgt.MultiFactorServerConfig
                          .ProviderServerConfig)
        assert provider_config.state == 'ENABLED'
        assert isinstance(provider_config.totp_provider_config,
                          multi_factor_config_mgt.MultiFactorServerConfig.ProviderServerConfig
                          .TOTPProviderServerConfig)
        assert provider_config.totp_provider_config.adjacent_intervals == ADJACENT_INTERVALS

def _assert_project_config(project_config):
    if project_config.multi_factor_config is not None:
        _assert_multi_factor_config(project_config.multi_factor_config)
