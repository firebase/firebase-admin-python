# Copyright 2020 Google Inc.
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

from copy import copy
import json

import pytest

import firebase_admin
from firebase_admin import project_config_mgt
from tests import testutils


GET_PROJECT_RESPONSE = """{
    "multiFactorConfig":{
        "state":"ENABLED",
        "factorIds":["PHONE_SMS"],
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
    service = project_config_mgt._get_project_mgt_service(app)
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
            'multiFactorConfig':{
                'state':'ENABLED',
                'factorIds':['PHONE_SMS'],
                'providerConfigs': [
                    {
                        'state':'ENABLED',
                        'totpProviderConfig': {
                            'adjacentIntervals': 5,
                        }
                    }
                ]
            }
        }
        project = project_config_mgt.ProjectConfig(data)
        _assert_project(project)

    def test_project_optional_params(self):
        data = {
            'name': 'test-project',
        }
        project = project_config_mgt.ProjectConfig(data)
        assert project.mfa is None


class TestGetProject:

    def test_get_project(self, project_config_mgt_app):
        _, recorder = _instrument_project_config_mgt(
            project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
        project = project_config_mgt.get_project(app=project_config_mgt_app)

        _assert_project(project)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/project-id/config'.format(PROJECT_CONFIG_MGT_URL_PREFIX)


class TestUpdateProject:

    def test_update_project_no_args(self, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(app=project_config_mgt_app)
        assert str(excinfo.value).startswith('At least one parameter must be specified for update')

    @pytest.mark.parametrize('mfa_config', ['foo', 0, 1, True, False, list(), tuple()])
    def test_update_project_invalid_mfa_config_type(self, mfa_config, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith(
            'multiFactorConfig should be of valid type MultiFactorConfig')

    def test_invalid_multi_factor_config_params(self, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa={
                'state':'DISABLED',
                'invalid':{},
            }, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('invalid is not a valid MultiFactorConfig parameter')

    def test_update_project_undefined_mfa_config_state(self, project_config_mgt_app):
        mfa_config = {'factorIds':["PHONE_SMS"]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('multiFactorConfig.state should be defined')
    
    @pytest.mark.parametrize('state', ['', 1, True, False, [], (), {}, "foo"])
    def test_update_project_invalid_mfa_config_state(self, project_config_mgt_app, state):
        mfa_config = {'state': state}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith(
        'multiFactorConfig.state must be either "ENABLED" or "DISABLED"')

    @pytest.mark.parametrize('factor_ids', [True, False, 1, 0, 'foo', {}, dict(), tuple(), list()])
    def test_invalid_mfa_config_factor_ids_type(self, factor_ids, project_config_mgt_app):
        mfa_config = {'state': 'ENABLED', 'factorIds': factor_ids}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith(
            'multiFactorConfig.factorIds must be a defined list of AuthFactor type strings')

    @pytest.mark.parametrize('factor_ids', [[1, 2, 3], [True, False], ['foo', 'bar', {}]])
    def test_invalid_mfa_config_factor_ids(self, project_config_mgt_app, factor_ids):
        mfa_config = {'state': 'ENABLED', 'factorIds': factor_ids}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
            assert str(excinfo.value).startswith('factorId must be in {\'PHONE_SMS\'}')
    
    @pytest.mark.parametrize('provider_configs', [True, False, 1, 0, list(), tuple(), dict()])
    def test_invalid_mfa_config_provider_configs_type(
        self, project_config_mgt_app, provider_configs):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': provider_configs}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith(
            'multiFactorConfig.providerConfigs must be a valid list of providerConfig types')
    
    @pytest.mark.parametrize('provider_configs', [[True], [{}], [1, 2], 
    [{'state': 'DISABLED', 'totpProviderConfig': {}}, "foo"]])
    def test_invalid_mfa_config_provider_config(self, project_config_mgt_app, provider_configs):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': provider_configs}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith(
            'multiFactorConfig.providerConfigs must be a valid list of providerConfig types')

    def test_invalid_provider_config_params(self, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa={
                'state':'DISABLED',
                'providerConfigs':[
                    {
                        'state':'DISABLED',
                        'invalid':{},
                    },
                ],
            }, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('invalid is not a valid ProviderConfig parameter')

    def test_undefined_provider_config_state(self, project_config_mgt_app):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': [{'totpProviderConfig':{}}]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('providerConfig.state should be defined')
    
    @pytest.mark.parametrize('state', ['', 1, True, False, [], (), {}, "foo"])
    def test_invalid_provider_config_state(self, project_config_mgt_app, state):
        mfa_config = {'state': 'DISABLED', 
        'providerConfigs': [{'state':state, 'totpProviderConfig':{}}]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith(
            'providerConfig.state must be either "ENABLED" or "DISABLED"')

    @pytest.mark.parametrize('state', ['ENABLED', 'DISABLED'])
    def test_undefined_totp_provider_config(self, project_config_mgt_app, state):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': [{'state':state}]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith(
            'providerConfig.totpProviderConfig must be present')

    @pytest.mark.parametrize('totp_provider_config', [True, False, 1, 0, list(), tuple()])
    def test_invalid_totp_provider_config_type(self, project_config_mgt_app, totp_provider_config):
        mfa_config = {'state': 'DISABLED', 
        'providerConfigs': [{'state':'ENABLED', 'totpProviderConfig':totp_provider_config}]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith(
            'providerConfig.totpProviderConfig must be of valid type TotpProviderConfig')
    
    def test_invalid_totp_provider_config_params(self, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa={
                'state':'DISABLED',
                'providerConfigs':[
                    {
                        'state':'DISABLED',
                        'totpProviderConfig': {
                            'invalid':{},
                            'adjacentIntervals':5,
                        }
                    },
                ],
            }, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('invalid is not a valid TotpProviderConfig parameter')
    
    @pytest.mark.parametrize('adjacent_intervals', ['', -1, True, False, [], (), {}, "foo", None])
    def test_invalid_adjacent_intervals_type(self, project_config_mgt_app, adjacent_intervals):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': 
        [{'state':'ENABLED', 'totpProviderConfig':{'adjacentIntervals':adjacent_intervals}}]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith(
            'totpProviderConfig.adjacentIntervals must be a valid positive integer')

    def test_update_project(self, project_config_mgt_app):
        _, recorder = _instrument_project_config_mgt(
            project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
        mfa_config_data = {
                'state' : 'ENABLED',
                'factorIds':["PHONE_SMS"],
                'providerConfigs' : [
                    {
                        'state' : 'ENABLED',
                        'totpProviderConfig':{
                            'adjacentIntervals' : 5
                        }
                    }
                ]
        }
        project = project_config_mgt.update_project(
             mfa=mfa_config_data, app=project_config_mgt_app)

        mask = ['mfa.enabledProviders', 'mfa.providerConfigs', 'mfa.state']

        _assert_project(project)
        self._assert_request(recorder, {
            'mfa':{
                'state':'ENABLED',
                'enabledProviders':['PHONE_SMS'],
                'providerConfigs': [
                    {
                        'state':'ENABLED',
                        'totpProviderConfig': {
                            'adjacentIntervals':5,
                        }
                    }
                ]
            }
        }, mask)

    def test_update_project_valid_mfa_configs(self, project_config_mgt_app):
        mfa_config_data = {
            'state':'ENABLED',
            'factorIds':['PHONE_SMS'],
            'providerConfigs': [
                {
                    'state':'ENABLED',
                    'totpProviderConfig': {
                        'adjacentIntervals':5,
                    }
                }
            ]
        }

        #multiFactorConfig.state is disabled
        _, recorder = _instrument_project_config_mgt(
            project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
        mfa_config_state_disabled = copy(mfa_config_data)
        mfa_config_state_disabled['state'] = 'DISABLED'
        project = project_config_mgt.update_project(
             mfa=mfa_config_state_disabled,
            app=project_config_mgt_app)

        _assert_project(project)
        mfa_config_state_disabled['enabledProviders'] = mfa_config_state_disabled['factorIds']
        mfa_config_state_disabled.pop('factorIds')
        mask = ['mfa.enabledProviders', 'mfa.providerConfigs', 'mfa.state']
        self._assert_request(recorder, {
            'mfa': mfa_config_state_disabled
        }, mask)

        #multiFactorConfig.state enabled and providerConfig.state disabled
        _, recorder = _instrument_project_config_mgt(
            project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
        mfa_config_state_enabled_totp_disabled = copy(mfa_config_data)
        mfa_config_state_enabled_totp_disabled['providerConfigs'][0]['state'] = 'DISABLED'
        project = project_config_mgt.update_project(
             mfa=mfa_config_state_enabled_totp_disabled,
            app=project_config_mgt_app)

        _assert_project(project)
        mfa_config_state_enabled_totp_disabled['enabledProviders'] = mfa_config_state_enabled_totp_disabled['factorIds']
        mfa_config_state_enabled_totp_disabled.pop('factorIds')
        mask = ['mfa.enabledProviders', 'mfa.providerConfigs', 'mfa.state']
        self._assert_request(recorder, {
            'mfa': mfa_config_state_enabled_totp_disabled
        }, mask)

    def _assert_request(self, recorder, body, mask):
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'PATCH'
        assert req.url == '{0}/project-id/config?updateMask={1}'.format(
            PROJECT_CONFIG_MGT_URL_PREFIX, ','.join(mask))
        got = json.loads(req.body.decode())
        assert got == body

def _assert_project(project):
    assert isinstance(project, project_config_mgt.ProjectConfig)
    assert project.mfa.state == 'ENABLED'
    assert project.mfa.enabled_providers == ['PHONE_SMS']
    assert len(project.mfa.provider_configs) == 1
    assert project.mfa.provider_configs[0].state == 'ENABLED'
    assert project.mfa.provider_configs[0].totp_provider_config.adjacent_intervals == 5
