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
from urllib import parse

import pytest

import firebase_admin
from firebase_admin import auth
from firebase_admin import credentials
from firebase_admin import exceptions
from firebase_admin import project_config_mgt
from firebase_admin import _auth_providers
from firebase_admin import _user_mgt
from firebase_admin.multi_factor_config_mgt import MultiFactorConfig, ProviderConfig, TotpProviderConfig
from tests import testutils
from tests import test_token_gen


GET_PROJECT_RESPONSE = """{
    "name": "project-id",
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

PROJECT_NOT_FOUND_RESPONSE = """{
    "error": {
        "message": "PROJECT_NOT_FOUND"
    }
}"""

MOCK_GET_USER_RESPONSE = testutils.resource('get_user.json')

INVALID_PROJECT_IDS = [None, '', 0, 1, True, False, list(), tuple(), dict()]
INVALID_BOOLEANS = ['', 1, 0, list(), tuple(), dict()]

PROJECT_CONFIG_MGT_URL_PREFIX = 'https://identitytoolkit.googleapis.com/admin/v2/projects'


@pytest.fixture(scope='module')
def project_config_mgt_app():
    app = firebase_admin.initialize_app(
        testutils.MockCredential(), name='projectMgt')
    yield app
    firebase_admin.delete_app(app)


def _instrument_project_config_mgt(app, status, payload):
    service = project_config_mgt._get_project_mgt_service(app)
    recorder = []
    service.client.session.mount(
        project_config_mgt._ProjectManagementService.PROJECT_CONFIG_MGT_URL,
        testutils.MockAdapter(payload, status, recorder))
    return service, recorder


class TestProject:

    @pytest.mark.parametrize('data', [None, 'foo', 0, 1, True, False, list(), tuple(), dict()])
    def test_invalid_data(self, data):
        with pytest.raises(ValueError):
            project_config_mgt.Project(data)

    def test_project(self):
        data = {
            'name': 'project-id',
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
        project = project_config_mgt.Project(data)
        _assert_project(project, project_id='project-id')  

    def test_project_optional_params(self):
        data = {
            'name': 'test-project',
        }
        project = project_config_mgt.Project(data)
        assert project.mfa is None


class TestGetProject:

    @pytest.mark.parametrize('project_id', INVALID_PROJECT_IDS)
    def test_invalid_project_id(self, project_id, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.get_project(project_id, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('Invalid project ID')

    def test_get_project(self, project_config_mgt_app):
        _, recorder = _instrument_project_config_mgt(project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
        project = project_config_mgt.get_project('project-id', app=project_config_mgt_app)

        _assert_project(project)
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'GET'
        assert req.url == '{0}/project-id/config'.format(PROJECT_CONFIG_MGT_URL_PREFIX)

    def test_project_not_found(self, project_config_mgt_app):
        _instrument_project_config_mgt(project_config_mgt_app, 500, PROJECT_NOT_FOUND_RESPONSE)
        with pytest.raises(project_config_mgt.ProjectNotFoundError) as excinfo:
            project_config_mgt.get_project('project-id', app=project_config_mgt_app)

        error_msg = 'No project found for the given identifier (PROJECT_NOT_FOUND).'
        assert excinfo.value.code == exceptions.NOT_FOUND
        assert str(excinfo.value) == error_msg
        assert excinfo.value.http_response is not None
        assert excinfo.value.cause is not None


class TestUpdateProject:

    @pytest.mark.parametrize('project_id', INVALID_PROJECT_IDS)
    def test_invalid_project_id(self, project_id, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project(project_id, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('Project ID must be a non-empty string')

    def test_update_project_no_args(self, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', app=project_config_mgt_app)
        assert str(excinfo.value).startswith('At least one parameter must be specified for update')

    def test_update_project(self, project_config_mgt_app):
        _, recorder = _instrument_project_config_mgt(project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
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
        project = project_config_mgt.update_project(
            'project-id', mfa=mfa_config_data, app=project_config_mgt_app)

        _assert_project(project)
        body = {
            'multiFactorConfig':{
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
        }
        mask = ['multiFactorConfig.factorIds', 'multiFactorConfig.providerConfigs', 'multiFactorConfig.state']
        self._assert_request(recorder, body, mask)

    @pytest.mark.parametrize('mfa_config', ['foo', 0, 1, True, False, list(), tuple()])
    def test_update_project_invalid_mfa_config_type(self, mfa_config, project_config_mgt_app):
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('multiFactorConfig should be of valid type MultiFactorConfig')

    def test_update_project_undefined_mfa_config_state(self, project_config_mgt_app):
        mfa_config = {'factorIds':["PHONE_SMS"]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('multiFactorConfig.state should be defined')
    
    @pytest.mark.parametrize('state', ['', 1, True, False, [], (), {}, "foo"])
    def test_update_project_invalid_mfa_config_state(self, project_config_mgt_app, state):
        mfa_config = {'state': state}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('multiFactorConfig.state must be either "ENABLED" or "DISABLED"')

    def test_update_project_undefined_mfa_config_factor_ids_enabled_state(self, project_config_mgt_app):
        mfa_config = {'state':'ENABLED'}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('multiFactorConfig.factorIds must be defined')

    @pytest.mark.parametrize('factor_ids', [True, False, 1, 0, 'foo', {}, dict(), tuple(), list()])
    def test_invalid_mfa_config_factor_ids_type(self, factor_ids, project_config_mgt_app):
        mfa_config = {'state': 'ENABLED', 'factorIds': factor_ids}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('multiFactorConfig.factorIds must be a defined list of AuthFactor type strings')

    @pytest.mark.parametrize('factor_ids', [[1, 2, 3], [True, False], ['foo', 'bar', {}]])
    def test_invalid_mfa_config_factor_ids(self, project_config_mgt_app, factor_ids):
        mfa_config = {'state': 'ENABLED', 'factorIds': factor_ids}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
            assert str(excinfo.value).startswith('factorId must be a valid AuthFactor type string')
    
    @pytest.mark.parametrize('provider_configs', [True, False, 1, 0, list(), tuple(), dict()])
    def test_invalid_mfa_config_provider_configs_type(self, project_config_mgt_app, provider_configs):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': provider_configs}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('multiFactorConfig.providerConfigs must be a valid list of providerConfig types')
    
    @pytest.mark.parametrize('provider_configs', [[True], [{}], [1,2], [{'state': 'DISABLED', 'totpProviderConfig': {}}, "foo"]])
    def test_invalid_mfa_config_provider_config(self, project_config_mgt_app, provider_configs):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': provider_configs}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('multiFactorConfigs.providerConfigs must be a valid array of type providerConfig')

    def test_undefined_provider_config_state(self, project_config_mgt_app):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': [{'totpProviderConfig':{}}]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('providerConfig.state should be defined')
    
    @pytest.mark.parametrize('state', ['', 1, True, False, [], (), {}, "foo"])
    def test_invalid_provider_config_state(self, project_config_mgt_app, state):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': [{'state':state, 'totpProviderConfig':{}}]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('providerConfig.state must be either "ENABLED" or "DISABLED"')

    @pytest.mark.parametrize('state', ['ENABLED','DISABLED'])
    def test_undefined_totp_provider_config(self, project_config_mgt_app, state):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': [{'state':state}]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('providerConfig.totpProviderConfig must be instantiated')

    @pytest.mark.parametrize('totp_provider_config', [True, False, 1, 0, list(), tuple()])
    def test_invalid_totp_provider_config_type(self, project_config_mgt_app, totp_provider_config):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': [{'state':'ENABLED', 'totpProviderConfig':totp_provider_config}]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('providerConfig.totpProviderConfig must be of valid type TotpProviderConfig')
    
    @pytest.mark.parametrize('adjacent_intervals', ['', -1, True, False, [], (), {}, "foo", None])
    def test_invalid_adjacent_intervals_type(self, project_config_mgt_app, adjacent_intervals):
        mfa_config = {'state': 'DISABLED', 'providerConfigs': [{'state':'ENABLED', 'totpProviderConfig':{'adjacentIntervals':adjacent_intervals}}]}
        with pytest.raises(ValueError) as excinfo:
            project_config_mgt.update_project('project-id', mfa=mfa_config, app=project_config_mgt_app)
        assert str(excinfo.value).startswith('totpProviderConfig.adjacentIntervals must be a valid positive integer')

    def test_update_project(self, project_config_mgt_app):
        _, recorder = _instrument_project_config_mgt(project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
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
            'project-id', mfa=mfa_config_data,app=project_config_mgt_app)

        mask = ['multiFactorConfig.factorIds','multiFactorConfig.providerConfigs','multiFactorConfig.state']

        _assert_project(project)
        self._assert_request(recorder, {
            'multiFactorConfig':{
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
        _, recorder = _instrument_project_config_mgt(project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
        mfa_config_state_disabled = copy(mfa_config_data)
        mfa_config_state_disabled['state'] = 'DISABLED'
        project = project_config_mgt.update_project(
            'project-id', mfa=mfa_config_state_disabled,
            app=project_config_mgt_app)

        mfa_config_state_disabled.pop('factorIds')
        _assert_project(project)
        mask = ['multiFactorConfig.providerConfigs','multiFactorConfig.state']
        self._assert_request(recorder, {
            'multiFactorConfig': mfa_config_state_disabled
        }, mask)

        #multiFactorConfig.state enabled and providerConfig.state disabled
        _, recorder = _instrument_project_config_mgt(project_config_mgt_app, 200, GET_PROJECT_RESPONSE)
        mfa_config_state_enabled_totp_disabled = copy(mfa_config_data)
        mfa_config_state_enabled_totp_disabled['providerConfigs'][0]['state'] = 'DISABLED'
        project = project_config_mgt.update_project(
            'project-id', mfa=mfa_config_state_enabled_totp_disabled,
            app=project_config_mgt_app)

        _assert_project(project)
        mask = ['multiFactorConfig.factorIds','multiFactorConfig.providerConfigs','multiFactorConfig.state']
        self._assert_request(recorder, {
            'multiFactorConfig': mfa_config_state_enabled_totp_disabled
        },mask)

    def _assert_request(self, recorder, body, mask):
        assert len(recorder) == 1
        req = recorder[0]
        assert req.method == 'PATCH'
        assert req.url == '{0}/project-id/config?updateMask={1}'.format(
            PROJECT_CONFIG_MGT_URL_PREFIX, ','.join(mask))
        got = json.loads(req.body.decode())
        assert got == body

def _assert_project(project, project_id='project-id'):
    assert isinstance(project, project_config_mgt.Project)
    assert project.project_id == project_id
    assert project.mfa.state == 'ENABLED'
    assert project.mfa.enabled_providers == ['PHONE_SMS']
    assert len(project.mfa.provider_configs) == 1
    assert project.mfa.provider_configs[0].state == 'ENABLED'
    assert project.mfa.provider_configs[0].totp_provider_config.adjacent_intervals == 5 
