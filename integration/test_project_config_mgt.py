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

"""Integration tests for firebase_admin.project_config_mgt module."""

import pytest

from firebase_admin import project_config_mgt


@pytest.fixture(scope='module')
def sample_mfa_config():
    mfa_config = {
        'state': 'ENABLED',
        'factorIds': ['PHONE_SMS'],
        'providerConfigs': [
            {
                'state': 'ENABLED',
                'totpProviderConfig': {
                    'adjacentIntervals': 5
                }
            }
        ]
    }
    return mfa_config


def test_update_project(sample_mfa_config, mfa=None):
    if mfa is None:
        mfa = sample_mfa_config
    project = project_config_mgt.update_project(mfa=mfa)
    assert isinstance(project, project_config_mgt.ProjectConfig)
    assert project.mfa.state == 'ENABLED'
    assert project.mfa.enabled_providers == ['PHONE_SMS']
    assert project.mfa.provider_configs[0].state == 'ENABLED'
    assert project.mfa.provider_configs[0].totp_provider_config.adjacent_intervals == 5


def test_get_project():
    project = project_config_mgt.get_project()
    assert isinstance(project, project_config_mgt.ProjectConfig)
    assert project.mfa.state == 'ENABLED'
    assert project.mfa.enabled_providers == ['PHONE_SMS']
    assert project.mfa.provider_configs[0].state == 'ENABLED'
    assert project.mfa.provider_configs[0].totp_provider_config.adjacent_intervals == 5
