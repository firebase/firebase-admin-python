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
from firebase_admin import multi_factor_config_mgt
from firebase_admin import password_policy_config_mgt


@pytest.fixture(scope='module')
def sample_mfa_config():
    mfa_config = {
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


def test_update_project_config():
    mfa_object = multi_factor_config_mgt.MultiFactorConfig(
        provider_configs=[
            multi_factor_config_mgt.ProviderConfig(
                state=multi_factor_config_mgt.ProviderConfig.State.ENABLED,
                totp_provider_config=multi_factor_config_mgt.TOTPProviderConfig(
                    adjacent_intervals=5
                )
            )
        ]
    )
    password_policy_object = password_policy_config_mgt.PasswordPolicyConfig(
        enforcement_state=password_policy_config_mgt.PasswordPolicyConfig.EnforcementState.ENFORCE,
        force_upgrade_on_signin=False,
        constraints=password_policy_config_mgt.CustomStrengthOptionsConfig(
        require_lowercase=True,
        require_non_alphanumeric=True,
        require_numeric=True,
        require_uppercase=True,
        max_length=30,
        min_length=8
        )
    )
    project_config = project_config_mgt.update_project_config(multi_factor_config=mfa_object, password_policy_config=password_policy_object)
    _assert_multi_factor_config(project_config.multi_factor_config)
    _assert_password_policy_config(project_config.password_policy_config)


def test_get_project():
    project_config = project_config_mgt.get_project_config()
    assert isinstance(project_config, project_config_mgt.ProjectConfig)
    _assert_multi_factor_config(project_config.multi_factor_config)
    _assert_password_policy_config(project_config.password_policy_config)

def _assert_multi_factor_config(multi_factor_config):
    assert isinstance(multi_factor_config, multi_factor_config_mgt.MultiFactorServerConfig)
    assert len(multi_factor_config.provider_configs) == 1
    assert isinstance(multi_factor_config.provider_configs, list)
    for provider_config in multi_factor_config.provider_configs:
        assert isinstance(provider_config, multi_factor_config_mgt.MultiFactorServerConfig
                          .ProviderConfigServerConfig)
        assert provider_config.state == 'ENABLED'
        assert isinstance(provider_config.totp_provider_config,
                          multi_factor_config_mgt.MultiFactorServerConfig.ProviderConfigServerConfig
                          .TOTPProviderServerConfig)
        assert provider_config.totp_provider_config.adjacent_intervals == 5

def _assert_password_policy_config(password_policy_config):
    assert isinstance(password_policy_config, password_policy_config_mgt.PasswordPolicyConfig)
    assert isinstance(password_policy_config.enforcement_state, password_policy_config_mgt.PasswordPolicyConfig.EnforcementState)
    assert password_policy_config.enforcement_state == 'ENFORCE'
    assert isinstance(password_policy_config.force_upgrade_on_signin, bool)
    assert password_policy_config.force_upgrade_on_signin is False
    assert isinstance(password_policy_config.constraints, password_policy_config_mgt.CustomStrengthOptionsConfig)
    assert isinstance(password_policy_config.constraints.require_lowercase, bool)
    assert password_policy_config.constraints.require_lowercase is True
    assert isinstance(password_policy_config.constraints.require_uppercase, bool)
    assert password_policy_config.constraints.require_uppercase is True
    assert isinstance(password_policy_config.constraints.require_numeric, bool)
    assert password_policy_config.constraints.require_numeric is True
    assert isinstance(password_policy_config.constraints.require_non_alphanumeric, bool)
    assert password_policy_config.constraints.require_non_alphanumeric is True
    assert isinstance(password_policy_config.constraints.min_length, int)
    assert password_policy_config.constraints.min_length == 8
    assert isinstance(password_policy_config.constraints.max_length, int)
    assert password_policy_config.constraints.max_length == 30

