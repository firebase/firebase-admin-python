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

from firebase_admin.project_config_mgt import ProjectConfig
from firebase_admin.project_config_mgt import get_project_config
from firebase_admin.project_config_mgt import update_project_config
from firebase_admin.multi_factor_config_mgt import MultiFactorConfig
from firebase_admin.multi_factor_config_mgt import MultiFactorServerConfig
from firebase_admin.multi_factor_config_mgt import ProviderConfig
from firebase_admin.multi_factor_config_mgt import TOTPProviderConfig
from firebase_admin.email_privacy_config_mgt import EmailPrivacyConfig
from firebase_admin.email_privacy_config_mgt import EmailPrivacyServerConfig

def test_update_project_config():
    mfa_object = MultiFactorConfig(
        provider_configs=[
            ProviderConfig(
                state=ProviderConfig.State.ENABLED,
                totp_provider_config=TOTPProviderConfig(
                    adjacent_intervals=5
                )
            )
        ]
    )
    email_privacy_object = EmailPrivacyConfig(
        enable_improved_email_privacy=True
    )
    project_config = update_project_config(
        multi_factor_config=mfa_object, email_privacy_config=email_privacy_object)
    _assert_multi_factor_config(project_config.multi_factor_config)
    _assert_email_privacy_config(project_config.email_privacy_config)


def test_get_project():
    project_config = get_project_config()
    assert isinstance(project_config, ProjectConfig)
    _assert_multi_factor_config(project_config.multi_factor_config)
    _assert_email_privacy_config(project_config.email_privacy_config)

def _assert_multi_factor_config(multi_factor_config):
    assert isinstance(multi_factor_config, MultiFactorServerConfig)
    assert len(multi_factor_config.provider_configs) == 1
    assert isinstance(multi_factor_config.provider_configs, list)
    for provider_config in multi_factor_config.provider_configs:
        assert isinstance(provider_config, MultiFactorServerConfig
                          .ProviderServerConfig)
        assert provider_config.state == 'ENABLED'
        assert isinstance(provider_config.totp_provider_config,
                          MultiFactorServerConfig.ProviderServerConfig
                          .TOTPProviderServerConfig)
        assert provider_config.totp_provider_config.adjacent_intervals == 5

def _assert_email_privacy_config(email_privacy_config):
    assert isinstance(email_privacy_config, EmailPrivacyServerConfig)
    assert email_privacy_config.enable_improved_email_privacy is True
