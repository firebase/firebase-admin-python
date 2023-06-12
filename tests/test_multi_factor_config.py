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
from copy import copy

import pytest

from firebase_admin import multi_factor_config_mgt

sample_mfa_config = multi_factor_config_mgt.MultiFactorConfig(
    provider_configs=[multi_factor_config_mgt.ProviderConfig(
        state=multi_factor_config_mgt.ProviderConfig.State.ENABLED,
        totp_provider_config=multi_factor_config_mgt.TOTPProviderConfig(
            adjacent_intervals=5
        )
    )]
)


class TestMultiFactorConfig:
    def test_invalid_mfa_config_params(self):
        test_config = copy(sample_mfa_config)
        test_config.invalid_parameter = 'invalid'
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('"invalid_parameter" is not a valid'
                                             ' "MultiFactorConfig" parameter.')

    @pytest.mark.parametrize('provider_configs',
                             [True, False, 1, 0, list(), tuple(), dict()])
    def test_invalid_provider_configs_type(self, provider_configs):
        test_config = copy(sample_mfa_config)
        test_config.provider_configs = provider_configs
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('provider_configs must be an array of type'
                                             ' ProviderConfigs.')

    @pytest.mark.parametrize('provider_configs',
                             [[True], [1, 2],
                              [{'state': 'DISABLED', 'totpProviderConfig': {}}, "foo"]])
    def test_invalid_mfa_config_provider_config(self, provider_configs):
        test_config = copy(sample_mfa_config)
        test_config.provider_configs = provider_configs
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('provider_configs must be an array of type'
                                             ' ProviderConfigs.')


class TestProviderConfig:
    def test_invalid_provider_config_params(self):
        test_config = copy(sample_mfa_config.provider_configs[0])
        test_config.invalid_parameter = 'invalid'
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('"invalid_parameter" is not a valid "ProviderConfig"'
                                             ' parameter.')

    def test_undefined_provider_config_state(self):
        test_config = copy(sample_mfa_config.provider_configs[0])
        test_config.state = None
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith(
            'provider_config.state must be defined.')

    @pytest.mark.parametrize('state',
                             ['', 1, True, False, [], (), {}, "foo", 'ENABLED'])
    def test_invalid_provider_config_state(self, state):
        test_config = multi_factor_config_mgt.ProviderConfig(
            state=state
        )
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('provider_config.state must be of type'
                                             ' ProviderConfig.State.')

    @pytest.mark.parametrize('state',
                             [multi_factor_config_mgt.ProviderConfig.State.ENABLED,
                              multi_factor_config_mgt.ProviderConfig.State.DISABLED])
    def test_undefined_totp_provider_config(self, state):
        test_config = multi_factor_config_mgt.ProviderConfig(state=state)
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('provider_config.totp_provider_config must be'
                                             ' defined.')

    @pytest.mark.parametrize('totp_provider_config',
                             [True, False, 1, 0, list(), tuple(), dict()])
    def test_invalid_totp_provider_config_type(self, totp_provider_config):
        test_config = copy(sample_mfa_config.provider_configs[0])
        test_config.totp_provider_config = totp_provider_config
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('provider_configs.totp_provider_config must be of type'
                                             ' TOTPProviderConfig.')


class TestTOTPProviderConfig:

    def test_invalid_totp_provider_config_params(self):
        test_config = copy(
            sample_mfa_config.provider_configs[0].totp_provider_config)
        test_config.invalid_parameter = 'invalid'
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('"invalid_parameter" is not a valid'
                                             ' "TOTPProviderConfig" parameter.')

    @pytest.mark.parametrize('adjacent_intervals',
                             ['', -1, True, False, [], (), {}, "foo", 11, 1.1])
    def test_invalid_adjacent_intervals_type(self, adjacent_intervals):
        test_config = copy(
            sample_mfa_config.provider_configs[0].totp_provider_config)
        test_config.adjacent_intervals = adjacent_intervals
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('totp_provider_config.adjacent_intervals must be an'
                                             ' integer between 1 and 10 (inclusive).')


class TestMultiFactorServerConfig:
    def test_invalid_multi_factor_config_response(self):
        test_config = 'invalid'
        with pytest.raises(ValueError) as excinfo:
            multi_factor_config_mgt.MultiFactorServerConfig(test_config)
        assert str(excinfo.value).startswith('Invalid data argument in MultiFactorServerConfig'
                                             ' constructor: {0}'.format(test_config))

    def test_invalid_provider_config_response(self):
        test_config = 'invalid'
        with pytest.raises(ValueError) as excinfo:
            multi_factor_config_mgt.MultiFactorServerConfig.ProviderServerConfig(test_config)
        assert str(excinfo.value).startswith('Invalid data argument in ProviderServerConfig'
                                             ' constructor: {0}'.format(test_config))

    def test_invalid_totp_provider_config_response(self):
        test_config = 'invalid'
        with pytest.raises(ValueError) as excinfo:
            multi_factor_config_mgt.MultiFactorServerConfig.ProviderServerConfig.\
                TOTPProviderServerConfig(test_config)
        assert str(excinfo.value).startswith('Invalid data argument in TOTPProviderServerConfig'
                                             ' constructor: {0}'.format(test_config))

    def test_valid_server_response(self):
        response = {
            'providerConfigs': [{
                'state': 'ENABLED',
                'totpProviderConfig': {
                    'adjacentIntervals': 5
                }
            }]
        }
        mfa_config = multi_factor_config_mgt.MultiFactorServerConfig(response)
        _assert_multi_factor_config(mfa_config)


def _assert_multi_factor_config(mfa_config):
    assert isinstance(mfa_config, multi_factor_config_mgt.MultiFactorServerConfig)
    assert len(mfa_config.provider_configs) == 1
    assert isinstance(mfa_config.provider_configs, list)
    for provider_config in mfa_config.provider_configs:
        assert isinstance(
            provider_config,
            multi_factor_config_mgt.MultiFactorServerConfig.ProviderServerConfig)
        assert provider_config.state == 'ENABLED'
        assert isinstance(provider_config.totp_provider_config,
                          multi_factor_config_mgt.MultiFactorServerConfig.ProviderServerConfig
                          .TOTPProviderServerConfig)
        assert provider_config.totp_provider_config.adjacent_intervals == 5
