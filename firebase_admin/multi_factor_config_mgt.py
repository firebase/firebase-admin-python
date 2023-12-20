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
"""Firebase multifactor configuration management module.

This module contains functions for managing multifactor auth configuration at
the project and tenant level.
"""
from enum import Enum
from typing import List

__all__ = [
    'validate_keys',
    'MultiFactorServerConfig',
    'TOTPProviderConfig',
    'ProviderConfig',
    'MultiFactorConfig',
]


def validate_keys(keys, valid_keys, config_name):
    for key in keys:
        if key not in valid_keys:
            raise ValueError(
                '"{0}" is not a valid "{1}" parameter.'.format(
                    key, config_name))


class MultiFactorServerConfig:
    """Represents the multi-factor configuration response received from the server.
    """

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError(
                'Invalid data argument in MultiFactorServerConfig constructor: {0}, must be a valid dict'.format(data))
        self._data = data

    @property
    def provider_configs(self):
        data = self._data.get('providerConfigs', None)
        if data is not None:
            return [self.ProviderServerConfig(d) for d in data]
        return None

    class ProviderServerConfig:
        """Represents the provider configuration response received from the server.
        """

        def __init__(self, data):
            if not isinstance(data, dict):
                raise ValueError(
                    'Invalid data argument in ProviderServerConfig constructor: {0}'.format(data))
            self._data = data

        @property
        def state(self):
            return self._data.get('state', None)

        @property
        def totp_provider_config(self):
            data = self._data.get('totpProviderConfig', None)
            if data is not None:
                return self.TOTPProviderServerConfig(data)
            return None

        class TOTPProviderServerConfig:
            """Represents the TOTP provider configuration response received from the server.
            """

            def __init__(self, data):
                if not isinstance(data, dict):
                    raise ValueError(
                        'Invalid data argument in TOTPProviderServerConfig'
                        ' constructor: {0}'.format(data))
                self._data = data

            @property
            def adjacent_intervals(self):
                return self._data.get('adjacentIntervals', None)


class TOTPProviderConfig:
    """A tenant or project's TOTP provider configuration."""

    def __init__(self, adjacent_intervals: int = None):
        self.adjacent_intervals: int = adjacent_intervals

    def to_dict(self) -> dict:
        data = {}
        if self.adjacent_intervals is not None:
            data['adjacentIntervals'] = self.adjacent_intervals
        return data

    def validate(self):
        """Validates the configuration.

        Raises:
            ValueError: In case of an unsuccessful validation.
        """
        validate_keys(
            keys=vars(self).keys(),
            valid_keys={'adjacent_intervals'},
            config_name='TOTPProviderConfig')
        if self.adjacent_intervals is not None:
            # Because bool types get converted to int here
            # pylint: disable=C0123
            if type(self.adjacent_intervals) is not int:
                raise ValueError(
                    'totp_provider_config.adjacent_intervals must be an integer between'
                    ' 1 and 10 (inclusive).')
            if not 1 <= self.adjacent_intervals <= 10:
                raise ValueError(
                    'totp_provider_config.adjacent_intervals must be an integer between'
                    ' 1 and 10 (inclusive).')

    def build_server_request(self):
        self.validate()
        return self.to_dict()


class ProviderConfig:
    """A tenant or project's multifactor provider configuration.
    Currently, only TOTP can be configured."""

    class State(Enum):
        ENABLED = 'ENABLED'
        DISABLED = 'DISABLED'

    def __init__(self,
                 state: State = None,
                 totp_provider_config: TOTPProviderConfig = None):
        self.state: self.State = state
        self.totp_provider_config: TOTPProviderConfig = totp_provider_config

    def to_dict(self) -> dict:
        data = {}
        if self.state:
            data['state'] = self.state.value
        if self.totp_provider_config:
            data['totpProviderConfig'] = self.totp_provider_config.to_dict()
        return data

    def validate(self):
        """Validates the provider configuration.

        Raises:
            ValueError: In case of an unsuccessful validation.
        """
        validate_keys(
            keys=vars(self).keys(),
            valid_keys={
                'state',
                'totp_provider_config'},
            config_name='ProviderConfig')
        if self.state is None:
            raise ValueError('ProviderConfig.state must be defined.')
        if not isinstance(self.state, ProviderConfig.State):
            raise ValueError(
                'ProviderConfig.state must be of type ProviderConfig.State.')
        if self.totp_provider_config is None:
            raise ValueError(
                'ProviderConfig.totp_provider_config must be defined.')
        if not isinstance(self.totp_provider_config, TOTPProviderConfig):
            raise ValueError(
                'ProviderConfig.totp_provider_config must be of type TOTPProviderConfig.')

    def build_server_request(self):
        self.validate()
        return self.to_dict()


class MultiFactorConfig:
    """A tenant or project's multi factor configuration."""

    def __init__(self,
                 provider_configs: List[ProviderConfig] = None):
        self.provider_configs: List[ProviderConfig] = provider_configs

    def to_dict(self) -> dict:
        data = {}
        if self.provider_configs is not None:
            data['providerConfigs'] = [d.to_dict()
                                       for d in self.provider_configs]
        return data

    def validate(self):
        """Validates the configuration.

        Raises:
            ValueError: In case of an unsuccessful validation.
        """
        validate_keys(
            keys=vars(self).keys(),
            valid_keys={'provider_configs'},
            config_name='MultiFactorConfig')
        if self.provider_configs is None:
            raise ValueError(
                'multi_factor_config.provider_configs must be specified')
        if not isinstance(self.provider_configs, list) or not self.provider_configs:
            raise ValueError(
                'provider_configs must be an array of type ProviderConfig.')
        for provider_config in self.provider_configs:
            if not isinstance(provider_config, ProviderConfig):
                raise ValueError(
                    'provider_configs must be an array of type ProviderConfig.')
            provider_config.validate()

    def build_server_request(self):
        self.validate()
        return self.to_dict()
