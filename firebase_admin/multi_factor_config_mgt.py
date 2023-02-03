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

This module contains functions for managing various multifactor configurations at
the project and tenant level.
"""


class TotpProviderConfig:
    """Represents a TOTP Provider Configuration"""

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError(
                'Invalid data argument in TotpProviderConfig constructor: {0}'.
                format(data))

        self._data = data

    @property
    def adjacent_intervals(self):
        return self._data.get('adjacentIntervals')


class ProviderConfig:
    """Represents a multi factor provider configuration"""

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError(
                'Invalid data argument in ProviderConfig constructor: {0}'.
                format(data))

        self._data = data

    @property
    def state(self):
        return self._data.get('state')

    @property
    def totp_provider_config(self):
        data = self._data.get('totpProviderConfig')
        if data:
            return TotpProviderConfig(data)
        return None


class MultiFactorConfig:
    """Represents a multi factor configuration for tenant or project
    """

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError(
                'Invalid data argument in MultiFactorConfig constructor: {0}'.
                format(data))

        self._data = data

    @property
    def state(self):
        return self._data.get('state')

    @property
    def enabled_providers(self):
        return self._data.get('factorIds')

    @property
    def provider_configs(self):
        data = self._data.get('providerConfigs')
        if data:
            return [ProviderConfig(d) for d in data]
        return None
