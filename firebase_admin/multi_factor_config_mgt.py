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
from firebase_admin import _auth_utils


class MfaConstants:
    """Various MFA constants used for validation and auth conversions"""
    STATE = 'state'
    FACTOR_IDS = 'factorIds'
    PROVIDER_CONFIGS = 'providerConfigs'
    TOTP_PROVIDER_CONFIG = 'totpProviderConfig'
    ADJACENT_INTERVALS = 'adjacentIntervals'
    MULTI_FACTOR_CONFIG_OBJ = 'MultiFactorConfig'
    PROVIDER_CONFIG_OBJ = 'ProviderConfig'
    TOTP_PROVIDER_CONFIG_OBJ = 'TotpProviderConfig'
    MULTI_FACTOR_CONFIG = 'multiFactorConfig'
    ENABLED_PROVIDERS = 'enabledProviders'
    VALID_AUTH_FACTOR_TYPES = set(['PHONE_SMS'])
    VALID_STATES = set(['ENABLED', 'DISABLED'])


class MultiFactorConfig:
    """Represents a multi factor configuration for tenant or project
    """

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError(
                'multiFactorConfig should be of valid type MultiFactorConfig')
        self._data = data

    def to_dict(self):
        return self._data

    @property
    def state(self):
        return self._data.get('state')

    @property
    def enabled_providers(self):
        return self._data.get('factorIds')

    @property
    def provider_configs(self):
        data = self._data.get('providerConfigs')
        if not isinstance(data, list) or not data:
            raise ValueError(
                'multiFactorConfig.providerConfigs must be a valid list of ProviderConfigs')
        if data:
            return [MultiFactorConfig.ProviderConfig(d) for d in data]
        return None

    class ProviderConfig:
        """Represents a multi factor provider configuration"""

        def __init__(self, data):
            if not isinstance(data, dict):
                raise ValueError(
                    'multiFactorConfig.providerConfigs must be a valid list of ProviderConfigs')
            self._data = data

        def to_dict(self):
            return self._data

        @property
        def state(self):
            return self._data.get('state')

        @property
        def totp_provider_config(self):
            data = self._data.get('totpProviderConfig')
            if data is None:
                raise ValueError('ProviderConfig.TotpProviderConfig must be present')
            return MultiFactorConfig.ProviderConfig.TotpProviderConfig(data)

        class TotpProviderConfig:
            """Represents a TOTP Provider Configuration"""

            def __init__(self, data):
                if not isinstance(data, dict):
                    raise ValueError(
                        'providerConfig.totpProviderConfig must' + 
                        ' be of valid type TotpProviderConfig')
                self._data = data

            def to_dict(self):
                return self._data

            @property
            def adjacent_intervals(self):
                return self._data.get('adjacentIntervals')


def validate_mfa_config(mfa_config: MultiFactorConfig):
    """Validates MFA Configuration sent to the server

    Args:
        mfa_config (MultiFactorConfig): Object received from the user

    Raises:
        ValueError: Depending on validation failures

    Returns:
        payload: JSON payload sent to the server
    """

    # defining a state validation function
    def validate_state(state, config):
        if not isinstance(state, str) or state not in MfaConstants.VALID_STATES:
            raise ValueError('{0}.{1} should be in '.format(
                config, MfaConstants.STATE) + str(MfaConstants.VALID_STATES))
        return state

    # validation of factorIds
    def validate_factor_ids(factor_ids):
        if not isinstance(factor_ids, list):
            raise ValueError('{0}.{1} should be a valid list of strings in '.format(
                MfaConstants.MULTI_FACTOR_CONFIG, MfaConstants.FACTOR_IDS) +\
                     str(MfaConstants.VALID_AUTH_FACTOR_TYPES))

        # validate each element in multiFactorConfig.factorIds
        for factor_id in factor_ids:
            if not isinstance(
                    factor_id, str) or factor_id not in MfaConstants.VALID_AUTH_FACTOR_TYPES:
                raise ValueError('{0}.{1} should be a valid list of strings in '.format(
                    MfaConstants.MULTI_FACTOR_CONFIG, MfaConstants.FACTOR_IDS) +\
                         str(MfaConstants.VALID_AUTH_FACTOR_TYPES))
        return factor_ids

    def validate_provider_configs(provider_configs):

        # validation of totpProviderConfig
        def validate_totp_provider_config(totp_provider_config):
            if not isinstance(totp_provider_config,
                              MultiFactorConfig.ProviderConfig.TotpProviderConfig):
                raise ValueError(
                    '{0} must be a valid config of type {1}'.format(
                        MfaConstants.TOTP_PROVIDER_CONFIG,
                        MfaConstants.TOTP_PROVIDER_CONFIG_OBJ))
            # validate TotpProviderConfig keys
            _auth_utils.validate_config_keys(
                input_keys=set(totp_provider_config.to_dict().keys()),
                valid_keys=set([MfaConstants.ADJACENT_INTERVALS]),
                config_name=MfaConstants.TOTP_PROVIDER_CONFIG_OBJ
            )
            totp_provider_config_payload = {}
            # validate totpProviderConfig.adjacentIntervals
            if totp_provider_config.adjacent_intervals is not None:
                # Because bool types get converted to int here
                # pylint: disable=C0123
                if ((type(totp_provider_config.adjacent_intervals) is not int) or
                        not 0 <= totp_provider_config.adjacent_intervals <= 10):
                    raise ValueError(
                        ('{0}.{1} must be a valid positive integer' +
                         ' between 0 and 10 (both inclusive).').format(
                             MfaConstants.TOTP_PROVIDER_CONFIG,
                             MfaConstants.ADJACENT_INTERVALS))
                totp_provider_config_payload[MfaConstants.ADJACENT_INTERVALS] = \
                    totp_provider_config.adjacent_intervals
            return totp_provider_config_payload

        if not isinstance(provider_configs, list):
            raise ValueError(
                '{0}.{1} must be a valid list of {2}s'.format(
                    MfaConstants.MULTI_FACTOR_CONFIG,
                    MfaConstants.PROVIDER_CONFIGS,
                    MfaConstants.PROVIDER_CONFIG_OBJ))

        provider_configs_payload = []
        # validate each element in multiFactorConfig.providerConfigs:
        for provider_config in provider_configs:
            provider_config_payload = {}
            if not isinstance(provider_config, MultiFactorConfig.ProviderConfig):
                raise ValueError(
                    '{0}.{1} must be a valid list of {2}s'.format(
                        MfaConstants.MULTI_FACTOR_CONFIG,
                        MfaConstants.PROVIDER_CONFIGS,
                        MfaConstants.PROVIDER_CONFIG_OBJ))

            # validate each ProviderConfig keys
            _auth_utils.validate_config_keys(
                input_keys=set(provider_config.to_dict().keys()),
                valid_keys=set([MfaConstants.STATE, MfaConstants.TOTP_PROVIDER_CONFIG]),
                config_name=MfaConstants.PROVIDER_CONFIG_OBJ
            )

            # validate ProviderConfig.State
            provider_config_payload[MfaConstants.STATE] = validate_state(
                provider_config.state, MfaConstants.PROVIDER_CONFIG_OBJ)

            # validate ProviderConfig.TotpProviderConfig
            provider_config_payload[MfaConstants.TOTP_PROVIDER_CONFIG] = \
                validate_totp_provider_config(provider_config.totp_provider_config)
            provider_configs_payload.append(provider_config_payload)

        return provider_configs_payload

    # validate multiFactorConfig type
    if not isinstance(mfa_config, MultiFactorConfig):
        raise ValueError("multiFactorConfig should be of valid type MultiFactorConfig")

    mfa_config_payload = {}
    # validate multiFactorConfig keys
    _auth_utils.validate_config_keys(
        input_keys=set(mfa_config.to_dict().keys()),
        valid_keys=set([MfaConstants.STATE, MfaConstants.FACTOR_IDS,
                        MfaConstants.PROVIDER_CONFIGS]),
        config_name=MfaConstants.MULTI_FACTOR_CONFIG_OBJ
    )

    # validate multiFactorConfig.state
    mfa_config_payload[MfaConstants.STATE] = validate_state(
        mfa_config.state, MfaConstants.MULTI_FACTOR_CONFIG)

    # validate multiFactorConfig.factorIds
    if mfa_config.enabled_providers is not None:
        mfa_config_payload[MfaConstants.ENABLED_PROVIDERS] = validate_factor_ids(
            mfa_config.enabled_providers)

    # validate multiFactorConfig.providerConfigs
    if mfa_config.provider_configs is not None:
        mfa_config_payload[MfaConstants.PROVIDER_CONFIGS] = validate_provider_configs(
            mfa_config.provider_configs)

    return mfa_config_payload
