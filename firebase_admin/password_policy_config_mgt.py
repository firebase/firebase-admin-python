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
from enum import Enum

__all__ = [
    'validate_keys',
    'PasswordPolicyServerConfig',
    'PasswordPolicyConfig',
    'CustomStrengthOptionsConfig',
]

def validate_keys(keys, valid_keys, config_name):
    for key in keys:
        if key not in valid_keys:
            raise ValueError(
                '"{0}" is not a valid "{1}" parameter.'.format(
                    key, config_name))


class PasswordPolicyServerConfig:
    """Represents password policy configuration response received from the server and
    converts it to user format.
    """

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError(
                'Invalid data argument in PasswordPolicyConfig constructor: {0}'.format(data))
        self._data = data

    @property
    def enforcement_state(self):
        return self._data.get('enforcementState', None)

    @property
    def force_upgrade_on_signin(self):
        return self._data.get('forceUpgradeOnSignin', None)

    @property
    def constraints(self):
        data = self._data.get('passwordPolicyVersions')
        if data is not None:
            return self.CustomStrengthOptionsServerConfig(data[0].get('customStrengthOptions'))
        return None

    class CustomStrengthOptionsServerConfig:
        """Represents custom strength options configuration response received from the server and
        converts it to user format.
        """

        def __init__(self, data):
            if not isinstance(data, dict):
                raise ValueError(
                    'Invalid data argument in CustomStrengthOptionsServerConfig'
                    ' constructor: {0}'.format(data))
            self._data = data

        @property
        def require_uppercase(self):
            return self._data.get('containsUppercaseCharacter', None)

        @property
        def require_lowercase(self):
            return self._data.get('containsLowercaseCharacter', None)

        @property
        def require_non_alphanumeric(self):
            return self._data.get('containsNonAlphanumericCharacter', None)

        @property
        def require_numeric(self):
            return self._data.get('containsNumericCharacter', None)

        @property
        def min_length(self):
            return self._data.get('minPasswordLength', None)

        @property
        def max_length(self):
            return self._data.get('maxPasswordLength', None)


class CustomStrengthOptionsConfig:
    """Represents the strength attributes for the password policy"""

    def __init__(
            self,
            min_length: int = 6,
            max_length: int = 4096,
            require_uppercase: bool = False,
            require_lowercase: bool = False,
            require_non_alphanumeric: bool = False,
            require_numeric: bool = False,
    ):
        self.min_length: int = min_length
        self.max_length: int = max_length
        self.require_uppercase: bool = require_uppercase
        self.require_lowercase: bool = require_lowercase
        self.require_non_alphanumeric: bool = require_non_alphanumeric
        self.require_numeric: bool = require_numeric

    def to_dict(self) -> dict:
        data = {}
        constraints_request = {}
        if self.max_length is not None:
            constraints_request['maxPasswordLength'] = self.max_length
        if self.min_length is not None:
            constraints_request['minPasswordLength'] = self.min_length
        if self.require_lowercase is not None:
            constraints_request['containsLowercaseCharacter'] = self.require_lowercase
        if self.require_uppercase is not None:
            constraints_request['containsUppercaseCharacter'] = self.require_uppercase
        if self.require_non_alphanumeric is not None:
            constraints_request['containsNonAlphanumericCharacter'] = self.require_non_alphanumeric
        if self.require_numeric is not None:
            constraints_request['containsNumericCharacter'] = self.require_numeric
        data['customStrengthOptions'] = constraints_request
        return data

    def validate(self):
        """Validates a constraints object.

        Raises:
            ValueError: In case of an unsuccessful validation.
        """
        validate_keys(
            keys=vars(self).keys(),
            valid_keys={
                'require_numeric',
                'require_uppercase',
                'require_lowercase',
                'require_non_alphanumeric',
                'min_length',
                'max_length'
            },
            config_name='CustomStrengthOptionsConfig')
        if not isinstance(self.require_lowercase, bool):
            raise ValueError('constraints.require_lowercase must be a boolean')
        if not isinstance(self.require_uppercase, bool):
            raise ValueError('constraints.require_uppercase must be a boolean')
        if not isinstance(self.require_non_alphanumeric, bool):
            raise ValueError(
                'constraints.require_non_alphanumeric must be a boolean')
        if not isinstance(self.require_numeric, bool):
            raise ValueError('constraints.require_numeric must be a boolean')
        if not isinstance(self.min_length, int):
            raise ValueError('constraints.min_length must be an integer')
        if not isinstance(self.max_length, int):
            raise ValueError('constraints.max_length must be an integer')
        if not (self.min_length >= 6 and self.min_length <= 30):
            raise ValueError('constraints.min_length must be between 6 and 30')
        if not (self.max_length >= 0 and self.max_length <= 4096):
            raise ValueError('constraints.max_length can be atmost 4096')
        if self.min_length > self.max_length:
            raise ValueError(
                'min_length must be less than or equal to max_length')

    def build_server_request(self):
        self.validate()
        return self.to_dict()


class PasswordPolicyConfig:
    """Represents the configuration for the password policy on the project"""

    class EnforcementState(Enum):
        ENFORCE = 'ENFORCE'
        OFF = 'OFF'

    def __init__(
            self,
            enforcement_state: EnforcementState = None,
            force_upgrade_on_signin: bool = False,
            constraints: CustomStrengthOptionsConfig = None,
    ):
        self.enforcement_state: self.EnforcementState = enforcement_state
        self.force_upgrade_on_signin: bool = force_upgrade_on_signin
        self.constraints: CustomStrengthOptionsConfig = constraints

    def to_dict(self) -> dict:
        data = {}
        if self.enforcement_state:
            data['enforcementState'] = self.enforcement_state.value
        if self.force_upgrade_on_signin:
            data['forceUpgradeOnSignin'] = self.force_upgrade_on_signin
        if self.constraints:
            data['passwordPolicyVersions'] = [self.constraints.to_dict()]
        return data

    def validate(self):
        """Validates a password_policy_config object.

        Raises:
            ValueError: In case of an unsuccessful validation.
        """
        validate_keys(
            keys=vars(self).keys(),
            valid_keys={
                'enforcement_state',
                'force_upgrade_on_signin',
                'constraints'},
            config_name='PasswordPolicyConfig')
        if self.enforcement_state is None:
            raise ValueError(
                'password_policy_config.enforcement_state must be defined.')
        if not isinstance(self.enforcement_state, PasswordPolicyConfig.EnforcementState):
            raise ValueError(
                'password_policy_config.enforcement_state must be of type'
                ' PasswordPolicyConfig.EnforcementState')
        if not isinstance(self.force_upgrade_on_signin, bool):
            raise ValueError(
                'password_policy_config.force_upgrade_on_signin must be a valid boolean')
        if self.enforcement_state is self.EnforcementState.ENFORCE and self.constraints is None:
            raise ValueError(
                'password_policy_config.constraints must be defined')
        if not isinstance(self.constraints, CustomStrengthOptionsConfig):
            raise ValueError(
                'password_policy_config.constraints must be of type CustomStrengthOptionsConfig')
        self.constraints.validate()

    def build_server_request(self):
        self.validate()
        return self.to_dict()
