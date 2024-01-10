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

__all__ = [
    'validate_keys',
    'EmailPrivacyServerConfig',
    'EmailPrivacyConfig',
]


def validate_keys(keys, valid_keys, config_name):
    for key in keys:
        if key not in valid_keys:
            raise ValueError(
                '"{0}" is not a valid "{1}" parameter.'.format(
                    key, config_name))


class EmailPrivacyServerConfig:
    """Represents email privacy configuration response received from the server and
    converts it to user format.
    """

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError(
                'Invalid data argument in EmailPrivacyConfig constructor: {0}'.format(data))
        self._data = data

    @property
    def enable_improved_email_privacy(self):
        return self._data.get('enableImprovedEmailPrivacy', False)

class EmailPrivacyConfig:
    """Represents a email privacy configuration for tenant or project
    """

    def __init__(self,
                 enable_improved_email_privacy: bool = False):
        self.enable_improved_email_privacy: bool = enable_improved_email_privacy

    def to_dict(self) -> dict:
        data = {}
        if self.enable_improved_email_privacy:
            data['enableImprovedEmailPrivacy'] = self.enable_improved_email_privacy
        return data

    def validate(self):
        """Validates a given email_privacy_config object.

        Raises:
            ValueError: In case of an unsuccessful validation.
        """
        validate_keys(
            keys=vars(self).keys(),
            valid_keys={'enable_improved_email_privacy'},
            config_name='EmailPrivacyConfig')
        if self.enable_improved_email_privacy is None:
            raise ValueError(
                'email_privacy_config.enable_improved_email_privacy must be specified')
        if not isinstance(self.enable_improved_email_privacy, bool):
            raise ValueError(
                'enable_improved_email_privacy must be a valid bool.')

    def build_server_request(self):
        self.validate()
        return self.to_dict()
