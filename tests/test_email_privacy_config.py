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

from firebase_admin.email_privacy_config_mgt import EmailPrivacyConfig
from firebase_admin.email_privacy_config_mgt import EmailPrivacyServerConfig

sample_email_privacy_config = EmailPrivacyConfig(
    enable_improved_email_privacy=True,
)


class TestEmailPrivacyConfig:
    def test_invalid_email_privacy_config_params(self):
        test_config = copy(sample_email_privacy_config)
        test_config.invalid_parameter = 'invalid'
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('"invalid_parameter" is not a valid'
                                             ' "EmailPrivacyConfig" parameter.')

    @pytest.mark.parametrize('enable_improved_email_privacy',
                             [{}, 1, 0, list(), tuple(), dict()])
    def test_invalid_enable_improved_email_privacy_type(self, enable_improved_email_privacy):
        test_config = copy(sample_email_privacy_config)
        test_config.enable_improved_email_privacy = enable_improved_email_privacy
        with pytest.raises(ValueError) as excinfo:
            test_config.build_server_request()
        assert str(excinfo.value).startswith('enable_improved_email_privacy must be a valid bool.')


class TestEmailPrivacyServerConfig:
    def test_invalid_email_privacy_config_response(self):
        test_config = 'invalid'
        with pytest.raises(ValueError) as excinfo:
            EmailPrivacyServerConfig(test_config)
        assert str(excinfo.value).startswith('Invalid data argument in EmailPrivacyConfig'
                                             ' constructor: {0}'.format(test_config))

    def test_valid_server_response(self):
        response = {
            'enableImprovedEmailPrivacy': True,
        }
        email_privacy_config = EmailPrivacyServerConfig(response)
        _assert_email_privacy_config(email_privacy_config)


def _assert_email_privacy_config(email_privacy_config):
    assert isinstance(email_privacy_config, EmailPrivacyServerConfig)
    assert email_privacy_config.enable_improved_email_privacy is True
