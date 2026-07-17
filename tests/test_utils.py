# Copyright 2026 Google Inc.
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

"""Test cases for the firebase_admin._utils module."""

import pytest
from firebase_admin import _utils

class TestGetEmulatorHost:

    @pytest.mark.parametrize('host', [
        'localhost:8080',
        '127.0.0.1:8080',
        '[::1]:8080',
        '[2001:db8::1]:8080',
        'my-host:9000',
        'my_host:9000',
        'my.host.name:12345',
        'host_with_underscores:8080',
    ])
    def test_get_emulator_host_valid(self, monkeypatch, host):
        monkeypatch.setenv('TEST_EMULATOR_HOST', host)
        assert _utils.get_emulator_host('TEST_EMULATOR_HOST') == host

    @pytest.mark.parametrize('host', [
        'http://localhost:8080',
        'localhost',
        '127.0.0.1',
        '[::1]',
        'my_host',
        'localhost:abc',
        'localhost:',
        ':8080',
        'invalid_host_name_with_chars$:8080',
        'host@name:8080',
    ])
    def test_get_emulator_host_invalid(self, monkeypatch, host):
        monkeypatch.setenv('TEST_EMULATOR_HOST', host)
        with pytest.raises(ValueError, match='Invalid TEST_EMULATOR_HOST'):
            _utils.get_emulator_host('TEST_EMULATOR_HOST')

    def test_get_emulator_host_not_set(self, monkeypatch):
        monkeypatch.delenv('TEST_EMULATOR_HOST', raising=False)
        assert _utils.get_emulator_host('TEST_EMULATOR_HOST') is None
