# Copyright 2017 Google Inc.
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

"""Firebase Remote Config Module.
This module has required APIs for the clients to use Firebase Remote Config with python.
"""

from typing import Dict, Optional
from firebase_admin import _http_client

class RemoteConfig:
    """Represents a Server Side Remote Config Class.

    The users can use this for initializing and loading a server template.
    """

    def __init__(self, app=None):
        timeout = app.options.get('httpTimeout', _http_client.DEFAULT_TIMEOUT_SECONDS)
        self._credential = app.credential.get_credential()
        self._api_client = _http_client.RemoteConfigApiClient(
            credential=self._credential, timeout=timeout)

    async def get_server_template(self, default_config: Optional[Dict[str, str]] = None):
        template = self.init_server_template(default_config)
        await template.load()
        return template

    def init_server_template(self, default_config: Optional[Dict[str, str]] = None):
        template = ServerTemplate(self._api_client, default_config=default_config)
        # Logic to handle setting template_data here
        return template


class ServerTemplateData:
    """Represents a Server Template Data class.
    """
    def __init__(self, template):
        self._template = template


class ServerTemplate:
    """Represents a Server Template with implementations for loading and evaluting the tempalte.
    """
    def __init__(self, client, default_config: Optional[Dict[str, str]] = None):
        # Private API client used to make network requests
        self._client = client
        # Field to represent the cached template. This gets set when the template is
        # fetched from RC servers via the load API, or via the set API.
        self._cache = None
        self._stringified_default_config = default_config.values
            # Logic to set default_config here

    async def load(self):
        self._cache = await self._client.getServerTemplate()

    def evaluate(self, context: Optional[Dict[str, str | int]]):
        # Logic to process the cached template into a ServerConfig here
        return ServerConfig(context.values)

    def set(self, template):
        if isinstance(template, str):
            self._cache = ServerTemplateData(template)
        elif isinstance(template, ServerTemplateData):
            self._cache = template


class ServerConfig:
    """Represents a Remote Config Server Side Config.
    """
    def __init__(self, config_values):
        self._config_values = config_values # dictionary of param key to values

    def get_boolean(self, key):
        return self._config_values[key]

    def get_string(self, key):
        return self._config_values[key]

    def get_int(self, key):
        return self._config_values[key]

    def get_value(self, key):
        return self._config_values[key]
