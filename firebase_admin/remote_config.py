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

import asyncio
from typing import Any, Dict, Optional
import requests
from firebase_admin import App, _http_client, _utils
import firebase_admin

_REMOTE_CONFIG_ATTRIBUTE = '_remoteconfig'

class ServerTemplateData:
    """Parses, validates and encapsulates template data and metadata."""
    def __init__(self, etag, template_data):
        """Initializes a new ServerTemplateData instance.

        Args:
            etag: The string to be used for initialize the ETag property.
            template_data: The data to be parsed for getting the parameters and conditions.

        Raises:
            ValueError: If the template data is not valid.
        """
        if 'parameters' in template_data:
            if template_data['parameters'] is not None:
                self._parameters = template_data['parameters']
            else:
                raise ValueError('Remote Config parameters must be a non-null object')
        else:
            self._parameters = {}

        if 'conditions' in template_data:
            if template_data['conditions'] is not None:
                self._conditions = template_data['conditions']
            else:
                raise ValueError('Remote Config conditions must be a non-null object')
        else:
            self._conditions = []

        self._version = ''
        if 'version' in template_data:
            self._version = template_data['version']

        self._etag = ''
        if etag is not None and isinstance(etag, str):
            self._etag = etag

    @property
    def parameters(self):
        return self._parameters

    @property
    def etag(self):
        return self._etag

    @property
    def version(self):
        return self._version

    @property
    def conditions(self):
        return self._conditions


class ServerTemplate:
    """Represents a Server Template with implementations for loading and evaluting the template."""
    def __init__(self, app: App = None, default_config: Optional[Dict[str, str]] = None):
        """Initializes a ServerTemplate instance.

        Args:
          app: App instance to be used. This is optional and the default app instance will
                be used if not present.
          default_config: The default config to be used in the evaluated config.
        """
        self._rc_service = _utils.get_app_service(app,
                                                  _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)

        # This gets set when the template is
        # fetched from RC servers via the load API, or via the set API.
        self._cache = None
        self._stringified_default_config: Dict[str, str] = {}

        # RC stores all remote values as string, but it's more intuitive
        # to declare default values with specific types, so this converts
        # the external declaration to an internal string representation.
        if default_config is not None:
            for key in default_config:
                self._stringified_default_config[key] = str(default_config[key])

    async def load(self):
        """Fetches the server template and caches the data."""
        self._cache = await self._rc_service.get_server_template()

    def evaluate(self):
        # Logic to process the cached template into a ServerConfig here.
        # TODO: Add and validate Condition evaluator.
        self._evaluator = _ConditionEvaluator(self._cache.parameters)
        return ServerConfig(config_values=self._evaluator.evaluate())

    def set(self, template: ServerTemplateData):
        """Updates the cache to store the given template is of type ServerTemplateData.

        Args:
          template: An object of type ServerTemplateData to be cached.
        """
        self._cache = template


class ServerConfig:
    """Represents a Remote Config Server Side Config."""
    def __init__(self, config_values):
        self._config_values = config_values # dictionary of param key to values

    def get_boolean(self, key):
        return bool(self.get_value(key))

    def get_string(self, key):
        return str(self.get_value(key))

    def get_int(self, key):
        return int(self.get_value(key))

    def get_value(self, key):
        return self._config_values[key]


class _RemoteConfigService:
    """Internal class that facilitates sending requests to the Firebase Remote
        Config backend API.
    """
    def __init__(self, app):
        """Initialize a JsonHttpClient with necessary inputs.

        Args:
            app: App instance to be used for fetching app specific details required
                for initializing the http client.
        """
        remote_config_base_url = 'https://firebaseremoteconfig.googleapis.com'
        self._project_id = app.project_id
        app_credential = app.credential.get_credential()
        rc_headers = {
            'X-FIREBASE-CLIENT': 'fire-admin-python/{0}'.format(firebase_admin.__version__), }
        timeout = app.options.get('httpTimeout', _http_client.DEFAULT_TIMEOUT_SECONDS)

        self._client = _http_client.JsonHttpClient(credential=app_credential,
                                                   base_url=remote_config_base_url,
                                                   headers=rc_headers, timeout=timeout)

    async def get_server_template(self):
        """Requests for a server template and converts the response to an instance of
        ServerTemplateData for storing the template parameters and conditions."""
        try:
            loop = asyncio.get_event_loop()
            headers, template_data = await loop.run_in_executor(None,
                                                                self._client.headers_and_body,
                                                                'get', self._get_url())
        except requests.exceptions.RequestException as error:
            raise self._handle_remote_config_error(error)
        else:
            return ServerTemplateData(headers.get('etag'), template_data)

    def _get_url(self):
        """Returns project prefix for url, in the format of /v1/projects/${projectId}"""
        return "/v1/projects/{0}/namespaces/firebase-server/serverRemoteConfig".format(
            self._project_id)

    @classmethod
    def _handle_remote_config_error(cls, error: Any):
        """Handles errors received from the Cloud Functions API."""
        return _utils.handle_platform_error_from_requests(error)


class _ConditionEvaluator:
    """Internal class that facilitates sending requests to the Firebase Remote
    Config backend API."""
    def __init__(self, parameters):
        self._parameters = parameters

    def evaluate(self):
        # TODO: Write logic for evaluator
        return self._parameters


async def get_server_template(app: App = None, default_config: Optional[Dict[str, str]] = None):
    """Initializes a new ServerTemplate instance and fetches the server template.

    Args:
        app: App instance to be used. This is optional and the default app instance will
            be used if not present.
        default_config: The default config to be used in the evaluated config.

    Returns:
        ServerTemplate: An object having the cached server template to be used for evaluation.
    """
    template = init_server_template(app=app, default_config=default_config)
    await template.load()
    return template

def init_server_template(app: App = None, default_config: Optional[Dict[str, str]] = None,
                         template_data: Optional[ServerTemplateData] = None):
    """Initializes a new ServerTemplate instance.

    Args:
        app: App instance to be used. This is optional and the default app instance will
            be used if not present.
        default_config: The default config to be used in the evaluated config.
        template_data: An optional template data to be set on initialization.

    Returns:
        ServerTemplate: A new ServerTemplate instance initialized with an optional
        template and config.
    """
    template = ServerTemplate(app=app, default_config=default_config)
    if template_data is not None:
        template.set(template_data)
    return template
