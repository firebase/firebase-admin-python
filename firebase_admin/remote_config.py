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
from firebase_admin import App, _http_client, _utils
import firebase_admin

_REMOTE_CONFIG_ATTRIBUTE = '_remoteconfig'

class ServerTemplateData:
    """Represents a Server Template Data class.
    """
    def __init__(self, resp):
        self._parameters = resp.body.parameters
        self._conditions = resp.body.conditions
        self._version = resp.body.version
        self._etag = resp.headers.get('ETag')

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

class Parameter:
    """ Representation of a remote config parameter."""

    def __init__(self, default_value):
        self._default_value = default_value # ParameterValue

    @property
    def default_value(self):
        return self._default_value


class ParameterValue:
    """ Base class to represent remote parameter values. A
    ParameterValue could be either an ExplicitParameterValue or an
    InAppDefaultValue. """


class ExplicitParameterValue(ParameterValue):
    def __init__(self, value):
        self._value = value

    @property
    def value(self):
        return self._value

class InAppDefaultValue(ParameterValue):
    def __init__(self, use_in_app_default):
        self._use_in_app_default = use_in_app_default

    @property
    def use_in_app_default(self):
        return self._use_in_app_default


class ServerTemplate:
    """Represents a Server Template with implementations for loading and evaluting the tempalte.
    """
    def __init__(self, app: App, default_config: Optional[Dict[str, str]] = None):
        self._rc_service = _utils.get_app_service(app, _REMOTE_CONFIG_ATTRIBUTE, _RemoteConfigService)

        # Field to represent the cached template. This gets set when the template is
        # fetched from RC servers via the load API, or via the set API.
        self._cache = None
        for key in default_config:
            self._stringified_default_config[key] = default_config[key]

    async def load(self):
        self._cache = await self._rc_service.getServerTemplate()

    def evaluate(self, context: Optional[Dict[str, str | int]]):
        # Logic to process the cached template into a ServerConfig here
        # TODO: add Condition evaluator 
        return ServerConfig(config_values=context.values)

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

class _RemoteConfigService:
    """ Internal class that facilitates sending requests to the Firebase Remote
    Config backend API. """

    def __init__(self, app):
        # Initialize a JsonHttpClient with basic inputs. Referenced other
        # products' code in the Python SDK for what basic inputs to use.
        remote_config_base_url = 'https://firebaseremoteconfig.googleapis.com'
        self._project_id = app.project_id
        app_credential = app.credential.get_credential()
        rc_headers = {
            'X-FIREBASE-CLIENT': 'fire-admin-python/{0}'.format(firebase_admin.__version__), }
        timeout = app.options.get('httpTimeout', _http_client.DEFAULT_TIMEOUT_SECONDS)

        self._client = _http_client.JsonHttpClient(credential=app_credential,
                                                   base_url=remote_config_base_url,
                                                   headers=rc_headers, timeout=timeout)


    def get_server_template(self):
        # Requests for server template and converts the response to
        # ServerTemplateData
        url_prefix = self._get_url_prefix()
        response_json = self._client.body('get',
                                          url=url_prefix+'/namespaces/ \
                                            firebase-server/serverRemoteConfig')
        return ServerTemplateData(response_json)

    def _get_url_prefix(self):
        # Returns project prefix for url, in the format of
        # /v1/projects/${projectId}
        return "/v1/projects/{0}".format(self._project_id)
    

async def get_server_template(app: App, default_config: Optional[Dict[str, str]] = None):
    template = init_server_template(app, default_config)
    await template.load()
    return template

def init_server_template(app: App, default_config: Optional[Dict[str, str]] = None, 
                         template_data: Optional[ServerTemplateData] = None):
    template = ServerTemplate(app, default_config=default_config)
    template.set(template_data)
    return template
