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

"""Firebase Data Connect module.

This module contains utilities for accessing Firebase Data Connect services associated with
Firebase apps.
"""

from collections.abc import Mapping
from dataclasses import dataclass, asdict, is_dataclass
from typing import Any, Dict, Generic, Optional, Type, TypeVar, Union
import firebase_admin
from firebase_admin import _utils, _http_client, App

__all__ = [
    'ConnectorConfig',
    'DataConnect',
    'client',
    'GraphqlOptions',
    'Impersonation',
    'ExecuteGraphqlResponse',
]

_DATA_CONNECT_ATTRIBUTE = '_data_connect'
_DATA_CONNECT_PROD_URL = 'https://firebasedataconnect.googleapis.com'
_API_VERSION = 'v1'

_SERVICES_URL_FORMAT = (
    '{host}/{version}/projects/{project_id}/locations/{location_id}'
    '/services/{service_id}:{endpoint_id}'
)

_EMULATOR_SERVICES_URL_FORMAT = (
    'http://{host}/{version}/projects/{project_id}/locations/{location_id}'
    '/services/{service_id}:{endpoint_id}'
)

# Generic Type Parameters
_Data = TypeVar("_Data")
_Variables = TypeVar("_Variables")

@dataclass(frozen=True)
class ConnectorConfig:
    """A configuration object for DataConnect.

    Attributes:
        service_id: A string representing the Google Cloud project ID of the service.
        location: A string representing the region of the service.
        connector: A string representing the name of the connector.
    """

    service_id: str
    location: str
    connector: str

    def __post_init__(self):
        if not isinstance(self.service_id, str):
            raise ValueError("service_id must be a string")
        if not self.service_id:
            raise ValueError("service_id cannot be empty")
        if not isinstance(self.location, str):
            raise ValueError("location must be a string")
        if not self.location:
            raise ValueError("location cannot be empty")
        if not isinstance(self.connector, str):
            raise ValueError("connector must be a string")
        if not self.connector:
            raise ValueError("connector cannot be empty")


class DataConnect:
    """Represents a Firebase Data Connect client instance. 
    
       This client provides access to the Firebase Data Connect service 
       for a specific Firebase app and connector configuration.
    
    Attributes:
        app: The Firebase App instance for this client.
        config: The ConnectorConfig object specifying the service ID, location, and connector name.
    """

    def __init__(self, app: App, config: ConnectorConfig) -> None:
        """Initializes a DataConnect client instance. """
        self._app: App = app
        self._config = config

    @property
    def app(self) -> App:
        return self._app

    @property
    def config(self) -> ConnectorConfig:
        return self._config


class _DataConnectService:
    """Service that maintains a collection of DataConnect clients."""

    def __init__(self, app: App) -> None:
        self._app: App = app
        self._clients: Dict[ConnectorConfig, DataConnect] = {}

    def get_client(self, config: ConnectorConfig) -> DataConnect:
        """Creates a client based on the ConnectorConfig. These clients are cached."""
        if not isinstance(config, ConnectorConfig):
            raise ValueError("Config must be of type firebase_admin.dataconnect.ConnectorConfig")
        if config not in self._clients:
            self._clients[config] = DataConnect(app=self._app, config=config)
        return self._clients[config]


def client(config: ConnectorConfig, app: Optional[App] = None) -> DataConnect:
    """Returns a DataConnect client for the specified configuration.

    This function does not make any RPC calls.

    Args:
        config: A ConnectorConfig instance specifying the service ID, location,
            and connector name.
        app: An App instance (optional). Defaults to the default Firebase App.

    Returns:
        DataConnect: A handle to the specified DataConnect client instance.

    Raises:
        ValueError: If config argument is not an instance of ConnectorConfig, or if
            app is an invalid instance of App.
    """

    if not isinstance(config, ConnectorConfig):
        raise ValueError("Config must be of type firebase_admin.dataconnect.ConnectorConfig")

    # must check whether app has a _DataConnectService attached to it yet
    dc_service = _utils.get_app_service(app, _DATA_CONNECT_ATTRIBUTE, _DataConnectService)

    return dc_service.get_client(config)



class Impersonation(dict):
    """Represents impersonation configuration for DataConnect requests."""

    @staticmethod
    def unauthenticated() -> 'Impersonation':
        """Returns impersonation configuration for unauthenticated requests."""
        return Impersonation(unauthenticated=True)

    @staticmethod
    def authenticated(auth_claims: Dict[str, Any]) -> 'Impersonation':
        """Returns impersonation configuration for authenticated requests.

        # TODO: More strongly type auth_claims later.
        """
        return Impersonation(authClaims=auth_claims)


@dataclass
class GraphqlOptions(Generic[_Variables]):
    variables: Optional[_Variables] = None
    operation_name: Optional[str] = None
    impersonate: Optional[Union[Impersonation, Dict[str, Any]]] = None


@dataclass
class ExecuteGraphqlResponse(Generic[_Data]):
    data: _Data


def _get_emulator_host() -> Optional[str]:
    return _utils.get_emulator_host("DATA_CONNECT_EMULATOR_HOST")


class _DataConnectApiClient:
    """Internal client for sending requests to the Firebase Data Connect backend.

    Attributes:
        connector_config: The connector configuration specifying the service,
            location, and connector name.
        app: The Firebase App instance associated with this client.
    """

    def __init__(self, connector_config: ConnectorConfig, app: App) -> None:
        if not isinstance(app, App):
            raise ValueError(
                'Second argument passed to DataConnectApiClient must be a valid '
                'Firebase app instance.'
            )
        self._connector_config = connector_config
        self._app = app

        self._project_id = app.project_id
        if not self._project_id:
            raise ValueError(
                'Failed to determine project ID. Initialize the SDK with service '
                'account credentials or set project ID as an app option. Alternatively, set the '
                'GOOGLE_CLOUD_PROJECT environment variable.')

        self._emulator_host = _get_emulator_host()
        if self._emulator_host:
            self._credential = _utils.EmulatorAdminCredentials()
        else:
            self._credential = app.credential.get_credential()

        self._http_client = _http_client.JsonHttpClient(credential=self._credential)

    def _validate_variables_type(
        self,
        variables: Any,
        variable_type: Optional[Type[Any]] = None
    ) -> None:
        """Validates variables against expected type."""
        if variables is not None:
            if not (isinstance(variables, Mapping) or is_dataclass(variables)):
                raise ValueError("variables must be a collections.abc.Mapping or a dataclass")
            if variable_type is not None:
                if not isinstance(variables, variable_type):
                    type_name = getattr(variable_type, '__name__', str(variable_type))
                    raise ValueError(f"variables must be of type {type_name}")

    def _validate_impersonation_options(self, impersonate: Any) -> None:
        """Validates impersonation dictionary options."""
        if impersonate is not None:
            if not isinstance(impersonate, dict):
                raise ValueError('impersonate option must be a dictionary')
            if 'unauthenticated' not in impersonate and 'authClaims' not in impersonate:
                raise ValueError(
                    "impersonate option must contain either "
                    "'unauthenticated' or 'authClaims'"
                )
            if 'unauthenticated' in impersonate and 'authClaims' in impersonate:
                raise ValueError(
                    "impersonate option cannot contain both "
                    "'unauthenticated' and 'authClaims'"
                )
            if 'unauthenticated' in impersonate:
                if not isinstance(impersonate['unauthenticated'], bool):
                    raise ValueError("'unauthenticated' claim must be a boolean")
            if 'authClaims' in impersonate:
                if not isinstance(impersonate['authClaims'], dict):
                    raise ValueError("'authClaims' claim must be a dictionary")

    def _validate_graphql_options(
        self,
        graphql_options: Optional[GraphqlOptions[Any]],
        variable_type: Optional[Type[Any]] = None
    ) -> None:
        """Validates GraphqlOptions inputs at runtime."""
        if graphql_options is not None:
            if not isinstance(graphql_options, GraphqlOptions):
                raise ValueError('options must be a GraphqlOptions instance')

            # Validate Variables against expected variable_type
            self._validate_variables_type(graphql_options.variables, variable_type)

            # Validate Operation Name (if it exists)
            operation_name = graphql_options.operation_name
            if operation_name is not None:
                if not isinstance(operation_name, str):
                    raise ValueError('operation_name must be a string')
                operation_name = operation_name.strip()
                if not operation_name:
                    raise ValueError('operation_name must be a non-empty string')
                graphql_options.operation_name = operation_name

            # Validate Impersonation (if it exists)
            self._validate_impersonation_options(graphql_options.impersonate)

    def _prepare_graphql_payload(
        self,
        graphql_query: str,
        graphql_options: Optional[GraphqlOptions[_Variables]]
    ) -> Dict[str, Any]:
        """Serializes input query and options to JSON-compatible dictionary."""
        payload = {
            "query": graphql_query
        }

        if graphql_options is not None:
            if graphql_options.variables is not None:
                if is_dataclass(graphql_options.variables):
                    payload["variables"] = asdict(graphql_options.variables)
                else:
                    payload["variables"] = graphql_options.variables

            if graphql_options.operation_name is not None:
                payload["operationName"] = graphql_options.operation_name

            if graphql_options.impersonate is not None:
                payload["extensions"] = {
                    "impersonate": graphql_options.impersonate
                }

        return payload

    def _get_firebase_dataconnect_service_url(self, method_name: str) -> str:
        """Build and return the URL for a Firebase Data Connect API method."""
        project_id = self._project_id
        location = self._connector_config.location
        service_id = self._connector_config.service_id

        if self._emulator_host:
            return _EMULATOR_SERVICES_URL_FORMAT.format(
                host=self._emulator_host,
                version=_API_VERSION,
                project_id=project_id,
                location_id=location,
                service_id=service_id,
                endpoint_id=method_name
            )
        return _SERVICES_URL_FORMAT.format(
            host=_DATA_CONNECT_PROD_URL,
            version=_API_VERSION,
            project_id=project_id,
            location_id=location,
            service_id=service_id,
            endpoint_id=method_name
        )

    def _get_headers(self) -> Dict[str, str]:
        """Build and return the headers for a Firebase Data Connect API call."""
        return {
            "X-Firebase-Client": f"fire-admin-python/{firebase_admin.__version__}",
            "x-goog-api-client": _utils.get_metrics_header(),
        }
