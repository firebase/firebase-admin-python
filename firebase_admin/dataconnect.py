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
import enum
import typing
from typing import Any, Dict, Generic, Optional, Type, TypeVar, Union

import requests

try:
    from types import UnionType  # pylint: disable=no-name-in-module
except ImportError:
    UnionType = None

import firebase_admin
from firebase_admin import _utils, _http_client, App, exceptions

__all__ = [
    'ConnectorConfig',
    'DataConnect',
    'client',
    'GraphqlOptions',
    'Impersonation',
    'ExecuteGraphqlResponse',
    'QueryError',
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


# Error Codes
_QUERY_ERROR_CODE = 'query-error'


class QueryError(exceptions.FirebaseError):
    """Raised when a GraphQL query or mutation execution fails."""

    def __init__(self, message: str, http_response: Any = None) -> None:
        super().__init__(
            code=_QUERY_ERROR_CODE,
            message=message,
            http_response=http_response
        )

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
                expected_type = typing.get_origin(variable_type) or variable_type
                if not isinstance(variables, expected_type):
                    type_name = getattr(expected_type, '__name__', str(expected_type))
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
                if not operation_name.strip():
                    raise ValueError('operation_name must be a non-empty string')

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
                payload["operationName"] = graphql_options.operation_name.strip()

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

    @staticmethod
    def _check_graphql_errors(resp_dict: Any, resp: Any) -> None:
        """Raises QueryError if the GraphQL response payload contains an errors key."""
        if isinstance(resp_dict, dict) and "errors" in resp_dict:
            errors = resp_dict["errors"]
            all_messages = ""
            if isinstance(errors, list):
                messages = []
                for err in errors:
                    if isinstance(err, dict):
                        message = err.get("message")
                        if message:
                            messages.append(message)
                all_messages = " ".join(messages)
            if not all_messages:
                all_messages = (
                    f"GraphQL execution failed: {errors}" if errors
                    else "GraphQL execution failed."
                )
            raise QueryError(
                message=all_messages,
                http_response=resp
            )

    def _make_gql_request(
        self,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Make a GraphQL request to the Data Connect service."""
        if url is None or headers is None or payload is None:
            raise ValueError("url, headers, and payload must all be specified.")

        try:
            resp_dict, resp = self._http_client.body_and_response(
                'post',
                url=url,
                headers=headers,
                json=payload
            )
        except requests.exceptions.RequestException as error:
            raise _utils.handle_platform_error_from_requests(error)

        _DataConnectApiClient._check_graphql_errors(resp_dict, resp)
        return resp_dict

    @staticmethod
    def _extract_actual_type(field_type: Any) -> Any:
        origin = typing.get_origin(field_type)
        if origin is Union or (UnionType is not None and origin is UnionType):
            args = typing.get_args(field_type)
            non_none_args = [arg for arg in args if arg is not type(None)]
            if len(non_none_args) == 1:
                return non_none_args[0]
        return field_type

    @staticmethod
    def _deserialize_type(type_hint: Any, data: Any) -> Any:
        """Recursively deserializes data into the specified type hint."""
        if data is None or type_hint is Any:
            return data

        actual_type = _DataConnectApiClient._extract_actual_type(type_hint)

        origin = typing.get_origin(actual_type)
        args = typing.get_args(actual_type)

        # Union (e.g. Union[int, str] or Union[int, List[str]])
        if origin is Union or (UnionType is not None and origin is UnionType):
            for arg in args:
                try:
                    res = _DataConnectApiClient._deserialize_type(arg, data)
                    base = typing.get_origin(arg) or arg
                    if base is Any or (isinstance(base, type) and isinstance(res, base)):
                        return res
                except (ValueError, TypeError):
                    continue
            return data

        # Dataclass
        if is_dataclass(actual_type):
            return _DataConnectApiClient._deserialize_dataclass(actual_type, data)

        # List
        if (origin is list or actual_type is list) and isinstance(data, list):
            if args:
                return [_DataConnectApiClient._deserialize_type(args[0], item) for item in data]
            return data

        # Dict / Mapping
        if (origin in (dict, Mapping) or actual_type in (dict, Mapping)) and isinstance(data, dict):
            if len(args) == 2:
                k_type, v_type = args
                new_dict = {}
                for key, val in data.items():
                    try:
                        coerced_key = k_type(key) if isinstance(k_type, type) else key
                    except (ValueError, TypeError):
                        coerced_key = key
                    new_dict[coerced_key] = _DataConnectApiClient._deserialize_type(
                        v_type, val
                    )
                return new_dict
            return data

        # Enum (fails loudly on invalid value)
        if isinstance(actual_type, type) and issubclass(actual_type, enum.Enum):
            try:
                return actual_type(data)
            except (ValueError, TypeError) as err:
                raise ValueError(
                    f"Invalid value {data!r} for Enum '{actual_type.__name__}'."
                ) from err

        # Primitive / Class Constructor
        if isinstance(actual_type, type):
            try:
                return actual_type(data)
            except (ValueError, TypeError):
                return data

        return data

    @staticmethod
    def _deserialize_dataclass(type_hint: Any, data: Any) -> Any:
        """Deserializes a dictionary payload into a target dataclass instance."""
        if not is_dataclass(type_hint):
            return data
        if not isinstance(data, dict):
            return data

        type_hints = typing.get_type_hints(type_hint)
        fields_to_pass = {}
        for field_name, _ in type_hint.__dataclass_fields__.items():
            if field_name in data:
                val = data[field_name]
                field_type = type_hints.get(field_name)
                fields_to_pass[field_name] = _DataConnectApiClient._deserialize_type(
                    field_type, val
                )
        return type_hint(**fields_to_pass)

    @staticmethod
    def _parse_graphql_response(
        resp_dict: Dict[str, Any],
        data_type: Type[_Data] = Any
    ) -> ExecuteGraphqlResponse[_Data]:
        """Parses a raw GraphQL response payload into ExecuteGraphqlResponse."""
        if not isinstance(resp_dict, dict):
            raise exceptions.InternalError(
                message="Response payload is not a valid JSON dictionary."
            )

        data = resp_dict.get("data")

        if data is None:
            return ExecuteGraphqlResponse(data=None)

        deserialized_data = _DataConnectApiClient._deserialize_type(data_type, data)
        return ExecuteGraphqlResponse(data=deserialized_data)
