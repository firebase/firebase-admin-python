"""Firebase Data Connect module.

This module contains utilities for accessing Firebase Data Connect services associated with
Firebase apps.
"""

from dataclasses import dataclass
from typing import Dict, Optional

from firebase_admin import _utils, App

__all__ = ['ConnectorConfig', 'DataConnect', 'client']

_DATA_CONNECT_ATTRIBUTE = '_data_connect_service'

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
    """Returns a DataConnect client for the specified configuration."""
    if not isinstance(config, ConnectorConfig):
        raise ValueError("Config must be of type firebase_admin.dataconnect.ConnectorConfig")

    # must check whether app has a _DataConnectService attached to it yet
    dc_service = _utils.get_app_service(app, _DATA_CONNECT_ATTRIBUTE, _DataConnectService)

    return dc_service.get_client(config)
