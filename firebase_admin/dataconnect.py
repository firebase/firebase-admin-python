from dataclasses import dataclass
from firebase_admin import App
from typing import Any, Dict, Generic, Optional, TypeVar, Union

@dataclass(frozen=True)
class ConnectorConfig:
    """
    Attributes:
        service_id (str): The Google Cloud project ID of the service.
        location (str): The region of the service.
        connector (str): The name of the connector.
    """

    service_id: str
    location: str
    connector: str

    def __post_init__(self):
        if not self.service_id:
            raise ValueError("service_id cannot be empty")
        if not self.location:
            raise ValueError("location cannot be empty")
        if not self.connector:
            raise ValueError("connector cannot be empty")


class DataConnect:
    def __init__(self, app: App, config: ConnectorConfig) -> None:
        """Initializes a DataConnect client instance"""
        self._app: App = app
        self._config = config

def client(config: ConnectorConfig, app: Optional[App] = None) -> DataConnect:
    """Returns a DataConnect client for the specified configuration"""