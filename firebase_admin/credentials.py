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

"""Firebase credentials module."""
import datetime
import json
import pathlib
from typing import TYPE_CHECKING, Any, NamedTuple, Optional, Union, cast
from typing_extensions import TypeGuard

import google.auth

from google.auth.credentials import Credentials as GoogleAuthCredentials
from google.auth.transport import requests
from google.auth import crypt
from google.oauth2 import credentials
from google.oauth2 import service_account

if TYPE_CHECKING:
    from _typeshed import StrPath

__all__ = (
    'AccessTokenInfo',
    'ApplicationDefault',
    'Base',
    'Certificate',
    'RefreshToken',
)

_request = requests.Request()
_scopes = [
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/datastore',
    'https://www.googleapis.com/auth/devstorage.read_write',
    'https://www.googleapis.com/auth/firebase',
    'https://www.googleapis.com/auth/identitytoolkit',
    'https://www.googleapis.com/auth/userinfo.email'
]


class AccessTokenInfo(NamedTuple):
    """Data included in an OAuth2 access token.

    Contains the access token string and the expiry time. The expirty time is exposed as a
    ``datetime`` value.
    """
    access_token: Any
    expiry: Optional[datetime.datetime]


class Base:
    """Provides OAuth2 access tokens for accessing Firebase services."""

    def get_access_token(self) -> AccessTokenInfo:
        """Fetches a Google OAuth2 access token using this credential instance.

        Returns:
          AccessTokenInfo: An access token obtained using the credential.
        """
        google_cred = self.get_credential()
        google_cred.refresh(_request)
        return AccessTokenInfo(google_cred.token, google_cred.expiry)

    def get_credential(self) -> GoogleAuthCredentials:
        """Returns the Google credential instance used for authentication."""
        raise NotImplementedError


class _ExternalCredentials(Base):  # pyright: ignore[reportUnusedClass]
    """A wrapper for google.auth.credentials.Credentials typed credential instances"""

    def __init__(self, credential: GoogleAuthCredentials) -> None:
        self._g_credential = credential

    def get_credential(self) -> GoogleAuthCredentials:
        """Returns the underlying Google Credential

        Returns:
          google.auth.credentials.Credentials: A Google Auth credential instance."""
        return self._g_credential


class Certificate(Base):
    """A credential initialized from a JSON certificate keyfile."""

    _CREDENTIAL_TYPE = 'service_account'

    def __init__(self, cert: Union['StrPath', dict[str, Any]]) -> None:
        """Initializes a credential from a Google service account certificate.

        Service account certificates can be downloaded as JSON files from the Firebase console.
        To instantiate a credential from a certificate file, either specify the file path or a
        dict representing the parsed contents of the file.

        Args:
          cert: Path to a certificate file or a dict representing the contents of a certificate.

        Raises:
          IOError: If the specified certificate file doesn't exist or cannot be read.
          ValueError: If the specified certificate is invalid.
        """
        super().__init__()
        if _is_file_path(cert):
            with open(cert, encoding='utf-8') as json_file:
                json_data = json.load(json_file)
        elif isinstance(cert, dict):
            json_data = cert
        else:
            raise ValueError(
                f'Invalid certificate argument: "{cert}". Certificate argument must be a file '
                'path, or a dict containing the parsed file contents.')

        if json_data.get('type') != self._CREDENTIAL_TYPE:
            raise ValueError(
                'Invalid service account certificate. Certificate must contain a '
                f'"type" field set to "{self._CREDENTIAL_TYPE}".')
        try:
            self._g_credential = service_account.Credentials.from_service_account_info(
                json_data, scopes=_scopes)
        except ValueError as error:
            raise ValueError(
                f'Failed to initialize a certificate credential. Caused by: "{error}"') from error

    @property
    def project_id(self) -> Optional[str]:
        return self._g_credential.project_id

    @property
    def signer(self) -> crypt.Signer:
        return self._g_credential.signer

    @property
    def service_account_email(self) -> str:
        return self._g_credential.service_account_email

    def get_credential(self) -> GoogleAuthCredentials:
        """Returns the underlying Google credential.

        Returns:
          google.auth.credentials.Credentials: A Google Auth credential instance."""
        return self._g_credential


class ApplicationDefault(Base):
    """A Google Application Default credential."""

    def __init__(self) -> None:
        """Creates an instance that will use Application Default credentials.

        The credentials will be lazily initialized when get_credential() or
        project_id() is called. See those methods for possible errors raised.
        """
        # Will be lazily-loaded via _load_credential().
        self._g_credential: Optional[GoogleAuthCredentials] = None
        self._project_id: Optional[str] = None

    def get_credential(self) -> GoogleAuthCredentials:
        """Returns the underlying Google credential.

        Raises:
          google.auth.exceptions.DefaultCredentialsError: If Application Default
              credentials cannot be initialized in the current environment.
        Returns:
          google.auth.credentials.Credentials: A Google Auth credential instance."""
        self._load_credential()
        return cast(GoogleAuthCredentials, self._g_credential)

    @property
    def project_id(self) -> Optional[str]:
        """Returns the project_id from the underlying Google credential.

        Raises:
          google.auth.exceptions.DefaultCredentialsError: If Application Default
              credentials cannot be initialized in the current environment.
        Returns:
          str: The project id."""
        self._load_credential()
        return self._project_id

    def _load_credential(self) -> None:
        if not self._g_credential:
            self._g_credential, self._project_id = google.auth.default(scopes=_scopes)


class RefreshToken(Base):
    """A credential initialized from an existing refresh token."""

    _CREDENTIAL_TYPE = 'authorized_user'

    def __init__(self, refresh_token: Union['StrPath', dict[str, Any]]) -> None:
        """Initializes a credential from a refresh token JSON file.

        The JSON must consist of client_id, client_secret and refresh_token fields. Refresh
        token files are typically created and managed by the gcloud SDK. To instantiate
        a credential from a refresh token file, either specify the file path or a dict
        representing the parsed contents of the file.

        Args:
          refresh_token: Path to a refresh token file or a dict representing the contents of a
              refresh token file.

        Raises:
          IOError: If the specified file doesn't exist or cannot be read.
          ValueError: If the refresh token configuration is invalid.
        """
        super().__init__()
        if _is_file_path(refresh_token):
            with open(refresh_token, encoding='utf-8') as json_file:
                json_data = json.load(json_file)
        elif isinstance(refresh_token, dict):
            json_data = refresh_token
        else:
            raise ValueError(
                f'Invalid refresh token argument: "{refresh_token}". Refresh token argument must '
                'be a file path, or a dict containing the parsed file contents.')

        if json_data.get('type') != self._CREDENTIAL_TYPE:
            raise ValueError(
                'Invalid refresh token configuration. JSON must contain a '
                f'"type" field set to "{self._CREDENTIAL_TYPE}".')
        self._g_credential = credentials.Credentials.from_authorized_user_info(json_data, _scopes)

    @property
    def client_id(self) -> Optional[str]:
        return self._g_credential.client_id

    @property
    def client_secret(self) -> Optional[str]:
        return self._g_credential.client_secret

    @property
    def refresh_token(self) -> Optional[str]:
        return self._g_credential.refresh_token

    def get_credential(self) -> GoogleAuthCredentials:
        """Returns the underlying Google credential.

        Returns:
          google.auth.credentials.Credentials: A Google Auth credential instance."""
        return self._g_credential


def _is_file_path(path: Any) -> TypeGuard['StrPath']:
    try:
        pathlib.Path(path)
        return True
    except TypeError:
        return False
