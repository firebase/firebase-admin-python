"""Firebase credentials module."""
import collections
import json

import google.auth
from google.auth.transport import requests
from google.oauth2 import credentials
from google.oauth2 import service_account


_request = requests.Request()


AccessTokenInfo = collections.namedtuple(
    'AccessTokenInfo', ['access_token', 'expiry'])


class Base(object):
    """Provides OAuth2 access tokens for accessing Firebase services."""

    def get_access_token(self):
        """Fetches a Google OAuth2 access token using this credential instance."""
        raise NotImplementedError

    def get_credential(self):
        """Returns the credential instance used for authentication."""
        raise NotImplementedError


class Certificate(Base):
    """A credential initialized from a JSON certificate keyfile."""

    _CREDENTIAL_TYPE = 'service_account'

    def __init__(self, file_path):
        """Initializes a credential from a certificate file.

        Parses the specified certificate file (service account file), and
        creates a credential instance from it.

        Args:
          file_path: Path to a service account certificate file.

        Raises:
          IOError: If the specified file doesn't exist or cannot be read.
          ValueError: If the certificate file is invalid.
        """
        super(Certificate, self).__init__()
        with open(file_path) as json_keyfile:
            json_data = json.load(json_keyfile)
        if json_data.get('type') != self._CREDENTIAL_TYPE:
            raise ValueError('Invalid certificate file. File must contain a '
                             '"type" field set to "{0}".'.format(self._CREDENTIAL_TYPE))
        self._project_id = json_data.get('project_id')
        self._g_credential = service_account.Credentials.from_service_account_info(json_data)

    @property
    def project_id(self):
        return self._project_id

    @property
    def signer(self):
        return self._g_credential.signer

    @property
    def service_account_email(self):
        return self._g_credential.service_account_email

    def get_access_token(self):
        """Fetches a Google OAuth2 access token using this certificate credential.

        Returns:
          AccessTokenInfo: An access token obtained using the credential.
        """
        self._g_credential.refresh(_request)
        return AccessTokenInfo(self._g_credential.token, self._g_credential.expiry)

    def get_credential(self):
        """Returns the underlying Google credential.

        Returns:
          google.auth.credentials.Credentials: A Google Auth credential instance."""
        return self._g_credential


class ApplicationDefault(Base):
    """A Google Application Default credential."""

    def __init__(self):
        """Initializes the Application Default credentials for the current environment.

        Raises:
          google.auth.exceptions.DefaultCredentialsError: If Application Default
              credentials cannot be initialized in the current environment.
        """
        super(ApplicationDefault, self).__init__()
        self._g_credential, self._project_id = google.auth.default()

    def get_access_token(self):
        """Fetches a Google OAuth2 access token using this application default credential.

        Returns:
          AccessTokenInfo: An access token obtained using the credential.
        """
        self._g_credential.refresh(_request)
        return AccessTokenInfo(self._g_credential.token, self._g_credential.expiry)

    def get_credential(self):
        """Returns the underlying Google credential.

        Returns:
          google.auth.credentials.Credentials: A Google Auth credential instance."""
        return self._g_credential

    @property
    def project_id(self):
        return self._project_id


class RefreshToken(Base):
    """A credential initialized from an existing refresh token."""

    _CREDENTIAL_TYPE = 'authorized_user'

    def __init__(self, file_path):
        """Initializes a refresh token credential from the specified JSON file.

        Args:
          file_path: File path to a refresh token JSON file.

        Raises:
          IOError: If the specified file doesn't exist or cannot be read.
          ValueError: If the refresh token file is invalid.
        """
        super(RefreshToken, self).__init__()
        with open(file_path) as json_keyfile:
            json_data = json.load(json_keyfile)
        if json_data.get('type') != self._CREDENTIAL_TYPE:
            raise ValueError('Invalid refresh token file. File must contain a '
                             '"type" field set to "{0}".'.format(self._CREDENTIAL_TYPE))
        client_id = json_data.get('client_id')
        client_secret = json_data.get('client_secret')
        refresh_token = json_data.get('refresh_token')
        self._g_credential = credentials.Credentials(
            token=None, refresh_token=refresh_token,
            token_uri='https://accounts.google.com/o/oauth2/token',
            client_id=client_id, client_secret=client_secret)

    @property
    def client_id(self):
        return self._g_credential.client_id

    @property
    def client_secret(self):
        return self._g_credential.client_secret

    @property
    def refresh_token(self):
        return self._g_credential.refresh_token

    def get_access_token(self):
        """Fetches a Google OAuth2 access token using this refresh token credential.

        Returns:
          AccessTokenInfo: An access token obtained using the credential.
        """
        self._g_credential.refresh(_request)
        return AccessTokenInfo(self._g_credential.token, self._g_credential.expiry)

    def get_credential(self):
        """Returns the underlying Google credential.

        Returns:
          google.auth.credentials.Credentials: A Google Auth credential instance."""
        return self._g_credential
