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
import collections
import json
import six

import google.auth
from google.auth.transport import requests
from google.oauth2 import credentials
from google.oauth2 import service_account


_request = requests.Request()
_scopes = [
    'https://www.googleapis.com/auth/devstorage.read_write',
    'https://www.googleapis.com/auth/firebase',
    'https://www.googleapis.com/auth/identitytoolkit',
    'https://www.googleapis.com/auth/userinfo.email'
]

AccessTokenInfo = collections.namedtuple(
    'AccessTokenInfo', ['access_token', 'expiry'])


class Base(object):
    """Provides OAuth2 access tokens for accessing Firebase services."""

    def get_access_token(self):
        """Fetches a Google OAuth2 access token using this credential instance.

        Returns:
          AccessTokenInfo: An access token obtained using the credential.
        """
        google_cred = self.get_credential()
        google_cred.refresh(_request)
        return AccessTokenInfo(google_cred.token, google_cred.expiry)

    def get_credential(self):
        """Returns the Google credential instance used for authentication."""
        raise NotImplementedError


class Certificate(Base):
    """A credential initialized from a JSON certificate keyfile."""

    _CREDENTIAL_TYPE = 'service_account'

    def __init__(self, cert):
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
        super(Certificate, self).__init__()
        if isinstance(cert, six.string_types):
            with open(cert) as json_file:
                json_data = json.load(json_file)
        elif isinstance(cert, dict):
            json_data = cert
        else:
            raise ValueError(
                'Invalid certificate argument: "{0}". Certificate argument must be a file path, '
                'or a dict containing the parsed file contents.'.format(cert))

        if json_data.get('type') != self._CREDENTIAL_TYPE:
            raise ValueError('Invalid service account certificate. Certificate must contain a '
                             '"type" field set to "{0}".'.format(self._CREDENTIAL_TYPE))
        self._project_id = json_data.get('project_id')
        try:
            self._g_credential = service_account.Credentials.from_service_account_info(
                json_data, scopes=_scopes)
        except ValueError as error:
            raise ValueError('Failed to initialize a certificate credential. '
                             'Caused by: "{0}"'.format(error))

    @property
    def project_id(self):
        return self._project_id

    @property
    def signer(self):
        return self._g_credential.signer

    @property
    def service_account_email(self):
        return self._g_credential.service_account_email

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
        self._g_credential, self._project_id = google.auth.default(scopes=_scopes)

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

    def __init__(self, refresh_token):
        """Initializes a credential from a refresh token JSON file.

        The JSON must consist of client_id, client_secert and refresh_token fields. Refresh
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
        super(RefreshToken, self).__init__()
        if isinstance(refresh_token, six.string_types):
            with open(refresh_token) as json_file:
                json_data = json.load(json_file)
        elif isinstance(refresh_token, dict):
            json_data = refresh_token
        else:
            raise ValueError(
                'Invalid refresh token argument: "{0}". Refresh token argument must be a file '
                'path, or a dict containing the parsed file contents.'.format(refresh_token))

        if json_data.get('type') != self._CREDENTIAL_TYPE:
            raise ValueError('Invalid refresh token configuration. JSON must contain a '
                             '"type" field set to "{0}".'.format(self._CREDENTIAL_TYPE))
        try:
            client_id = json_data['client_id']
            client_secret = json_data['client_secret']
            refresh_token = json_data['refresh_token']
        except KeyError as error:
            raise ValueError('Failed to initialize a refresh token credential. '
                             'Caused by: "{0}"'.format(error))
        self._g_credential = credentials.Credentials(
            token=None, refresh_token=refresh_token,
            token_uri='https://accounts.google.com/o/oauth2/token',
            client_id=client_id, client_secret=client_secret, scopes=_scopes)

    @property
    def client_id(self):
        return self._g_credential.client_id

    @property
    def client_secret(self):
        return self._g_credential.client_secret

    @property
    def refresh_token(self):
        return self._g_credential.refresh_token

    def get_credential(self):
        """Returns the underlying Google credential.

        Returns:
          google.auth.credentials.Credentials: A Google Auth credential instance."""
        return self._g_credential
