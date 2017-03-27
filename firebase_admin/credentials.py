"""Firebase credentials module."""
import json

from oauth2client import client
from oauth2client import crypt


class Base(object):
    """Provides OAuth2 access tokens for accessing Firebase services."""

    def get_access_token(self):
        """Fetches a Google OAuth2 access token using this credential instance.

        Returns:
          An oauth2client.client.AccessTokenInfo instance
        """
        raise NotImplementedError

    def get_credential(self):
        """Returns the credential instance used for authentication."""
        raise NotImplementedError


class Certificate(Base):
    """A credential initialized from a JSON certificate keyfile."""

    def __init__(self, file_path):
        """Initializes a credential from a certificate file.

        Parses the specified certificate file (service account file), and
        creates a credential instance from it.

        Args:
          file_path: Path to a service account certificate file.

        Raises:
          IOError: If the specified file doesn't exist or cannot be read.
          ValueError: If an error occurs while parsing the file content.
        """
        super(Certificate, self).__init__()
        # TODO(hkj): Clean this up once we are able to take a dependency
        # TODO(hkj): on latest oauth2client.
        with open(file_path) as json_keyfile:
            json_data = json.load(json_keyfile)
        self._project_id = json_data.get('project_id')
        try:
            self._signer = crypt.Signer.from_string(
                json_data.get('private_key'))
        except Exception as error:
            err_type, err_value, err_traceback = sys.exc_info()
            err_message = 'Failed to parse the private key string: {0}'.format(
                error)
            raise ValueError, (err_message, err_type, err_value), err_traceback
        self._service_account_email = json_data.get('client_email')
        self._g_credential = client.GoogleCredentials.from_stream(file_path)

    @property
    def project_id(self):
        return self._project_id

    @property
    def signer(self):
        return self._signer

    @property
    def service_account_email(self):
        return self._service_account_email

    def get_access_token(self):
        self._g_credential.refresh(httplib2.Http())
        return self._g_credential.get_access_token()

    def get_credential(self):
        return self._g_credential
