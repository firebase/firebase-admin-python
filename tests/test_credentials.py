"""Tests for firebase_admin.credentials module."""
import json
import os

from firebase_admin import credentials
from oauth2client import client
from oauth2client import crypt
import pytest

from tests import testutils


class TestCertificate(object):

    def test_init_from_file(self):
        credential = credentials.Certificate(
            testutils.resource_filename('service_account.json'))
        assert credential.project_id == 'mock-project-id'
        assert credential.service_account_email == 'mock-email@mock-project.iam.gserviceaccount.com'
        assert isinstance(credential.signer, crypt.Signer)

        g_credential = credential.get_credential()
        assert isinstance(g_credential, client.GoogleCredentials)
        assert g_credential.access_token is None

        # The HTTP client should not be used or referenced.
        credentials._http = 'unused'
        access_token = credential.get_access_token()
        assert isinstance(access_token.access_token, basestring)
        assert isinstance(access_token.expires_in, int)

    def test_init_from_nonexisting_file(self):
        with pytest.raises(IOError):
            credentials.Certificate(
                testutils.resource_filename('non_existing.json'))

    def test_init_from_invalid_file(self):
        with pytest.raises(ValueError):
            credentials.Certificate(
                testutils.resource_filename('refresh_token.json'))


@pytest.fixture
def app_default(request):
    file_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = request.param
    yield
    if file_path:
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = file_path


class TestApplicationDefault(object):

    @pytest.mark.parametrize('app_default', [testutils.resource_filename('service_account.json')],
                             indirect=True)
    def test_init(self, app_default): # pylint: disable=unused-argument
        credential = credentials.ApplicationDefault()
        g_credential = credential.get_credential()
        assert isinstance(g_credential, client.GoogleCredentials)
        assert g_credential.access_token is None

        # The HTTP client should not be used.
        credentials._http = 'unused'
        access_token = credential.get_access_token()
        assert isinstance(access_token.access_token, basestring)
        assert isinstance(access_token.expires_in, int)

    @pytest.mark.parametrize('app_default', [testutils.resource_filename('non_existing.json')],
                             indirect=True)
    def test_nonexisting_path(self, app_default): # pylint: disable=unused-argument
        with pytest.raises(client.ApplicationDefaultCredentialsError):
            credentials.ApplicationDefault()


class TestRefreshToken(object):

    def test_init_from_file(self):
        credential = credentials.RefreshToken(
            testutils.resource_filename('refresh_token.json'))

        g_credential = credential.get_credential()
        assert isinstance(g_credential, client.GoogleCredentials)
        assert g_credential.access_token is None

        mock_response = {
            'access_token': 'mock_access_token',
            'expires_in': 1234
        }
        credentials._http = testutils.HttpMock(200, json.dumps(mock_response))
        access_token = credential.get_access_token()
        assert access_token.access_token == 'mock_access_token'
        assert access_token.expires_in <= 1234

    def test_init_from_nonexisting_file(self):
        with pytest.raises(IOError):
            credentials.RefreshToken(
                testutils.resource_filename('non_existing.json'))

    def test_init_from_invalid_file(self):
        with pytest.raises(ValueError):
            credentials.RefreshToken(
                testutils.resource_filename('service_account.json'))
