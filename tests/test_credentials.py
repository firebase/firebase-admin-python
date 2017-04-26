"""Tests for firebase_admin.credentials module."""
import datetime
import json
import os

import google.auth
from google.auth import crypt
from google.oauth2 import credentials as gcredentials
from google.oauth2 import service_account
from firebase_admin import credentials
import pytest

from tests import testutils


class TestCertificate(object):

    invalid_certs = {
        'NonExistingFile': ('non_existing.json', IOError),
        'RefreskToken': ('refresh_token.json', ValueError),
        'MalformedPrivateKey': ('malformed_key.json', ValueError),
        'MissingClientId': ('no_client_id_service_account.json', ValueError),
    }

    def test_init_from_file(self):
        credential = credentials.Certificate(
            testutils.resource_filename('service_account.json'))
        assert credential.project_id == 'mock-project-id'
        assert credential.service_account_email == 'mock-email@mock-project.iam.gserviceaccount.com'
        assert isinstance(credential.signer, crypt.Signer)

        g_credential = credential.get_credential()
        assert isinstance(g_credential, service_account.Credentials)
        assert g_credential.token is None

        mock_response = {'access_token': 'mock_access_token', 'expires_in': 3600}
        credentials._request = testutils.MockRequest(200, json.dumps(mock_response))
        access_token = credential.get_access_token()
        assert access_token.access_token == 'mock_access_token'
        assert isinstance(access_token.expiry, datetime.datetime)

    @pytest.mark.parametrize('file_name,error', invalid_certs.values(), ids=list(invalid_certs))
    def test_init_from_invalid_certificate(self, file_name, error):
        with pytest.raises(error):
            credentials.Certificate(testutils.resource_filename(file_name))


@pytest.fixture
def app_default(request):
    var_name = 'GOOGLE_APPLICATION_CREDENTIALS'
    file_path = os.environ.get(var_name)
    os.environ[var_name] = request.param
    yield
    if file_path:
        os.environ[var_name] = file_path
    else:
        del os.environ[var_name]


class TestApplicationDefault(object):

    @pytest.mark.parametrize('app_default', [testutils.resource_filename('service_account.json')],
                             indirect=True)
    def test_init(self, app_default): # pylint: disable=unused-argument
        credential = credentials.ApplicationDefault()
        assert credential.project_id == 'mock-project-id'

        g_credential = credential.get_credential()
        assert isinstance(g_credential, google.auth.credentials.Credentials)
        assert g_credential.token is None

        mock_response = {'access_token': 'mock_access_token', 'expires_in': 3600}
        credentials._request = testutils.MockRequest(200, json.dumps(mock_response))
        access_token = credential.get_access_token()
        assert access_token.access_token == 'mock_access_token'
        assert isinstance(access_token.expiry, datetime.datetime)

    @pytest.mark.parametrize('app_default', [testutils.resource_filename('non_existing.json')],
                             indirect=True)
    def test_nonexisting_path(self, app_default): # pylint: disable=unused-argument
        with pytest.raises(IOError):
            credentials.ApplicationDefault()


class TestRefreshToken(object):

    def test_init_from_file(self):
        credential = credentials.RefreshToken(
            testutils.resource_filename('refresh_token.json'))
        assert credential.client_id == 'mock.apps.googleusercontent.com'
        assert credential.client_secret == 'mock-secret'
        assert credential.refresh_token == 'mock-refresh-token'

        g_credential = credential.get_credential()
        assert isinstance(g_credential, gcredentials.Credentials)
        assert g_credential.token is None

        mock_response = {
            'access_token': 'mock_access_token',
            'expires_in': 3600
        }
        credentials._request = testutils.MockRequest(200, json.dumps(mock_response))
        access_token = credential.get_access_token()
        assert access_token.access_token == 'mock_access_token'
        assert isinstance(access_token.expiry, datetime.datetime)

    def test_init_from_nonexisting_file(self):
        with pytest.raises(IOError):
            credentials.RefreshToken(
                testutils.resource_filename('non_existing.json'))

    def test_init_from_invalid_file(self):
        with pytest.raises(ValueError):
            credentials.RefreshToken(
                testutils.resource_filename('service_account.json'))
