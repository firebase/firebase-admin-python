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

"""Tests for firebase_admin.credentials module."""
import datetime
import json
import os
import pathlib

import google.auth
from google.auth import crypt
from google.auth import exceptions
from google.oauth2 import credentials as gcredentials
from google.oauth2 import service_account
import pytest

from firebase_admin import credentials
from tests import testutils


def check_scopes(g_credential):
    assert isinstance(g_credential, google.auth.credentials.ReadOnlyScoped)
    assert sorted(credentials._scopes) == sorted(g_credential.scopes)


class TestCertificate:

    invalid_certs = {
        'NonExistingFile': ('non_existing.json', IOError),
        'RefreskToken': ('refresh_token.json', ValueError),
        'MalformedPrivateKey': ('malformed_key.json', ValueError),
        'MissingClientId': ('no_client_email_service_account.json', ValueError),
    }

    def test_init_from_file(self):
        credential = credentials.Certificate(
            testutils.resource_filename('service_account.json'))
        self._verify_credential(credential)

    def test_init_from_path_like(self):
        path = pathlib.Path(testutils.resource_filename('service_account.json'))
        credential = credentials.Certificate(path)
        self._verify_credential(credential)


    def test_init_from_dict(self):
        parsed_json = json.loads(testutils.resource('service_account.json'))
        credential = credentials.Certificate(parsed_json)
        self._verify_credential(credential)

    @pytest.mark.parametrize('file_name,error', invalid_certs.values(), ids=list(invalid_certs))
    def test_init_from_invalid_certificate(self, file_name, error):
        with pytest.raises(error):
            credentials.Certificate(testutils.resource_filename(file_name))

    @pytest.mark.parametrize('arg', [None, 0, 1, True, False, list(), tuple(), dict()])
    def test_invalid_args(self, arg):
        with pytest.raises(ValueError):
            credentials.Certificate(arg)

    def _verify_credential(self, credential):
        assert credential.project_id == 'mock-project-id'
        assert credential.service_account_email == 'mock-email@mock-project.iam.gserviceaccount.com'
        assert isinstance(credential.signer, crypt.Signer)

        g_credential = credential.get_credential()
        assert isinstance(g_credential, service_account.Credentials)
        assert g_credential.token is None
        check_scopes(g_credential)

        mock_response = {'access_token': 'mock_access_token', 'expires_in': 3600}
        credentials._request = testutils.MockRequest(200, json.dumps(mock_response))
        access_token = credential.get_access_token()
        assert access_token.access_token == 'mock_access_token'
        assert isinstance(access_token.expiry, datetime.datetime)


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


class TestApplicationDefault:

    @pytest.mark.parametrize('app_default', [testutils.resource_filename('service_account.json')],
                             indirect=True)
    def test_init(self, app_default):
        del app_default
        credential = credentials.ApplicationDefault()
        assert credential.project_id == 'mock-project-id'

        g_credential = credential.get_credential()
        assert isinstance(g_credential, google.auth.credentials.Credentials)
        assert g_credential.token is None
        check_scopes(g_credential)

        mock_response = {'access_token': 'mock_access_token', 'expires_in': 3600}
        credentials._request = testutils.MockRequest(200, json.dumps(mock_response))
        access_token = credential.get_access_token()
        assert access_token.access_token == 'mock_access_token'
        assert isinstance(access_token.expiry, datetime.datetime)

    @pytest.mark.parametrize('app_default', [testutils.resource_filename('non_existing.json')],
                             indirect=True)
    def test_nonexisting_path(self, app_default):
        del app_default
        # This does not yet throw because the credentials are lazily loaded.
        creds = credentials.ApplicationDefault()

        with pytest.raises(exceptions.DefaultCredentialsError):
            creds.get_credential()  # This now throws.


class TestRefreshToken:

    def test_init_from_file(self):
        credential = credentials.RefreshToken(
            testutils.resource_filename('refresh_token.json'))
        self._verify_credential(credential)

    def test_init_from_path_like(self):
        path = pathlib.Path(testutils.resource_filename('refresh_token.json'))
        credential = credentials.RefreshToken(path)
        self._verify_credential(credential)

    def test_init_from_dict(self):
        parsed_json = json.loads(testutils.resource('refresh_token.json'))
        credential = credentials.RefreshToken(parsed_json)
        self._verify_credential(credential)

    def test_init_from_nonexisting_file(self):
        with pytest.raises(IOError):
            credentials.RefreshToken(
                testutils.resource_filename('non_existing.json'))

    def test_init_from_invalid_file(self):
        with pytest.raises(ValueError):
            credentials.RefreshToken(
                testutils.resource_filename('service_account.json'))

    @pytest.mark.parametrize('arg', [None, 0, 1, True, False, list(), tuple(), dict()])
    def test_invalid_args(self, arg):
        with pytest.raises(ValueError):
            credentials.RefreshToken(arg)

    @pytest.mark.parametrize('key', ['client_id', 'client_secret', 'refresh_token'])
    def test_required_field(self, key):
        data = {
            'client_id': 'value',
            'client_secret': 'value',
            'refresh_token': 'value',
            'type': 'authorized_user'
        }
        del data[key]
        with pytest.raises(ValueError):
            credentials.RefreshToken(data)

    def _verify_credential(self, credential):
        assert credential.client_id == 'mock.apps.googleusercontent.com'
        assert credential.client_secret == 'mock-secret'
        assert credential.refresh_token == 'mock-refresh-token'

        g_credential = credential.get_credential()
        assert isinstance(g_credential, gcredentials.Credentials)
        assert g_credential.token is None
        check_scopes(g_credential)

        mock_response = {
            'access_token': 'mock_access_token',
            'expires_in': 3600
        }
        credentials._request = testutils.MockRequest(200, json.dumps(mock_response))
        access_token = credential.get_access_token()
        assert access_token.access_token == 'mock_access_token'
        assert isinstance(access_token.expiry, datetime.datetime)
