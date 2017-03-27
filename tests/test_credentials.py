"""Tests for firebase_admin.credentials module."""
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

        # The HTTP client should not be used.
        credential._http = None
        access_token = credential.get_access_token()
        assert isinstance(access_token.access_token, basestring)
        assert isinstance(access_token.expires_in, int)


    def test_init_from_nonexisting_file(self):
        with pytest.raises(IOError):
            credentials.Certificate(
                testutils.resource_filename('non_existing.json'))
