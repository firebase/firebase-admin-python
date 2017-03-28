"""Tests for firebase_admin.App."""
import os

import pytest

import firebase_admin
from firebase_admin import credentials
from tests import testutils


CREDENTIAL = credentials.Certificate(
    testutils.resource_filename('service_account.json'))

class CredentialProvider(object):
    def init(self):
        pass

    def get(self):
        pass

    def cleanup(self):
        pass


class Cert(CredentialProvider):
    def get(self):
        return CREDENTIAL


class RefreshToken(CredentialProvider):
    def get(self):
        return credentials.RefreshToken(testutils.resource_filename('refresh_token.json'))


class ExplicitAppDefault(CredentialProvider):
    VAR_NAME = 'GOOGLE_APPLICATION_CREDENTIALS'

    def init(self):
        self.file_path = os.environ.get(self.VAR_NAME)
        os.environ[self.VAR_NAME] = testutils.resource_filename('service_account.json')

    def get(self):
        return credentials.ApplicationDefault()

    def cleanup(self):
        if self.file_path:
            os.environ[self.VAR_NAME] = self.file_path
        else:
            del os.environ[self.VAR_NAME]


class ImplicitAppDefault(ExplicitAppDefault):
    def get(self):
        return None


@pytest.fixture(params=[Cert(), RefreshToken(), ExplicitAppDefault(), ImplicitAppDefault()],
                ids=['cert', 'refreshtoken', 'explicit-appdefault', 'implicit-appdefault'])
def app_credential(request):
    provider = request.param
    provider.init()
    yield provider.get()
    provider.cleanup()


class TestFirebaseApp(object):
    """Test cases for App initialization and life cycle."""

    invalid_credentials = ['', 'foo', 0, 1, dict(), list(), tuple(), True, False]
    invalid_options = ['', 0, 1, list(), tuple(), True, False]
    invalid_names = [None, '', 0, 1, dict(), list(), tuple(), True, False]

    def teardown_method(self):
        testutils.cleanup_apps()

    def test_default_app_init(self, app_credential):
        app = firebase_admin.initialize_app(app_credential)
        assert firebase_admin._DEFAULT_APP_NAME == app.name
        if app_credential:
            assert app_credential is app.credential
        else:
            assert isinstance(app.credential, credentials.ApplicationDefault)
        with pytest.raises(ValueError):
            firebase_admin.initialize_app(app_credential)

    def test_non_default_app_init(self, app_credential):
        app = firebase_admin.initialize_app(app_credential, name='myApp')
        assert app.name == 'myApp'
        if app_credential:
            assert app_credential is app.credential
        else:
            assert isinstance(app.credential, credentials.ApplicationDefault)
        with pytest.raises(ValueError):
            firebase_admin.initialize_app(app_credential, name='myApp')

    @pytest.mark.parametrize('cred', invalid_credentials)
    def test_app_init_with_invalid_credential(self, cred):
        with pytest.raises(ValueError):
            firebase_admin.initialize_app(cred)

    @pytest.mark.parametrize('options', invalid_options)
    def test_app_init_with_invalid_options(self, options):
        with pytest.raises(ValueError):
            firebase_admin.initialize_app(CREDENTIAL, options=options)

    @pytest.mark.parametrize('name', invalid_names)
    def test_app_init_with_invalid_name(self, name):
        with pytest.raises(ValueError):
            firebase_admin.initialize_app(CREDENTIAL, name=name)

    def test_default_app_get(self):
        app = firebase_admin.initialize_app(CREDENTIAL)
        assert app is firebase_admin.get_app()

    def test_non_default_app_get(self):
        app = firebase_admin.initialize_app(CREDENTIAL, name='myApp')
        assert app is firebase_admin.get_app('myApp')

    @pytest.mark.parametrize('args', [(), ('myApp',)],
                             ids=['DefaultApp', 'CustomApp'])
    def test_non_existing_app_get(self, args):
        with pytest.raises(ValueError):
            firebase_admin.get_app(*args)

    @pytest.mark.parametrize('name', invalid_names)
    def test_app_get_with_invalid_name(self, name):
        with pytest.raises(ValueError):
            firebase_admin.get_app(name)
