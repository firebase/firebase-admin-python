"""Tests for firebase.App."""
import pytest

import firebase_admin
from firebase_admin import credentials
from tests import testutils


CREDENTIAL = credentials.Certificate(
    testutils.resource_filename('service_account.json'))


class TestFirebaseApp(object):
    """Test cases for App initialization and life cycle."""

    invalid_credentials = [None, '', 'foo', 0, 1, dict(), list(), tuple(), True, False]
    invalid_options = ['', 0, 1, list(), tuple(), True, False]
    invalid_names = [None, '', 0, 1, dict(), list(), tuple(), True, False]

    def teardown_method(self):
        testutils.cleanup_apps()

    def test_default_app_init(self):
        app = firebase_admin.initialize_app(CREDENTIAL)
        assert firebase_admin._DEFAULT_APP_NAME == app.name
        assert CREDENTIAL is app.credential
        with pytest.raises(ValueError):
            firebase_admin.initialize_app(CREDENTIAL)

    def test_non_default_app_init(self):
        app = firebase_admin.initialize_app(CREDENTIAL, name='myApp')
        assert app.name == 'myApp'
        assert CREDENTIAL is app.credential
        with pytest.raises(ValueError):
            firebase_admin.initialize_app(CREDENTIAL, name='myApp')

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
