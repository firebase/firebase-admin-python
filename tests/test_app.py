"""Tests for firebase.App."""
import pytest

import firebase
from firebase import auth
from tests import testutils


CREDENTIAL = auth.CertificateCredential(
    testutils.resource_filename('service_account.json'))
OPTIONS = {'credential': CREDENTIAL}


class TestFirebaseApp(object):
    """Test cases for App initialization and life cycle."""

    invalid_options = {
        'EmptyOptions': ({}, ValueError),
        'NoCredential': ({'k':'v'}, ValueError),
        'NoneOptions': (None, ValueError),
        'IntOptions': (1, ValueError),
        'StringOptions': ('foo', ValueError),
    }

    invalid_names = [None, '', 0, 1, dict(), list(), tuple(), True, False]

    def teardown_method(self):
        testutils.cleanup_apps()

    def test_default_app_init(self):
        app = firebase.initialize_app(OPTIONS)
        assert firebase._DEFAULT_APP_NAME == app.name
        assert CREDENTIAL is app.options.credential
        with pytest.raises(ValueError):
            firebase.initialize_app(OPTIONS)

    def test_non_default_app_init(self):
        app = firebase.initialize_app(OPTIONS, 'myApp')
        assert app.name == 'myApp'
        assert CREDENTIAL is app.options.credential
        with pytest.raises(ValueError):
            firebase.initialize_app(OPTIONS, 'myApp')

    @pytest.mark.parametrize('options,error', invalid_options.values(),
                             ids=invalid_options.keys())
    def test_app_init_with_invalid_options(self, options, error):
        with pytest.raises(error):
            firebase.initialize_app(options)

    @pytest.mark.parametrize('name', invalid_names)
    def test_app_init_with_invalid_name(self, name):
        with pytest.raises(ValueError):
            firebase.initialize_app(OPTIONS, name)

    def test_default_app_get(self):
        app = firebase.initialize_app(OPTIONS)
        assert app is firebase.get_app()

    def test_non_default_app_get(self):
        app = firebase.initialize_app(OPTIONS, 'myApp')
        assert app is firebase.get_app('myApp')

    @pytest.mark.parametrize('args', [(), ('myApp',)],
                             ids=['DefaultApp', 'CustomApp'])
    def test_non_existing_app_get(self, args):
        with pytest.raises(ValueError):
            firebase.get_app(*args)

    @pytest.mark.parametrize('name', invalid_names)
    def test_app_get_with_invalid_name(self, name):
        with pytest.raises(ValueError):
            firebase.initialize_app(OPTIONS, name)
