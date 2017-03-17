"""Tests for firebase.App."""
import unittest

import firebase
from firebase import auth
from tests import testutils


class FirebaseAppTest(unittest.TestCase):
    """Test cases for App initialization and life cycle."""

    SERVICE_ACCOUNT_PATH = 'service_account.json'
    CREDENTIAL = auth.CertificateCredential(
        testutils.resource_filename(SERVICE_ACCOUNT_PATH))
    OPTIONS = {'credential': CREDENTIAL}

    def tearDown(self):
        testutils.cleanup_apps()

    def test_default_app_init(self):
        app = firebase.initialize_app(self.OPTIONS)
        self.assertEquals(firebase._DEFAULT_APP_NAME, app.name)
        self.assertIs(self.CREDENTIAL, app.options.credential)
        with self.assertRaises(ValueError):
            firebase.initialize_app(self.OPTIONS)

    def test_non_default_app_init(self):
        app = firebase.initialize_app(self.OPTIONS, 'myApp')
        self.assertEquals('myApp', app.name)
        self.assertIs(self.CREDENTIAL, app.options.credential)
        with self.assertRaises(ValueError):
            firebase.initialize_app(self.OPTIONS, 'myApp')

    def test_app_init_with_empty_options(self):
        with self.assertRaises(ValueError):
            firebase.initialize_app({})

    def test_app_init_with_no_credential(self):
        options = {'key': 'value'}
        with self.assertRaises(ValueError):
            firebase.initialize_app(options)

    def test_app_init_with_invalid_options(self):
        for options in [None, 0, 1, 'foo', list(), tuple(), True, False]:
            with self.assertRaises(ValueError):
                firebase.initialize_app(options)

    def test_app_init_with_invalid_name(self):
        for name in [None, '', 0, 1, dict(), list(), tuple(), True, False]:
            with self.assertRaises(ValueError):
                firebase.initialize_app(self.OPTIONS, name)

    def test_default_app_get(self):
        app = firebase.initialize_app(self.OPTIONS)
        self.assertIs(app, firebase.get_app())

    def test_non_default_app_get(self):
        app = firebase.initialize_app(self.OPTIONS, 'myApp')
        self.assertIs(app, firebase.get_app('myApp'))

    def test_non_existing_default_app_get(self):
        with self.assertRaises(ValueError):
            self.assertIsNone(firebase.get_app())

    def test_non_existing_app_get(self):
        with self.assertRaises(ValueError):
            self.assertIsNone(firebase.get_app('myApp'))

    def test_app_get_with_invalid_name(self):
        for name in [None, '', 0, 1, dict(), list(), tuple(), True, False]:
            with self.assertRaises(ValueError):
                firebase.initialize_app(self.OPTIONS, name)
