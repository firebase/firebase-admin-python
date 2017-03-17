"""Tests for firebase.App."""
import unittest

import firebase
from firebase import auth
import testutils


class FirebaseAppTest(unittest.TestCase):

  SERVICE_ACCOUNT_PATH = 'service_account.json'
  CREDENTIAL = auth.CertificateCredential(
      testutils.resource_filename(SERVICE_ACCOUNT_PATH))
  OPTIONS = {'credential': CREDENTIAL}

  def tearDown(self):
    testutils.cleanup_apps()

  def testDefaultAppInit(self):
    app = firebase.initialize_app(self.OPTIONS)
    self.assertEquals(firebase._DEFAULT_APP_NAME, app.name)
    self.assertIs(self.CREDENTIAL, app.options.credential)
    with self.assertRaises(ValueError):
      firebase.initialize_app(self.OPTIONS)

  def testNonDefaultAppInit(self):
    app = firebase.initialize_app(self.OPTIONS, 'myApp')
    self.assertEquals('myApp', app.name)
    self.assertIs(self.CREDENTIAL, app.options.credential)
    with self.assertRaises(ValueError):
      firebase.initialize_app(self.OPTIONS, 'myApp')

  def testAppInitWithEmptyOptions(self):
    with self.assertRaises(ValueError):
      firebase.initialize_app({})

  def testAppInitWithNoCredential(self):
    options = {'key': 'value'}
    with self.assertRaises(ValueError):
      firebase.initialize_app(options)

  def testAppInitWithInvalidOptions(self):
    for options in [None, 0, 1, 'foo', list(), tuple(), True, False]:
      with self.assertRaises(ValueError):
        firebase.initialize_app(options)

  def testAppInitWithInvalidName(self):
    for name in [None, '', 0, 1, dict(), list(), tuple(), True, False]:
      with self.assertRaises(ValueError):
        firebase.initialize_app(self.OPTIONS, name)

  def testDefaultAppGet(self):
    app = firebase.initialize_app(self.OPTIONS)
    self.assertIs(app, firebase.get_app())

  def testNonDefaultAppGet(self):
    app = firebase.initialize_app(self.OPTIONS, 'myApp')
    self.assertIs(app, firebase.get_app('myApp'))

  def testNonExistingDefaultAppGet(self):
    with self.assertRaises(ValueError):
      self.assertIsNone(firebase.get_app())

  def testNonExistingAppGet(self):
    with self.assertRaises(ValueError):
      self.assertIsNone(firebase.get_app('myApp'))

  def testAppGetWithInvalidName(self):
    for name in [None, '', 0, 1, dict(), list(), tuple(), True, False]:
      with self.assertRaises(ValueError):
        firebase.initialize_app(self.OPTIONS, name)

