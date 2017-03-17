"""Tests for firebase.auth."""
import os
import time
import unittest

from oauth2client import client
from oauth2client import crypt

import firebase
from firebase import auth
from firebase import jwt
import testutils


class _AbstractAuthTest(unittest.TestCase):
  """Super class for auth-related tests.

  Defines constants used in auth-related tests, and provides a method for
  asserting the validity of custom tokens.
  """
  SERVICE_ACCOUNT_EMAIL = 'test-484@mg-test-1210.iam.gserviceaccount.com'
  PROJECT_ID = 'test-484'
  CLIENT_CERT_URL = ('https://www.googleapis.com/robot/v1/metadata/x509/'
                     'test-484%40mg-test-1210.iam.gserviceaccount.com')

  FIREBASE_AUDIENCE = ('https://identitytoolkit.googleapis'
                       '.com/google.identity.identitytoolkit.'
                       'v1.IdentityToolkit')
  USER = 'user1'
  ISSUER = 'test-484@mg-test-1210.iam.gserviceaccount.com'
  CLAIMS = {'one': 2, 'three': 'four'}

  CREDENTIAL = auth.CertificateCredential(
      testutils.resource_filename('service_account.json'))
  PUBLIC_CERTS = testutils.resource('public_certs.json')
  PRIVATE_KEY = testutils.resource('private_key.pem')

  def verify_custom_token(self, custom_token, verify_claims=True):
    token = client.verify_id_token(
        custom_token,
        self.FIREBASE_AUDIENCE,
        http=testutils.HttpMock(200, self.PUBLIC_CERTS),
        cert_uri=self.CLIENT_CERT_URL)
    self.assertEquals(token['uid'], self.USER)
    self.assertEquals(token['iss'], self.SERVICE_ACCOUNT_EMAIL)
    self.assertEquals(token['sub'], self.SERVICE_ACCOUNT_EMAIL)
    if verify_claims:
      self.assertEquals(token['claims']['one'], self.CLAIMS['one'])
      self.assertEquals(token['claims']['three'], self.CLAIMS['three'])

  def _merge_jwt_claims(self, defaults, overrides):
    defaults.update(overrides)
    for k, v in overrides.items():
      if v is None:
        del defaults[k]
    return defaults

  def get_id_token(self, payload_overrides=None, header_overrides=None):
    signer = crypt.Signer.from_string(self.PRIVATE_KEY)
    headers = {
        'kid': 'd98d290613ae1468f7e5f5cf604ead38ca9c8358'
    }
    payload = {
        'aud': 'mg-test-1210',
        'iss': 'https://securetoken.google.com/mg-test-1210',
        'iat': int(time.time()) - 100,
        'exp': int(time.time()) + 3600,
        'sub': '1234567890',
        'uid': self.USER,
        'admin': True,
    }
    if header_overrides:
      headers = self._merge_jwt_claims(headers, header_overrides)
    if payload_overrides:
      payload = self._merge_jwt_claims(payload, payload_overrides)
    return jwt.encode(payload, signer, headers=headers)


class TokenGeneratorTest(_AbstractAuthTest):

  APP = firebase.App('test-app', {'credential': _AbstractAuthTest.CREDENTIAL})
  TOKEN_GEN = auth._TokenGenerator(APP)

  def testCustomTokenCreation(self):
    token_string = self.TOKEN_GEN.create_custom_token(self.USER, self.CLAIMS)
    self.assertIsInstance(token_string, basestring)
    self.verify_custom_token(token_string)

  def testCustomTokenCreationWithCorrectHeader(self):
    token_string = self.TOKEN_GEN.create_custom_token(self.USER, self.CLAIMS)
    header, _ = jwt.decode(token_string)
    self.assertEquals('JWT', header.get('typ'))
    self.assertEquals('RS256', header.get('alg'))

  def testCustomTokenCreationWithoutDevClaims(self):
    token_string = self.TOKEN_GEN.create_custom_token(self.USER)
    self.verify_custom_token(token_string, False)

  def testCustomTokenCreationWithEmptyDevClaims(self):
    token_string = self.TOKEN_GEN.create_custom_token(self.USER, {})
    self.verify_custom_token(token_string, False)

  def testCustomTokenCreationWithNoUid(self):
    with self.assertRaises(ValueError):
      self.TOKEN_GEN.create_custom_token(None)

  def testCustomTokenCreationWithEmptyUid(self):
    with self.assertRaises(ValueError):
      self.TOKEN_GEN.create_custom_token('')

  def testCustomTokenCreationWithLongUid(self):
    with self.assertRaises(ValueError):
      self.TOKEN_GEN.create_custom_token('x' * 129)

  def testCustomTokenCreationWithNonStringUid(self):
    for item in [True, False, 0, 1, [], {}, {'a': 1}]:
      with self.assertRaises(ValueError):
        self.TOKEN_GEN.create_custom_token(item)

  def testCustomTokenCreationWithBadClaims(self):
    for item in [True, False, 0, 1, 'foo', [], (1, 2)]:
      with self.assertRaises(ValueError):
        self.TOKEN_GEN.create_custom_token('user1', item)

  def testCustomTokenCreationWithNonCertCredential(self):
    app = firebase.initialize_app({'credential': auth.Credential()}, 'test-app')
    token_generator = auth._TokenGenerator(app)
    with self.assertRaises(ValueError):
      token_generator.create_custom_token(self.USER)

  def testCustomTokenCreationFailsWithReservedClaim(self):
    with self.assertRaises(ValueError):
      self.TOKEN_GEN.create_custom_token(self.USER, {'sub': '1234'})

  def testCustomTokenCreationWithMalformedDeveloperClaims(self):
    with self.assertRaises(ValueError):
      self.TOKEN_GEN.create_custom_token(self.USER, 'bad_value')

  def testVerifyValidToken(self):
    id_token = self.get_id_token()
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    claims = self.TOKEN_GEN.verify_id_token(id_token)
    self.assertEquals(claims['admin'], True)
    self.assertEquals(claims['uid'], self.USER)

  def testVerifyValidTokenWithProjectIdEnvVariable(self):
    id_token = self.get_id_token()
    gcloud_project = os.environ.get(auth.GCLOUD_PROJECT_ENV_VAR)
    try:
      os.environ[auth.GCLOUD_PROJECT_ENV_VAR] = 'mg-test-1210'
      app = firebase.App('test-app', {'credential': auth.Credential()})
      token_generator = auth._TokenGenerator(app)
      auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
      claims = token_generator.verify_id_token(id_token)
      self.assertEquals(claims['admin'], True)
      self.assertEquals(claims['uid'], self.USER)
    finally:
      if gcloud_project:
        os.environ[auth.GCLOUD_PROJECT_ENV_VAR] = gcloud_project
      else:
        del os.environ[auth.GCLOUD_PROJECT_ENV_VAR]

  def testVerifyTokenWithoutProjectId(self):
    id_token = self.get_id_token()
    if os.environ.has_key(auth.GCLOUD_PROJECT_ENV_VAR):
      del os.environ[auth.GCLOUD_PROJECT_ENV_VAR]

    app = firebase.App('test-app', {'credential': auth.Credential()})
    token_generator = auth._TokenGenerator(app)
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(ValueError):
      token_generator.verify_id_token(id_token)

  def testVerifyTokenWithNoKeyId(self):
    id_token = self.get_id_token(header_overrides={'kid': None})
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyTokenWithWrongKeyId(self):
    id_token = self.get_id_token(header_overrides={'kid': 'foo'})
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(client.VerifyJwtTokenError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyTokenWithWrongAlgorithm(self):
    id_token = self.get_id_token(header_overrides={'alg': 'HS256'})
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyInvalidTokenWithCustomToken(self):
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    id_token = self.TOKEN_GEN.create_custom_token(self.USER)
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyInvalidTokenWithBadAudience(self):
    id_token = self.get_id_token({'aud': 'bad-audience'})
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyInvalidTokenWithBadIssuer(self):
    id_token = self.get_id_token({
        'iss': 'https://securetoken.google.com/wrong-issuer'
    })
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyInvalidTokenWithEmptySubject(self):
    id_token = self.get_id_token({'sub': ''})
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyInvalidTokenWithNonStringSubject(self):
    id_token = self.get_id_token({'sub': 10})
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyInvalidTokenWithLongSubject(self):
    id_token = self.get_id_token({'sub': 'a' * 129})
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyInvalidTokenWithFutureToken(self):
    id_token = self.get_id_token({'iat': int(time.time()) + 1000})
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyInvalidTokenWithExpiredToken(self):
    id_token = self.get_id_token({
        'iat': int(time.time()) - 10000,
        'exp': int(time.time()) - 3600
    })
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyTokenWithCertificateRequestFailure(self):
    id_token = self.get_id_token()
    auth._http = testutils.HttpMock(404, 'not found')
    with self.assertRaises(client.VerifyJwtTokenError):
      self.TOKEN_GEN.verify_id_token(id_token)

  def testVerifyNoneToken(self):
    with self.assertRaises(ValueError):
      self.TOKEN_GEN.verify_id_token(None)

  def testVerifyEmptyToken(self):
    with self.assertRaises(ValueError):
      self.TOKEN_GEN.verify_id_token('')

  def testVerifyNonStringToken(self):
    for item in [True, False, 0, 1, [], {}, {'a': 1}]:
      with self.assertRaises(ValueError):
        self.TOKEN_GEN.verify_id_token(item)

  def testVerifyBadFormatToken(self):
    with self.assertRaises(crypt.AppIdentityError):
      self.TOKEN_GEN.verify_id_token('foobar')

  def testMalformedDeveloperClaims(self):
    with self.assertRaises(ValueError):
      self.TOKEN_GEN.create_custom_token(self.USER, 'bad_value')


class AuthApiTest(_AbstractAuthTest):

  def setUp(self):
    super(AuthApiTest, self).setUp()
    firebase.initialize_app({'credential': self.CREDENTIAL})

  def tearDown(self):
    testutils.cleanup_apps()
    super(AuthApiTest, self).tearDown()

  def testCustomTokenCreation(self):
    token_string = auth.create_custom_token(self.USER, self.CLAIMS)
    self.assertIsInstance(token_string, basestring)
    self.verify_custom_token(token_string)

  def testCustomTokenCreationForNonDefaultApp(self):
    app = firebase.initialize_app({'credential': self.CREDENTIAL}, 'test-app')
    token_string = auth.create_custom_token(self.USER, self.CLAIMS, app)
    self.assertIsInstance(token_string, basestring)
    self.verify_custom_token(token_string)

  def testCustomTokenCreationForUninitializedApp(self):
    app = firebase.App('test-app', {'credential': self.CREDENTIAL})
    with self.assertRaises(ValueError):
      auth.create_custom_token(self.USER, self.CLAIMS, app)

  def testCustomTokenCreationForUninitializedDuplicateApp(self):
    firebase.initialize_app({'credential': self.CREDENTIAL}, 'test-app')
    app = firebase.App('test-app', {'credential': self.CREDENTIAL})
    with self.assertRaises(ValueError):
      auth.create_custom_token(self.USER, self.CLAIMS, app)

  def testCustomTokenCreationForInvalidApp(self):
    for app in ['foo', 1, 0, True, False, dict(), list(), tuple()]:
      with self.assertRaises(ValueError):
        auth.create_custom_token(self.USER, self.CLAIMS, app)

  def testVerifyIdToken(self):
    id_token = self.get_id_token()
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    claims = auth.verify_id_token(id_token)
    self.assertEquals(claims['admin'], True)
    self.assertEquals(claims['uid'], self.USER)

  def testVerifyIdTokenForNonDefaultApp(self):
    app = firebase.initialize_app({'credential': self.CREDENTIAL}, 'test-app')
    id_token = self.get_id_token()
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    claims = auth.verify_id_token(id_token, app)
    self.assertEquals(claims['admin'], True)
    self.assertEquals(claims['uid'], self.USER)

  def testVerifyIdTokenForUninitializedApp(self):
    app = firebase.App('test-app', {'credential': self.CREDENTIAL})
    id_token = self.get_id_token()
    auth._http = testutils.HttpMock(200, self.PUBLIC_CERTS)
    with self.assertRaises(ValueError):
      auth.verify_id_token(id_token, app)

  def testVerifyIdTokenForUninitializedDuplicateApp(self):
    firebase.initialize_app({'credential': self.CREDENTIAL}, 'test-app')
    app = firebase.App('test-app', {'credential': self.CREDENTIAL})
    id_token = self.get_id_token()
    with self.assertRaises(ValueError):
      auth.verify_id_token(id_token, app)

  def testVerifyIdTokenForInvalidApp(self):
    id_token = self.get_id_token()
    for app in ['foo', 1, 0, True, False, dict(), list(), tuple()]:
      with self.assertRaises(ValueError):
        auth.verify_id_token(id_token, app)

