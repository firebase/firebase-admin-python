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

"""Tests for firebase_admin.App."""
import os

import pytest

import firebase_admin
from firebase_admin import credentials
from firebase_admin import _utils
from tests import testutils


CREDENTIAL = credentials.Certificate(
    testutils.resource_filename('service_account.json'))
GCLOUD_PROJECT = 'GCLOUD_PROJECT'

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


class AppService(object):
    def __init__(self, app):
        self._app = app


@pytest.fixture(params=[Cert(), RefreshToken(), ExplicitAppDefault(), ImplicitAppDefault()],
                ids=['cert', 'refreshtoken', 'explicit-appdefault', 'implicit-appdefault'])
def app_credential(request):
    provider = request.param
    provider.init()
    yield provider.get()
    provider.cleanup()

@pytest.fixture(params=[None, 'myApp'], ids=['DefaultApp', 'CustomApp'])
def init_app(request):
    if request.param:
        return firebase_admin.initialize_app(CREDENTIAL, name=request.param)
    else:
        return firebase_admin.initialize_app(CREDENTIAL)


class TestFirebaseApp(object):
    """Test cases for App initialization and life cycle."""

    invalid_credentials = ['', 'foo', 0, 1, dict(), list(), tuple(), True, False]
    invalid_options = ['', 0, 1, list(), tuple(), True, False]
    invalid_names = [None, '', 0, 1, dict(), list(), tuple(), True, False]
    invalid_apps = [
        None, '', 0, 1, dict(), list(), tuple(), True, False,
        firebase_admin.App('uninitialized', CREDENTIAL, {})
    ]

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

    def test_project_id_from_options(self, app_credential):
        app = firebase_admin.initialize_app(
            app_credential, options={'projectId': 'test-project'}, name='myApp')
        assert app.project_id == 'test-project'

    def test_project_id_from_credentials(self):
        app = firebase_admin.initialize_app(CREDENTIAL, name='myApp')
        assert app.project_id == 'mock-project-id'

    def test_project_id_from_environment(self):
        project_id = os.environ.get(GCLOUD_PROJECT)
        os.environ[GCLOUD_PROJECT] = 'env-project'
        try:
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='myApp')
            assert app.project_id == 'env-project'
        finally:
            if project_id:
                os.environ[GCLOUD_PROJECT] = project_id
            else:
                del os.environ[GCLOUD_PROJECT]

    def test_no_project_id(self):
        project_id = os.environ.get(GCLOUD_PROJECT)
        if project_id:
            del os.environ[GCLOUD_PROJECT]
        try:
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='myApp')
            assert app.project_id is None
        finally:
            if project_id:
                os.environ[GCLOUD_PROJECT] = project_id

    def test_app_get(self, init_app):
        assert init_app is firebase_admin.get_app(init_app.name)

    @pytest.mark.parametrize('args', [(), ('myApp',)],
                             ids=['DefaultApp', 'CustomApp'])
    def test_non_existing_app_get(self, args):
        with pytest.raises(ValueError):
            firebase_admin.get_app(*args)

    @pytest.mark.parametrize('name', invalid_names)
    def test_app_get_with_invalid_name(self, name):
        with pytest.raises(ValueError):
            firebase_admin.get_app(name)

    @pytest.mark.parametrize('app', invalid_apps)
    def test_invalid_app_delete(self, app):
        with pytest.raises(ValueError):
            firebase_admin.delete_app(app)

    def test_app_delete(self, init_app):
        assert firebase_admin.get_app(init_app.name) is init_app
        firebase_admin.delete_app(init_app)
        with pytest.raises(ValueError):
            firebase_admin.get_app(init_app.name)
        with pytest.raises(ValueError):
            firebase_admin.delete_app(init_app)

    def test_app_services(self, init_app):
        service = _utils.get_app_service(init_app, 'test.service', AppService)
        assert isinstance(service, AppService)
        service2 = _utils.get_app_service(init_app, 'test.service', AppService)
        assert service is service2
        firebase_admin.delete_app(init_app)
        with pytest.raises(ValueError):
            _utils.get_app_service(init_app, 'test.service', AppService)

    @pytest.mark.parametrize('arg', [0, 1, True, False, 'str', list(), dict(), tuple()])
    def test_app_services_invalid_arg(self, arg):
        with pytest.raises(ValueError):
            _utils.get_app_service(arg, 'test.service', AppService)

    def test_app_services_invalid_app(self, init_app):
        app = firebase_admin.App(init_app.name, init_app.credential, {})
        with pytest.raises(ValueError):
            _utils.get_app_service(app, 'test.service', AppService)
