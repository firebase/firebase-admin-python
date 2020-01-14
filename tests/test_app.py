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
from collections import namedtuple
import os

import pytest

import firebase_admin
from firebase_admin import credentials
from firebase_admin import _utils
from tests import testutils

CREDENTIAL = credentials.Certificate(
    testutils.resource_filename('service_account.json'))
CONFIG_JSON = firebase_admin._FIREBASE_CONFIG_ENV_VAR

# This fixture will ignore the environment variable pointing to the default
# configuration for the duration of the tests.

class CredentialProvider:
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


class AppService:
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

    return firebase_admin.initialize_app(CREDENTIAL)

@pytest.fixture(scope="function")
def env_test_case(request):
    config_old = set_config_env(request.param.config_json)
    yield request.param
    revert_config_env(config_old)


EnvOptionsTestCase = namedtuple('EnvOptionsTestCase',
                                'name, config_json, init_options, want_options')
env_options_test_cases = [
    EnvOptionsTestCase(name='Environment var not set, initialized with an empty options dict',
                       config_json=None,
                       init_options={},
                       want_options={}),
    EnvOptionsTestCase(name='Environment var empty, initialized with an empty options dict',
                       config_json='',
                       init_options={},
                       want_options={}),
    EnvOptionsTestCase(name='Environment var not set, initialized with no options dict',
                       config_json=None,
                       init_options=None,
                       want_options={}),
    EnvOptionsTestCase(name='Environment empty, initialized with no options dict',
                       config_json='',
                       init_options=None,
                       want_options={}),
    EnvOptionsTestCase(name='Environment var not set, initialized with options dict',
                       config_json=None,
                       init_options={'storageBucket': 'bucket1'},
                       want_options={'storageBucket': 'bucket1'}),
    EnvOptionsTestCase(name='Environment var set to file but ignored, initialized with options',
                       config_json='firebase_config.json',
                       init_options={'storageBucket': 'bucket1'},
                       want_options={'storageBucket': 'bucket1'}),
    EnvOptionsTestCase(name='Environment var set to json but ignored, initialized with options',
                       config_json='{"storageBucket": "hipster-chat.appspot.mock"}',
                       init_options={'storageBucket': 'bucket1'},
                       want_options={'storageBucket': 'bucket1'}),
    EnvOptionsTestCase(name='Environment var set to file, initialized with no options dict',
                       config_json='firebase_config.json',
                       init_options=None,
                       want_options={'databaseAuthVariableOverride': {'some_key': 'some_val'},
                                     'databaseURL': 'https://hipster-chat.firebaseio.mock',
                                     'projectId': 'hipster-chat-mock',
                                     'storageBucket': 'hipster-chat.appspot.mock'}),
    EnvOptionsTestCase(name='Environment var set to json string, initialized with no options dict',
                       config_json='{"databaseAuthVariableOverride": {"some_key": "some_val"}, ' +
                       '"databaseURL": "https://hipster-chat.firebaseio.mock", ' +
                       '"projectId": "hipster-chat-mock",' +
                       '"storageBucket": "hipster-chat.appspot.mock"}',
                       init_options=None,
                       want_options={'databaseAuthVariableOverride': {'some_key': 'some_val'},
                                     'databaseURL': 'https://hipster-chat.firebaseio.mock',
                                     'projectId': 'hipster-chat-mock',
                                     'storageBucket': 'hipster-chat.appspot.mock'}),
    EnvOptionsTestCase(name='Invalid key in json file is ignored, the rest of the values are used',
                       config_json='firebase_config_invalid_key.json',
                       init_options=None,
                       want_options={'projectId': 'hipster-chat-mock'}),
    EnvOptionsTestCase(name='Invalid key in json file is ignored, the rest of the values are used',
                       config_json='{"databaseUrrrrL": "https://hipster-chat.firebaseio.mock",' +
                       '"projectId": "hipster-chat-mock"}',
                       init_options=None,
                       want_options={'projectId': 'hipster-chat-mock'}),
    EnvOptionsTestCase(name='Environment var set to file but ignored, init empty options dict',
                       config_json='firebase_config.json',
                       init_options={},
                       want_options={}),
    EnvOptionsTestCase(name='Environment var set to string but ignored, init empty options dict',
                       config_json='{"projectId": "hipster-chat-mock"}',
                       init_options={},
                       want_options={}),
    EnvOptionsTestCase(name='Environment variable set to json file with some options set',
                       config_json='firebase_config_partial.json',
                       init_options=None,
                       want_options={'databaseURL': 'https://hipster-chat.firebaseio.mock',
                                     'projectId': 'hipster-chat-mock'}),
    EnvOptionsTestCase(name='Environment variable set to json string with some options set',
                       config_json='{"databaseURL": "https://hipster-chat.firebaseio.mock",' +
                       '"projectId": "hipster-chat-mock"}',
                       init_options=None,
                       want_options={'databaseURL': 'https://hipster-chat.firebaseio.mock',
                                     'projectId': 'hipster-chat-mock'}),
    EnvOptionsTestCase(name='Environment var set to json file but ignored, init with options dict',
                       config_json='firebase_config_partial.json',
                       init_options={'projectId': 'pid1-mock',
                                     'storageBucket': 'sb1-mock'},
                       want_options={'projectId': 'pid1-mock',
                                     'storageBucket': 'sb1-mock'}),
    EnvOptionsTestCase(name='Environment var set to file but ignored, init with full options dict',
                       config_json='firebase_config.json',
                       init_options={'databaseAuthVariableOverride': 'davy1-mock',
                                     'databaseURL': 'https://db1-mock',
                                     'projectId': 'pid1-mock',
                                     'storageBucket': 'sb1-.mock'},
                       want_options={'databaseAuthVariableOverride': 'davy1-mock',
                                     'databaseURL': 'https://db1-mock',
                                     'projectId': 'pid1-mock',
                                     'storageBucket': 'sb1-.mock'})]

def set_config_env(config_json):
    config_old = os.environ.get(CONFIG_JSON)
    if config_json is not None:
        if not config_json or config_json.startswith('{'):
            os.environ[CONFIG_JSON] = config_json
        else:
            os.environ[CONFIG_JSON] = testutils.resource_filename(
                config_json)
    elif  os.environ.get(CONFIG_JSON) is not None:
        del os.environ[CONFIG_JSON]
    return config_old


def revert_config_env(config_old):
    if config_old is not None:
        os.environ[CONFIG_JSON] = config_old
    elif os.environ.get(CONFIG_JSON) is not None:
        del os.environ[CONFIG_JSON]

class TestFirebaseApp:
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


    @pytest.mark.parametrize('bad_file_name', ['firebase_config_empty.json',
                                               'firebase_config_invalid.json',
                                               'no_such_file'])
    def test_app_init_with_invalid_config_file(self, bad_file_name):
        config_old = set_config_env(bad_file_name)
        with pytest.raises(ValueError):
            firebase_admin.initialize_app(CREDENTIAL)
        revert_config_env(config_old)

    def test_app_init_with_invalid_config_string(self):
        config_old = set_config_env('{,,')
        with pytest.raises(ValueError):
            firebase_admin.initialize_app(CREDENTIAL)
        revert_config_env(config_old)


    @pytest.mark.parametrize('env_test_case', env_options_test_cases,
                             ids=[x.name for x in env_options_test_cases],
                             indirect=['env_test_case'])
    def test_app_init_with_default_config(self, env_test_case):
        app = firebase_admin.initialize_app(CREDENTIAL, options=env_test_case.init_options)
        assert app.options._options == env_test_case.want_options

    def test_project_id_from_options(self, app_credential):
        app = firebase_admin.initialize_app(
            app_credential, options={'projectId': 'test-project'}, name='myApp')
        assert app.project_id == 'test-project'

    def test_project_id_from_credentials(self):
        app = firebase_admin.initialize_app(CREDENTIAL, name='myApp')
        assert app.project_id == 'mock-project-id'

    def test_project_id_from_environment(self):
        variables = ['GOOGLE_CLOUD_PROJECT', 'GCLOUD_PROJECT']
        for idx, var in enumerate(variables):
            old_project_id = os.environ.get(var)
            new_project_id = 'env-project-{0}'.format(idx)
            os.environ[var] = new_project_id
            try:
                app = firebase_admin.initialize_app(
                    testutils.MockCredential(), name='myApp{0}'.format(var))
                assert app.project_id == new_project_id
            finally:
                if old_project_id:
                    os.environ[var] = old_project_id
                else:
                    del os.environ[var]

    def test_no_project_id(self):
        def evaluate():
            app = firebase_admin.initialize_app(testutils.MockCredential(), name='myApp')
            assert app.project_id is None
        testutils.run_without_project_id(evaluate)

    def test_non_string_project_id(self):
        options = {'projectId': {'key': 'not a string'}}
        with pytest.raises(ValueError):
            firebase_admin.initialize_app(CREDENTIAL, options=options)

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
