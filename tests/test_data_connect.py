# Copyright 2026 Google Inc.
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

"""Test cases for the firebase_admin.dataconnect module."""

from unittest import mock
from dataclasses import dataclass
from google.auth import credentials as google_auth_credentials
import pytest

import firebase_admin
from firebase_admin import _utils
from firebase_admin import dataconnect
from tests import testutils

BASE_CONFIG = dataconnect.ConnectorConfig(
    service_id="starterproject",
    location="us-east4",
    connector="my_connector",
)


class TestConnectorConfig:

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_connector_config_initialization(self):
        assert BASE_CONFIG.service_id == "starterproject"
        assert BASE_CONFIG.location == "us-east4"
        assert BASE_CONFIG.connector == "my_connector"

    def test_connector_config_is_frozen(self):
        with pytest.raises(AttributeError, match="cannot assign to field 'service_id'"):
            BASE_CONFIG.service_id = "changed_id"
        with pytest.raises(AttributeError, match="cannot assign to field 'location'"):
            BASE_CONFIG.location = "us-central1"
        with pytest.raises(AttributeError, match="cannot assign to field 'connector'"):
            BASE_CONFIG.connector = "changed_connector"

    def test_connector_config_string_written(self):
        repr_str = repr(BASE_CONFIG)
        assert "service_id='starterproject'" in repr_str
        assert "location='us-east4'" in repr_str
        assert "connector='my_connector'" in repr_str

    def test_connector_config_empty_strings(self):
        with pytest.raises(ValueError, match="service_id cannot be empty"):
            dataconnect.ConnectorConfig(
                service_id="", location="us-east4", connector="my_connector"
            )

        with pytest.raises(ValueError, match="location cannot be empty"):
            dataconnect.ConnectorConfig(
                service_id="starterproject", location="", connector="my_connector"
            )

        with pytest.raises(ValueError, match="connector cannot be empty"):
            dataconnect.ConnectorConfig(
                service_id="starterproject", location="us-east4", connector=""
            )

    def test_connector_config_invalid_types(self):
        with pytest.raises(ValueError, match="service_id must be a string"):
            dataconnect.ConnectorConfig(
                service_id=None, location="us-east4", connector="my_connector"
            )
        with pytest.raises(ValueError, match="location must be a string"):
            dataconnect.ConnectorConfig(
                service_id="starterproject", location=123, connector="my_connector"
            )
        with pytest.raises(ValueError, match="connector must be a string"):
            dataconnect.ConnectorConfig(
                service_id="starterproject", location="us-east4", connector=456
            )


class TestDataConnect:

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_init_property_assignment(self):
        cred = testutils.MockCredential()
        try:
            app = firebase_admin.initialize_app(cred, name="starter_app")
        except ValueError:
            pytest.fail("initialize app has an error")

        try:
            data_connect_instance = dataconnect.DataConnect(app, BASE_CONFIG)
        except ValueError:
            pytest.fail("DataConnect initialization failed.")

        assert data_connect_instance._app is app # pylint: disable=protected-access
        assert data_connect_instance._config is BASE_CONFIG # pylint: disable=protected-access
        assert data_connect_instance.app is app
        assert data_connect_instance.config is BASE_CONFIG

        assert data_connect_instance._app.name == "starter_app" # pylint: disable=protected-access
        assert data_connect_instance._config.service_id == "starterproject" # pylint: disable=protected-access


class TestDataConnectClientFactory:

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def setup_method(self):
        self.cred = testutils.MockCredential()
        self.app = firebase_admin.initialize_app(self.cred, name="starter_app")
        self.config1 = BASE_CONFIG
        self.config2 = dataconnect.ConnectorConfig(
            service_id="starterproject2", location="us-east4", connector="my_connector2"
        )

    @mock.patch.object(dataconnect._DataConnectService, "get_client", autospec=True)
    def test_client_successful(self, mock_get_client):
        mock_get_client.side_effect = lambda service, config: dataconnect.DataConnect(
            service._app, config # pylint: disable=protected-access
        )
        client1 = dataconnect.client(self.config1, app=self.app)
        client2 = dataconnect.client(self.config2, app=self.app)
        assert mock_get_client.call_count == 2
        mock_get_client.assert_any_call(mock.ANY, self.config1)
        mock_get_client.assert_any_call(mock.ANY, self.config2)
        assert isinstance(client1, dataconnect.DataConnect)
        assert client1.config is self.config1
        assert client1.app is self.app
        assert client2.config is self.config2

    def test_client_retrieval_different_apps_same_config(self):
        app2 = firebase_admin.initialize_app(self.cred, name="app2")

        client1 = dataconnect.client(self.config1, app=self.app)
        client2 = dataconnect.client(self.config1, app=app2)

        assert client1 is not client2
        assert client1.app is self.app
        assert client1.app is not client2.app

    def test_invalid_config_type(self):
        err_msg = "Config must be of type firebase_admin.dataconnect.ConnectorConfig"
        with pytest.raises(ValueError, match=err_msg):
            dataconnect.client("not-a-config", app=self.app)

    def test_invalid_app_type(self):
        with pytest.raises(ValueError, match="Illegal app argument"):
            dataconnect.client(self.config1, "not-a-app")

    def test_client_default_app(self):
        default_app = firebase_admin.initialize_app(self.cred)
        client_instance = dataconnect.client(self.config1)
        assert client_instance.app is default_app

    def test_client_none_config(self):
        err_msg = "Config must be of type firebase_admin.dataconnect.ConnectorConfig"
        with pytest.raises(ValueError, match=err_msg):
            dataconnect.client(None, app=self.app)

    @mock.patch.object(_utils, "get_app_service", wraps=_utils.get_app_service)
    def test_uses_app_service_mechanism(self, mock_get_app_service):
        """Ensures dataconnect.client uses the standard app service loader."""
        dataconnect.client(self.config1, app=self.app)
        mock_get_app_service.assert_called_once()
        args, _ = mock_get_app_service.call_args
        assert args[0] is self.app
        assert args[1] == dataconnect._DATA_CONNECT_ATTRIBUTE # pylint: disable=protected-access
        assert args[2] == dataconnect._DataConnectService # pylint: disable=protected-access


class TestDataConnectService:

    def setup_method(self):
        self.cred = testutils.MockCredential()
        self.app = firebase_admin.initialize_app(self.cred, name="starter_app")
        self.service = dataconnect._DataConnectService(self.app) # pylint: disable=protected-access

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_cache_hit(self):
        config = dataconnect.ConnectorConfig("s1", "l1", "c1")
        client1 = self.service.get_client(config)
        client2 = self.service.get_client(config)
        assert client1 is client2

        assert isinstance(client1, dataconnect.DataConnect)
        assert client1.config is config

    def test_cache_miss_on_different_config(self):
        config1 = dataconnect.ConnectorConfig("s1", "l1", "c1")
        config2 = dataconnect.ConnectorConfig("s2", "l2", "c2")
        client1 = self.service.get_client(config1)
        client2 = self.service.get_client(config2)
        assert client1 is not client2

    @pytest.mark.parametrize(
        "config_a, config_b, expect_same",
        [
            (
                dataconnect.ConnectorConfig("s", "l", "c"),
                dataconnect.ConnectorConfig("s", "l", "c_diff"),
                False,
            ),
            (
                dataconnect.ConnectorConfig("s", "l", "c"),
                dataconnect.ConnectorConfig("s", "l_diff", "c"),
                False,
            ),
            (
                dataconnect.ConnectorConfig("s", "l", "c"),
                dataconnect.ConnectorConfig("s_diff", "l", "c"),
                False,
            ),
            (
                dataconnect.ConnectorConfig("s", "l", "c"),
                dataconnect.ConnectorConfig("s", "l", "c"),
                True,
            ),
        ],
    )
    def test_complex_cache_key(self, config_a, config_b, expect_same):
        client_a = self.service.get_client(config_a)
        client_b = self.service.get_client(config_b)
        if expect_same:
            assert client_a is client_b
        else:
            assert client_a is not client_b

    def test_config_equivalence(self):
        config1 = dataconnect.ConnectorConfig("s1", "l1", "c1")
        config2 = dataconnect.ConnectorConfig("s1", "l1", "c1")
        client1 = self.service.get_client(config1)
        client2 = self.service.get_client(config2)
        assert client1 is client2

    @mock.patch("firebase_admin.dataconnect.DataConnect", autospec=True)
    def test_client_creation_mocking(self, mock_data_connect):
        config1 = dataconnect.ConnectorConfig("s_mock", "l_mock", "c_mock1")
        config2 = dataconnect.ConnectorConfig("s_mock", "l_mock", "c_mock2")

        self.service.get_client(config1)
        mock_data_connect.assert_called_once_with(app=self.app, config=config1)

        mock_data_connect.reset_mock()

        self.service.get_client(config1)
        mock_data_connect.assert_not_called()

        mock_data_connect.reset_mock()

        # first call using config2
        self.service.get_client(config2)
        mock_data_connect.assert_called_once_with(app=self.app, config=config2)

    @mock.patch("firebase_admin.dataconnect.DataConnect", autospec=True)
    def test_error_handling_in_creation(self, mock_data_connect):
        config = dataconnect.ConnectorConfig("s_err", "l_err", "c_err")
        test_error = RuntimeError("Failed to create client")
        mock_data_connect.side_effect = test_error

        with pytest.raises(RuntimeError, match="Failed to create client"):
            self.service.get_client(config)

        # Ensure the failed creation wasn't cached
        mock_data_connect.side_effect = None
        self.service.get_client(config)
        assert mock_data_connect.call_count == 2

    def test_invalid_config_in_service(self):
        err_msg = "Config must be of type firebase_admin.dataconnect.ConnectorConfig"
        with pytest.raises(ValueError, match=err_msg):
            self.service.get_client(None)


class TestDataConnectServiceWorkflow:

    def setup_method(self):
        self.cred = testutils.MockCredential()
        self.app1 = firebase_admin.initialize_app(self.cred, name="integ_app1")
        self.app2 = firebase_admin.initialize_app(self.cred, name="integ_app2")

        self.config1 = BASE_CONFIG
        self.config2 = dataconnect.ConnectorConfig(
            service_id="service2", location="us-east4", connector="conn2"
        )
        self.config1_copy = dataconnect.ConnectorConfig(
            service_id="starterproject", location="us-east4", connector="my_connector"
        )

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_overall_client_retrieval_and_caching(self):
        client1a = dataconnect.client(self.config1, app=self.app1)
        client1b = dataconnect.client(self.config1_copy, app=self.app1)
        client2 = dataconnect.client(self.config2, app=self.app1)

        assert isinstance(client1a, dataconnect.DataConnect)
        assert client1a.app is self.app1
        assert client1a.config is self.config1

        # Same config
        assert client1b is client1a

        # Different config
        assert isinstance(client2, dataconnect.DataConnect)
        assert client2.app is self.app1
        assert client2.config is self.config2
        assert client2 is not client1a

        # Different app
        client1_app2 = dataconnect.client(self.config1, app=self.app2)

        assert isinstance(client1_app2, dataconnect.DataConnect)
        assert client1_app2.app is self.app2
        assert client1_app2.config is self.config1
        assert client1_app2 is not client1a


class TestDataConnectApiClientConstructor:

    def setup_method(self):
        self.cred = testutils.MockCredential()

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_constructor_invalid_app(self):
        msg = (
            "Second argument passed to DataConnectApiClient must be a valid "
            "Firebase app instance."
        )
        with pytest.raises(ValueError, match=msg):
            dataconnect._DataConnectApiClient(BASE_CONFIG, None)

    def test_constructor_missing_project_id(self):
        class CredentialWithoutProjectId(firebase_admin.credentials.Base):
            def get_credential(self):
                class DummyGoogleCred(google_auth_credentials.Credentials):
                    def refresh(self, request):
                        pass
                return DummyGoogleCred()

        app_no_project_id = firebase_admin.initialize_app(
            CredentialWithoutProjectId(),
            name="no-project-id-app"
        )
        try:
            with pytest.raises(ValueError, match="Failed to determine project ID"):
                dataconnect._DataConnectApiClient(BASE_CONFIG, app_no_project_id)
        finally:
            firebase_admin.delete_app(app_no_project_id)

    def test_constructor_connector_config(self):
        app = firebase_admin.initialize_app(self.cred, options={'projectId': 'test-project'})
        api_client = dataconnect._DataConnectApiClient(BASE_CONFIG, app)
        assert api_client._connector_config is BASE_CONFIG

    def test_constructor_emulator_host_invalid(self, monkeypatch):
        monkeypatch.setenv("DATA_CONNECT_EMULATOR_HOST", "http://localhost:9399")
        app = firebase_admin.initialize_app(self.cred, options={'projectId': 'test-project'})
        with pytest.raises(ValueError, match="Invalid DATA_CONNECT_EMULATOR_HOST"):
            dataconnect._DataConnectApiClient(BASE_CONFIG, app)


class TestDataConnectApiClientValidateGraphqlOptions:

    def setup_method(self):
        self.cred = testutils.MockCredential()
        self.app = firebase_admin.initialize_app(
            self.cred, options={'projectId': 'test-project'}
        )
        self.api_client = dataconnect._DataConnectApiClient(BASE_CONFIG, self.app)

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_validate_graphql_options_valid(self):
        # Valid with no options
        self.api_client._validate_graphql_options(None)

        # Valid with default options (no arguments)
        options = dataconnect.GraphqlOptions()
        self.api_client._validate_graphql_options(options)

    def test_validate_graphql_options_valid_impersonate(self):
        # Valid unauthenticated impersonation
        imp_unauth = dataconnect.Impersonation.unauthenticated()
        options = dataconnect.GraphqlOptions(impersonate=imp_unauth)
        self.api_client._validate_graphql_options(options)

        # Valid authenticated impersonation
        imp_auth = dataconnect.Impersonation.authenticated(
            {"sub": "authenticated-UUID"}
        )
        options = dataconnect.GraphqlOptions(impersonate=imp_auth)
        self.api_client._validate_graphql_options(options)

    def test_validate_graphql_options_valid_dataclass_variables(self):
        @dataclass
        class UserProfile:
            address: str
            phone: str

        @dataclass
        class CreateUserVariables:
            user_id: str
            name: str
            profile: UserProfile

        profile_val = UserProfile(address="123 Road", phone="332-3233-0199")
        valid_variables = CreateUserVariables(
            user_id="1", name="Fred", profile=profile_val
        )
        options = dataconnect.GraphqlOptions(variables=valid_variables)
        self.api_client._validate_graphql_options(options, CreateUserVariables)

    def test_validate_graphql_options_valid_mapping_variables(self):
        options = dataconnect.GraphqlOptions(variables={"user_id": "1", "name": "Fred"})
        self.api_client._validate_graphql_options(options)

    def test_validate_graphql_options_invalid_options(self):
        with pytest.raises(ValueError, match="options must be a GraphqlOptions instance"):
            self.api_client._validate_graphql_options("invalid-options")

    def test_validate_graphql_options_invalid_impersonate(self):
        # impersonate must be dict
        options = dataconnect.GraphqlOptions(impersonate="invalid")
        with pytest.raises(ValueError, match="impersonate option must be a dictionary"):
            self.api_client._validate_graphql_options(options)

        # impersonate must have either unauthenticated or authClaims
        options = dataconnect.GraphqlOptions(impersonate={"invalid_key": True})
        msg = (
            "impersonate option must contain either "
            "'unauthenticated' or 'authClaims'"
        )
        with pytest.raises(ValueError, match=msg):
            self.api_client._validate_graphql_options(options)

        # unauthenticated must be boolean
        options = dataconnect.GraphqlOptions(impersonate={"unauthenticated": "not-bool"})
        with pytest.raises(ValueError, match="'unauthenticated' claim must be a boolean"):
            self.api_client._validate_graphql_options(options)

        # authClaims must be a dict
        options = dataconnect.GraphqlOptions(impersonate={"authClaims": "not-dict"})
        with pytest.raises(ValueError, match="'authClaims' claim must be a dictionary"):
            self.api_client._validate_graphql_options(options)

        # impersonate cannot contain both unauthenticated and authClaims
        options = dataconnect.GraphqlOptions(
            impersonate={"unauthenticated": True, "authClaims": {"uid": "123"}}
        )
        msg = (
            "impersonate option cannot contain both "
            "'unauthenticated' and 'authClaims'"
        )
        with pytest.raises(ValueError, match=msg):
            self.api_client._validate_graphql_options(options)

    def test_validate_graphql_options_invalid_operation_name(self):
        # Test type validation
        options = dataconnect.GraphqlOptions(operation_name=123)
        with pytest.raises(ValueError, match="operation_name must be a string"):
            self.api_client._validate_graphql_options(options)

        # Test empty string validation
        options = dataconnect.GraphqlOptions(operation_name="")
        with pytest.raises(ValueError, match="operation_name must be a non-empty string"):
            self.api_client._validate_graphql_options(options)

        # Test stripped whitespace validation
        options = dataconnect.GraphqlOptions(operation_name="   ")
        with pytest.raises(ValueError, match="operation_name must be a non-empty string"):
            self.api_client._validate_graphql_options(options)

    def test_validate_graphql_options_invalid_variables(self):
        @dataclass
        class UserProfile:
            address: str
            phone: str

        @dataclass
        class CreateUserVariables:
            user_id: str
            name: str
            profile: UserProfile

        # Test invalid variable format (not Mapping or dataclass)
        options = dataconnect.GraphqlOptions(variables="invalid-string-format")
        msg = "variables must be a collections.abc.Mapping or a dataclass"
        with pytest.raises(ValueError, match=msg):
            self.api_client._validate_graphql_options(options)

        # Test valid Mapping format but type mismatch against expected dataclass type
        options = dataconnect.GraphqlOptions(variables={"foo": "bar"})
        with pytest.raises(ValueError, match="variables must be of type CreateUserVariables"):
            self.api_client._validate_graphql_options(options, CreateUserVariables)


class TestDataConnectApiClientPrepareGraphqlPayload:

    def setup_method(self):
        self.cred = testutils.MockCredential()
        self.app = firebase_admin.initialize_app(self.cred, options={'projectId': 'test-project'})
        self.api_client = dataconnect._DataConnectApiClient(BASE_CONFIG, self.app)

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_prepare_graphql_payload_only_query(self):
        payload = self.api_client._prepare_graphql_payload("query { hello }", None)
        assert payload == {"query": "query { hello }"}

    def test_prepare_graphql_payload_with_variables(self):
        options = dataconnect.GraphqlOptions(variables={"foo": "bar"})
        payload = self.api_client._prepare_graphql_payload("query { hello }", options)
        assert payload == {
            "query": "query { hello }",
            "variables": {"foo": "bar"}
        }

    def test_prepare_graphql_payload_with_dataclass_variables(self):
        @dataclass
        class UserProfile:
            address: str
            phone: str

        @dataclass
        class CreateUserVariables:
            user_id: str
            name: str
            profile: UserProfile

        profile_val = UserProfile(address="123 Road", phone="332-3233-0199")
        valid_variables = CreateUserVariables(
            user_id="1", name="Fred", profile=profile_val
        )
        options = dataconnect.GraphqlOptions(variables=valid_variables)
        payload = self.api_client._prepare_graphql_payload("query { hello }", options)
        assert payload == {
            "query": "query { hello }",
            "variables": {
                "user_id": "1",
                "name": "Fred",
                "profile": {
                    "address": "123 Road",
                    "phone": "332-3233-0199"
                }
            }
        }

    def test_prepare_graphql_payload_with_operation_name(self):
        options = dataconnect.GraphqlOptions(operation_name="myOp")
        payload = self.api_client._prepare_graphql_payload("query { hello }", options)
        assert payload == {
            "query": "query { hello }",
            "operationName": "myOp"
        }

    def test_prepare_graphql_payload_with_impersonate_unauthenticated(self):
        imp_unauth = dataconnect.Impersonation.unauthenticated()
        options = dataconnect.GraphqlOptions(impersonate=imp_unauth)
        payload = self.api_client._prepare_graphql_payload("query { hello }", options)
        assert payload == {
            "query": "query { hello }",
            "extensions": {
                "impersonate": {"unauthenticated": True}
            }
        }

    def test_prepare_graphql_payload_with_impersonate_authenticated(self):
        imp_auth = dataconnect.Impersonation.authenticated(
            {"sub": "authenticated-UUID"}
        )
        options = dataconnect.GraphqlOptions(impersonate=imp_auth)
        payload = self.api_client._prepare_graphql_payload("query { hello }", options)
        assert payload == {
            "query": "query { hello }",
            "extensions": {
                "impersonate": {"authClaims": {"sub": "authenticated-UUID"}}
            }
        }

    def test_prepare_graphql_payload_with_all_fields(self):
        @dataclass
        class UserProfile:
            address: str
            phone: str

        @dataclass
        class CreateUserVariables:
            user_id: str
            name: str
            profile: UserProfile

        profile_val = UserProfile(address="123 Road", phone="332-3233-0199")
        valid_variables = CreateUserVariables(
            user_id="1", name="Fred", profile=profile_val
        )
        imp_auth = dataconnect.Impersonation.authenticated(
            {"sub": "authenticated-UUID"}
        )
        options = dataconnect.GraphqlOptions(
            variables=valid_variables,
            operation_name="getUsers",
            impersonate=imp_auth
        )
        payload = self.api_client._prepare_graphql_payload("query { hello }", options)
        assert payload == {
            "query": "query { hello }",
            "operationName": "getUsers",
            "variables": {
                "user_id": "1",
                "name": "Fred",
                "profile": {
                    "address": "123 Road",
                    "phone": "332-3233-0199"
                }
            },
            "extensions": {
                "impersonate": {"authClaims": {"sub": "authenticated-UUID"}}
            }
        }


class TestDataConnectApiClientServiceUrl:

    def setup_method(self):
        self.cred = testutils.MockCredential()
        self.app = firebase_admin.initialize_app(self.cred, options={'projectId': 'test-project'})
        self.api_client = dataconnect._DataConnectApiClient(BASE_CONFIG, self.app)

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_get_firebase_dataconnect_service_url_production(self):
        url = self.api_client._get_firebase_dataconnect_service_url("executeGraphql")
        expected = (
            "https://firebasedataconnect.googleapis.com/v1"
            "/projects/test-project/locations/us-east4"
            "/services/starterproject:executeGraphql"
        )
        assert url == expected

    def test_get_firebase_dataconnect_service_url_emulator(self, monkeypatch):
        monkeypatch.setenv("DATA_CONNECT_EMULATOR_HOST", "localhost:9399")
        api_client = dataconnect._DataConnectApiClient(BASE_CONFIG, self.app)
        url = api_client._get_firebase_dataconnect_service_url("executeGraphql")
        expected = (
            "http://localhost:9399/v1"
            "/projects/test-project/locations/us-east4"
            "/services/starterproject:executeGraphql"
        )
        assert url == expected


class TestDataConnectApiClientGetHeaders:

    def setup_method(self):
        self.cred = testutils.MockCredential()
        self.app = firebase_admin.initialize_app(
            self.cred, options={'projectId': 'test-project'}
        )
        self.api_client = dataconnect._DataConnectApiClient(BASE_CONFIG, self.app)

    def teardown_method(self, method):
        del method
        testutils.cleanup_apps()

    def test_get_headers(self):
        headers = self.api_client._get_headers()
        assert isinstance(headers, dict)
        assert headers.get("X-Firebase-Client") == f"fire-admin-python/{firebase_admin.__version__}"
        assert headers.get("x-goog-api-client") == _utils.get_metrics_header()
