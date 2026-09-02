# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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
#
import os
import mock
import packaging.version

import grpc
from grpc.experimental import aio
import math
import pytest
from proto.marshal.rules.dates import DurationRule, TimestampRule

from requests import Response
from requests.sessions import Session

from google.api_core import client_options
from google.api_core import exceptions as core_exceptions
from google.api_core import gapic_v1
from google.api_core import grpc_helpers
from google.api_core import grpc_helpers_async
from google.auth import credentials as ga_credentials
from google.auth.exceptions import MutualTLSChannelError
from google.firebase.appcheck_v1beta.services.config_service import ConfigServiceClient
from google.firebase.appcheck_v1beta.services.config_service import pagers
from google.firebase.appcheck_v1beta.services.config_service import transports
from google.firebase.appcheck_v1beta.services.config_service.transports.base import _GOOGLE_AUTH_VERSION
from google.firebase.appcheck_v1beta.types import configuration
from google.oauth2 import service_account
from google.protobuf import duration_pb2  # type: ignore
from google.protobuf import field_mask_pb2  # type: ignore
import google.auth


# TODO(busunkim): Once google-auth >= 1.25.0 is required transitively
# through google-api-core:
# - Delete the auth "less than" test cases
# - Delete these pytest markers (Make the "greater than or equal to" tests the default).
requires_google_auth_lt_1_25_0 = pytest.mark.skipif(
    packaging.version.parse(_GOOGLE_AUTH_VERSION) >= packaging.version.parse("1.25.0"),
    reason="This test requires google-auth < 1.25.0",
)
requires_google_auth_gte_1_25_0 = pytest.mark.skipif(
    packaging.version.parse(_GOOGLE_AUTH_VERSION) < packaging.version.parse("1.25.0"),
    reason="This test requires google-auth >= 1.25.0",
)

def client_cert_source_callback():
    return b"cert bytes", b"key bytes"


# If default endpoint is localhost, then default mtls endpoint will be the same.
# This method modifies the default endpoint so the client can produce a different
# mtls endpoint for endpoint testing purposes.
def modify_default_endpoint(client):
    return "foo.googleapis.com" if ("localhost" in client.DEFAULT_ENDPOINT) else client.DEFAULT_ENDPOINT


def test__get_default_mtls_endpoint():
    api_endpoint = "example.googleapis.com"
    api_mtls_endpoint = "example.mtls.googleapis.com"
    sandbox_endpoint = "example.sandbox.googleapis.com"
    sandbox_mtls_endpoint = "example.mtls.sandbox.googleapis.com"
    non_googleapi = "api.example.com"

    assert ConfigServiceClient._get_default_mtls_endpoint(None) is None
    assert ConfigServiceClient._get_default_mtls_endpoint(api_endpoint) == api_mtls_endpoint
    assert ConfigServiceClient._get_default_mtls_endpoint(api_mtls_endpoint) == api_mtls_endpoint
    assert ConfigServiceClient._get_default_mtls_endpoint(sandbox_endpoint) == sandbox_mtls_endpoint
    assert ConfigServiceClient._get_default_mtls_endpoint(sandbox_mtls_endpoint) == sandbox_mtls_endpoint
    assert ConfigServiceClient._get_default_mtls_endpoint(non_googleapi) == non_googleapi


@pytest.mark.parametrize("client_class", [
    ConfigServiceClient,
])
def test_config_service_client_from_service_account_info(client_class):
    creds = ga_credentials.AnonymousCredentials()
    with mock.patch.object(service_account.Credentials, 'from_service_account_info') as factory:
        factory.return_value = creds
        info = {"valid": True}
        client = client_class.from_service_account_info(info)
        assert client.transport._credentials == creds
        assert isinstance(client, client_class)

        assert client.transport._host == 'firebaseappcheck.googleapis.com:443'


@pytest.mark.parametrize("transport_class,transport_name", [
    (transports.ConfigServiceRestTransport, "rest"),
])
def test_config_service_client_service_account_always_use_jwt(transport_class, transport_name):
    with mock.patch.object(service_account.Credentials, 'with_always_use_jwt_access', create=True) as use_jwt:
        creds = service_account.Credentials(None, None, None)
        transport = transport_class(credentials=creds, always_use_jwt_access=True)
        use_jwt.assert_called_once_with(True)

    with mock.patch.object(service_account.Credentials, 'with_always_use_jwt_access', create=True) as use_jwt:
        creds = service_account.Credentials(None, None, None)
        transport = transport_class(credentials=creds, always_use_jwt_access=False)
        use_jwt.assert_not_called()


@pytest.mark.parametrize("client_class", [
    ConfigServiceClient,
])
def test_config_service_client_from_service_account_file(client_class):
    creds = ga_credentials.AnonymousCredentials()
    with mock.patch.object(service_account.Credentials, 'from_service_account_file') as factory:
        factory.return_value = creds
        client = client_class.from_service_account_file("dummy/file/path.json")
        assert client.transport._credentials == creds
        assert isinstance(client, client_class)

        client = client_class.from_service_account_json("dummy/file/path.json")
        assert client.transport._credentials == creds
        assert isinstance(client, client_class)

        assert client.transport._host == 'firebaseappcheck.googleapis.com:443'


def test_config_service_client_get_transport_class():
    transport = ConfigServiceClient.get_transport_class()
    available_transports = [
        transports.ConfigServiceRestTransport,
    ]
    assert transport in available_transports

    transport = ConfigServiceClient.get_transport_class("rest")
    assert transport == transports.ConfigServiceRestTransport


@pytest.mark.parametrize("client_class,transport_class,transport_name", [
    (ConfigServiceClient, transports.ConfigServiceRestTransport, "rest"),
])
@mock.patch.object(ConfigServiceClient, "DEFAULT_ENDPOINT", modify_default_endpoint(ConfigServiceClient))
def test_config_service_client_client_options(client_class, transport_class, transport_name):
    # Check that if channel is provided we won't create a new one.
    with mock.patch.object(ConfigServiceClient, 'get_transport_class') as gtc:
        transport = transport_class(
            credentials=ga_credentials.AnonymousCredentials()
        )
        client = client_class(transport=transport)
        gtc.assert_not_called()

    # Check that if channel is provided via str we will create a new one.
    with mock.patch.object(ConfigServiceClient, 'get_transport_class') as gtc:
        client = client_class(transport=transport_name)
        gtc.assert_called()

    # Check the case api_endpoint is provided.
    options = client_options.ClientOptions(api_endpoint="squid.clam.whelk")
    with mock.patch.object(transport_class, '__init__') as patched:
        patched.return_value = None
        client = client_class(client_options=options)
        patched.assert_called_once_with(
            credentials=None,
            credentials_file=None,
            host="squid.clam.whelk",
            scopes=None,
            client_cert_source_for_mtls=None,
            quota_project_id=None,
            client_info=transports.base.DEFAULT_CLIENT_INFO,
        )

    # Check the case api_endpoint is not provided and GOOGLE_API_USE_MTLS_ENDPOINT is
    # "never".
    with mock.patch.dict(os.environ, {"GOOGLE_API_USE_MTLS_ENDPOINT": "never"}):
        with mock.patch.object(transport_class, '__init__') as patched:
            patched.return_value = None
            client = client_class()
            patched.assert_called_once_with(
                credentials=None,
                credentials_file=None,
                host=client.DEFAULT_ENDPOINT,
                scopes=None,
                client_cert_source_for_mtls=None,
                quota_project_id=None,
                client_info=transports.base.DEFAULT_CLIENT_INFO,
            )

    # Check the case api_endpoint is not provided and GOOGLE_API_USE_MTLS_ENDPOINT is
    # "always".
    with mock.patch.dict(os.environ, {"GOOGLE_API_USE_MTLS_ENDPOINT": "always"}):
        with mock.patch.object(transport_class, '__init__') as patched:
            patched.return_value = None
            client = client_class()
            patched.assert_called_once_with(
                credentials=None,
                credentials_file=None,
                host=client.DEFAULT_MTLS_ENDPOINT,
                scopes=None,
                client_cert_source_for_mtls=None,
                quota_project_id=None,
                client_info=transports.base.DEFAULT_CLIENT_INFO,
            )

    # Check the case api_endpoint is not provided and GOOGLE_API_USE_MTLS_ENDPOINT has
    # unsupported value.
    with mock.patch.dict(os.environ, {"GOOGLE_API_USE_MTLS_ENDPOINT": "Unsupported"}):
        with pytest.raises(MutualTLSChannelError):
            client = client_class()

    # Check the case GOOGLE_API_USE_CLIENT_CERTIFICATE has unsupported value.
    with mock.patch.dict(os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": "Unsupported"}):
        with pytest.raises(ValueError):
            client = client_class()

    # Check the case quota_project_id is provided
    options = client_options.ClientOptions(quota_project_id="octopus")
    with mock.patch.object(transport_class, '__init__') as patched:
        patched.return_value = None
        client = client_class(client_options=options)
        patched.assert_called_once_with(
            credentials=None,
            credentials_file=None,
            host=client.DEFAULT_ENDPOINT,
            scopes=None,
            client_cert_source_for_mtls=None,
            quota_project_id="octopus",
            client_info=transports.base.DEFAULT_CLIENT_INFO,
        )

@pytest.mark.parametrize("client_class,transport_class,transport_name,use_client_cert_env", [
    (ConfigServiceClient, transports.ConfigServiceRestTransport, "rest", "true"),
    (ConfigServiceClient, transports.ConfigServiceRestTransport, "rest", "false"),
])
@mock.patch.object(ConfigServiceClient, "DEFAULT_ENDPOINT", modify_default_endpoint(ConfigServiceClient))
@mock.patch.dict(os.environ, {"GOOGLE_API_USE_MTLS_ENDPOINT": "auto"})
def test_config_service_client_mtls_env_auto(client_class, transport_class, transport_name, use_client_cert_env):
    # This tests the endpoint autoswitch behavior. Endpoint is autoswitched to the default
    # mtls endpoint, if GOOGLE_API_USE_CLIENT_CERTIFICATE is "true" and client cert exists.

    # Check the case client_cert_source is provided. Whether client cert is used depends on
    # GOOGLE_API_USE_CLIENT_CERTIFICATE value.
    with mock.patch.dict(os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": use_client_cert_env}):
        options = client_options.ClientOptions(client_cert_source=client_cert_source_callback)
        with mock.patch.object(transport_class, '__init__') as patched:
            patched.return_value = None
            client = client_class(client_options=options)

            if use_client_cert_env == "false":
                expected_client_cert_source = None
                expected_host = client.DEFAULT_ENDPOINT
            else:
                expected_client_cert_source = client_cert_source_callback
                expected_host = client.DEFAULT_MTLS_ENDPOINT

            patched.assert_called_once_with(
                credentials=None,
                credentials_file=None,
                host=expected_host,
                scopes=None,
                client_cert_source_for_mtls=expected_client_cert_source,
                quota_project_id=None,
                client_info=transports.base.DEFAULT_CLIENT_INFO,
            )

    # Check the case ADC client cert is provided. Whether client cert is used depends on
    # GOOGLE_API_USE_CLIENT_CERTIFICATE value.
    with mock.patch.dict(os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": use_client_cert_env}):
        with mock.patch.object(transport_class, '__init__') as patched:
            with mock.patch('google.auth.transport.mtls.has_default_client_cert_source', return_value=True):
                with mock.patch('google.auth.transport.mtls.default_client_cert_source', return_value=client_cert_source_callback):
                    if use_client_cert_env == "false":
                        expected_host = client.DEFAULT_ENDPOINT
                        expected_client_cert_source = None
                    else:
                        expected_host = client.DEFAULT_MTLS_ENDPOINT
                        expected_client_cert_source = client_cert_source_callback

                    patched.return_value = None
                    client = client_class()
                    patched.assert_called_once_with(
                        credentials=None,
                        credentials_file=None,
                        host=expected_host,
                        scopes=None,
                        client_cert_source_for_mtls=expected_client_cert_source,
                        quota_project_id=None,
                        client_info=transports.base.DEFAULT_CLIENT_INFO,
                    )

    # Check the case client_cert_source and ADC client cert are not provided.
    with mock.patch.dict(os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": use_client_cert_env}):
        with mock.patch.object(transport_class, '__init__') as patched:
            with mock.patch("google.auth.transport.mtls.has_default_client_cert_source", return_value=False):
                patched.return_value = None
                client = client_class()
                patched.assert_called_once_with(
                    credentials=None,
                    credentials_file=None,
                    host=client.DEFAULT_ENDPOINT,
                    scopes=None,
                    client_cert_source_for_mtls=None,
                    quota_project_id=None,
                    client_info=transports.base.DEFAULT_CLIENT_INFO,
                )


@pytest.mark.parametrize("client_class,transport_class,transport_name", [
    (ConfigServiceClient, transports.ConfigServiceRestTransport, "rest"),
])
def test_config_service_client_client_options_scopes(client_class, transport_class, transport_name):
    # Check the case scopes are provided.
    options = client_options.ClientOptions(
        scopes=["1", "2"],
    )
    with mock.patch.object(transport_class, '__init__') as patched:
        patched.return_value = None
        client = client_class(client_options=options)
        patched.assert_called_once_with(
            credentials=None,
            credentials_file=None,
            host=client.DEFAULT_ENDPOINT,
            scopes=["1", "2"],
            client_cert_source_for_mtls=None,
            quota_project_id=None,
            client_info=transports.base.DEFAULT_CLIENT_INFO,
        )

@pytest.mark.parametrize("client_class,transport_class,transport_name", [
    (ConfigServiceClient, transports.ConfigServiceRestTransport, "rest"),
])
def test_config_service_client_client_options_credentials_file(client_class, transport_class, transport_name):
    # Check the case credentials file is provided.
    options = client_options.ClientOptions(
        credentials_file="credentials.json"
    )
    with mock.patch.object(transport_class, '__init__') as patched:
        patched.return_value = None
        client = client_class(client_options=options)
        patched.assert_called_once_with(
            credentials=None,
            credentials_file="credentials.json",
            host=client.DEFAULT_ENDPOINT,
            scopes=None,
            client_cert_source_for_mtls=None,
            quota_project_id=None,
            client_info=transports.base.DEFAULT_CLIENT_INFO,
        )


def test_get_app_attest_config_rest(transport: str = 'rest', request_type=configuration.GetAppAttestConfigRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.AppAttestConfig(
            name='name_value',
            token_ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.AppAttestConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.get_app_attest_config(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.AppAttestConfig)
    assert response.name == 'name_value'
    assert response.token_ttl == duration_pb2.Duration(seconds=751)


def test_get_app_attest_config_rest_from_dict():
    test_get_app_attest_config_rest(request_type=dict)


def test_get_app_attest_config_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.AppAttestConfig()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.AppAttestConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_app_attest_config(
            name='name_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'name_value' in http_call[1] + str(body) + str(params)


def test_get_app_attest_config_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_app_attest_config(
            configuration.GetAppAttestConfigRequest(),
            name='name_value',
        )


def test_batch_get_app_attest_configs_rest(transport: str = 'rest', request_type=configuration.BatchGetAppAttestConfigsRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.BatchGetAppAttestConfigsResponse(
            configs=[configuration.AppAttestConfig(name='name_value')],
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.BatchGetAppAttestConfigsResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.batch_get_app_attest_configs(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.BatchGetAppAttestConfigsResponse)
    assert response.configs == [configuration.AppAttestConfig(name='name_value')]


def test_batch_get_app_attest_configs_rest_from_dict():
    test_batch_get_app_attest_configs_rest(request_type=dict)


def test_batch_get_app_attest_configs_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.BatchGetAppAttestConfigsResponse()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.BatchGetAppAttestConfigsResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.batch_get_app_attest_configs(
            parent='parent_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'parent_value' in http_call[1] + str(body) + str(params)


def test_batch_get_app_attest_configs_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.batch_get_app_attest_configs(
            configuration.BatchGetAppAttestConfigsRequest(),
            parent='parent_value',
        )


def test_update_app_attest_config_rest(transport: str = 'rest', request_type=configuration.UpdateAppAttestConfigRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.AppAttestConfig(
            name='name_value',
            token_ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.AppAttestConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.update_app_attest_config(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.AppAttestConfig)
    assert response.name == 'name_value'
    assert response.token_ttl == duration_pb2.Duration(seconds=751)


def test_update_app_attest_config_rest_from_dict():
    test_update_app_attest_config_rest(request_type=dict)


def test_update_app_attest_config_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.AppAttestConfig()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.AppAttestConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        app_attest_config = configuration.AppAttestConfig(name='name_value')
        update_mask = field_mask_pb2.FieldMask(paths=['paths_value'])
        client.update_app_attest_config(
            app_attest_config=app_attest_config,
            update_mask=update_mask,
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert configuration.AppAttestConfig.to_json(app_attest_config, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)
        assert field_mask_pb2.FieldMask.to_json(update_mask, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)


def test_update_app_attest_config_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.update_app_attest_config(
            configuration.UpdateAppAttestConfigRequest(),
            app_attest_config=configuration.AppAttestConfig(name='name_value'),
            update_mask=field_mask_pb2.FieldMask(paths=['paths_value']),
        )


def test_get_device_check_config_rest(transport: str = 'rest', request_type=configuration.GetDeviceCheckConfigRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.DeviceCheckConfig(
            name='name_value',
            token_ttl=duration_pb2.Duration(seconds=751),
            key_id='key_id_value',
            private_key='private_key_value',
            private_key_set=True,
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.DeviceCheckConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.get_device_check_config(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.DeviceCheckConfig)
    assert response.name == 'name_value'
    assert response.token_ttl == duration_pb2.Duration(seconds=751)
    assert response.key_id == 'key_id_value'
    assert response.private_key == 'private_key_value'
    assert response.private_key_set is True


def test_get_device_check_config_rest_from_dict():
    test_get_device_check_config_rest(request_type=dict)


def test_get_device_check_config_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.DeviceCheckConfig()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.DeviceCheckConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_device_check_config(
            name='name_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'name_value' in http_call[1] + str(body) + str(params)


def test_get_device_check_config_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_device_check_config(
            configuration.GetDeviceCheckConfigRequest(),
            name='name_value',
        )


def test_batch_get_device_check_configs_rest(transport: str = 'rest', request_type=configuration.BatchGetDeviceCheckConfigsRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.BatchGetDeviceCheckConfigsResponse(
            configs=[configuration.DeviceCheckConfig(name='name_value')],
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.BatchGetDeviceCheckConfigsResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.batch_get_device_check_configs(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.BatchGetDeviceCheckConfigsResponse)
    assert response.configs == [configuration.DeviceCheckConfig(name='name_value')]


def test_batch_get_device_check_configs_rest_from_dict():
    test_batch_get_device_check_configs_rest(request_type=dict)


def test_batch_get_device_check_configs_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.BatchGetDeviceCheckConfigsResponse()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.BatchGetDeviceCheckConfigsResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.batch_get_device_check_configs(
            parent='parent_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'parent_value' in http_call[1] + str(body) + str(params)


def test_batch_get_device_check_configs_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.batch_get_device_check_configs(
            configuration.BatchGetDeviceCheckConfigsRequest(),
            parent='parent_value',
        )


def test_update_device_check_config_rest(transport: str = 'rest', request_type=configuration.UpdateDeviceCheckConfigRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.DeviceCheckConfig(
            name='name_value',
            token_ttl=duration_pb2.Duration(seconds=751),
            key_id='key_id_value',
            private_key='private_key_value',
            private_key_set=True,
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.DeviceCheckConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.update_device_check_config(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.DeviceCheckConfig)
    assert response.name == 'name_value'
    assert response.token_ttl == duration_pb2.Duration(seconds=751)
    assert response.key_id == 'key_id_value'
    assert response.private_key == 'private_key_value'
    assert response.private_key_set is True


def test_update_device_check_config_rest_from_dict():
    test_update_device_check_config_rest(request_type=dict)


def test_update_device_check_config_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.DeviceCheckConfig()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.DeviceCheckConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        device_check_config = configuration.DeviceCheckConfig(name='name_value')
        update_mask = field_mask_pb2.FieldMask(paths=['paths_value'])
        client.update_device_check_config(
            device_check_config=device_check_config,
            update_mask=update_mask,
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert configuration.DeviceCheckConfig.to_json(device_check_config, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)
        assert field_mask_pb2.FieldMask.to_json(update_mask, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)


def test_update_device_check_config_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.update_device_check_config(
            configuration.UpdateDeviceCheckConfigRequest(),
            device_check_config=configuration.DeviceCheckConfig(name='name_value'),
            update_mask=field_mask_pb2.FieldMask(paths=['paths_value']),
        )


def test_get_recaptcha_config_rest(transport: str = 'rest', request_type=configuration.GetRecaptchaConfigRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.RecaptchaConfig(
            token_ttl=duration_pb2.Duration(seconds=751),
            name='name_value',
            site_secret='site_secret_value',
            site_secret_set=True,
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.RecaptchaConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.get_recaptcha_config(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.RecaptchaConfig)
    assert response.token_ttl == duration_pb2.Duration(seconds=751)
    assert response.name == 'name_value'
    assert response.site_secret == 'site_secret_value'
    assert response.site_secret_set is True


def test_get_recaptcha_config_rest_from_dict():
    test_get_recaptcha_config_rest(request_type=dict)


def test_get_recaptcha_config_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.RecaptchaConfig()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.RecaptchaConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_recaptcha_config(
            name='name_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'name_value' in http_call[1] + str(body) + str(params)


def test_get_recaptcha_config_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_recaptcha_config(
            configuration.GetRecaptchaConfigRequest(),
            name='name_value',
        )


def test_batch_get_recaptcha_configs_rest(transport: str = 'rest', request_type=configuration.BatchGetRecaptchaConfigsRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.BatchGetRecaptchaConfigsResponse(
            configs=[configuration.RecaptchaConfig(token_ttl=duration_pb2.Duration(seconds=751))],
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.BatchGetRecaptchaConfigsResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.batch_get_recaptcha_configs(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.BatchGetRecaptchaConfigsResponse)
    assert response.configs == [configuration.RecaptchaConfig(token_ttl=duration_pb2.Duration(seconds=751))]


def test_batch_get_recaptcha_configs_rest_from_dict():
    test_batch_get_recaptcha_configs_rest(request_type=dict)


def test_batch_get_recaptcha_configs_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.BatchGetRecaptchaConfigsResponse()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.BatchGetRecaptchaConfigsResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.batch_get_recaptcha_configs(
            parent='parent_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'parent_value' in http_call[1] + str(body) + str(params)


def test_batch_get_recaptcha_configs_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.batch_get_recaptcha_configs(
            configuration.BatchGetRecaptchaConfigsRequest(),
            parent='parent_value',
        )


def test_update_recaptcha_config_rest(transport: str = 'rest', request_type=configuration.UpdateRecaptchaConfigRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.RecaptchaConfig(
            token_ttl=duration_pb2.Duration(seconds=751),
            name='name_value',
            site_secret='site_secret_value',
            site_secret_set=True,
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.RecaptchaConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.update_recaptcha_config(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.RecaptchaConfig)
    assert response.token_ttl == duration_pb2.Duration(seconds=751)
    assert response.name == 'name_value'
    assert response.site_secret == 'site_secret_value'
    assert response.site_secret_set is True


def test_update_recaptcha_config_rest_from_dict():
    test_update_recaptcha_config_rest(request_type=dict)


def test_update_recaptcha_config_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.RecaptchaConfig()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.RecaptchaConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        recaptcha_config = configuration.RecaptchaConfig(token_ttl=duration_pb2.Duration(seconds=751))
        update_mask = field_mask_pb2.FieldMask(paths=['paths_value'])
        client.update_recaptcha_config(
            recaptcha_config=recaptcha_config,
            update_mask=update_mask,
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert configuration.RecaptchaConfig.to_json(recaptcha_config, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)
        assert field_mask_pb2.FieldMask.to_json(update_mask, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)


def test_update_recaptcha_config_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.update_recaptcha_config(
            configuration.UpdateRecaptchaConfigRequest(),
            recaptcha_config=configuration.RecaptchaConfig(token_ttl=duration_pb2.Duration(seconds=751)),
            update_mask=field_mask_pb2.FieldMask(paths=['paths_value']),
        )


def test_get_safety_net_config_rest(transport: str = 'rest', request_type=configuration.GetSafetyNetConfigRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.SafetyNetConfig(
            name='name_value',
            token_ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.SafetyNetConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.get_safety_net_config(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.SafetyNetConfig)
    assert response.name == 'name_value'
    assert response.token_ttl == duration_pb2.Duration(seconds=751)


def test_get_safety_net_config_rest_from_dict():
    test_get_safety_net_config_rest(request_type=dict)


def test_get_safety_net_config_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.SafetyNetConfig()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.SafetyNetConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_safety_net_config(
            name='name_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'name_value' in http_call[1] + str(body) + str(params)


def test_get_safety_net_config_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_safety_net_config(
            configuration.GetSafetyNetConfigRequest(),
            name='name_value',
        )


def test_batch_get_safety_net_configs_rest(transport: str = 'rest', request_type=configuration.BatchGetSafetyNetConfigsRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.BatchGetSafetyNetConfigsResponse(
            configs=[configuration.SafetyNetConfig(name='name_value')],
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.BatchGetSafetyNetConfigsResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.batch_get_safety_net_configs(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.BatchGetSafetyNetConfigsResponse)
    assert response.configs == [configuration.SafetyNetConfig(name='name_value')]


def test_batch_get_safety_net_configs_rest_from_dict():
    test_batch_get_safety_net_configs_rest(request_type=dict)


def test_batch_get_safety_net_configs_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.BatchGetSafetyNetConfigsResponse()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.BatchGetSafetyNetConfigsResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.batch_get_safety_net_configs(
            parent='parent_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'parent_value' in http_call[1] + str(body) + str(params)


def test_batch_get_safety_net_configs_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.batch_get_safety_net_configs(
            configuration.BatchGetSafetyNetConfigsRequest(),
            parent='parent_value',
        )


def test_update_safety_net_config_rest(transport: str = 'rest', request_type=configuration.UpdateSafetyNetConfigRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.SafetyNetConfig(
            name='name_value',
            token_ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.SafetyNetConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.update_safety_net_config(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.SafetyNetConfig)
    assert response.name == 'name_value'
    assert response.token_ttl == duration_pb2.Duration(seconds=751)


def test_update_safety_net_config_rest_from_dict():
    test_update_safety_net_config_rest(request_type=dict)


def test_update_safety_net_config_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.SafetyNetConfig()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.SafetyNetConfig.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        safety_net_config = configuration.SafetyNetConfig(name='name_value')
        update_mask = field_mask_pb2.FieldMask(paths=['paths_value'])
        client.update_safety_net_config(
            safety_net_config=safety_net_config,
            update_mask=update_mask,
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert configuration.SafetyNetConfig.to_json(safety_net_config, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)
        assert field_mask_pb2.FieldMask.to_json(update_mask, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)


def test_update_safety_net_config_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.update_safety_net_config(
            configuration.UpdateSafetyNetConfigRequest(),
            safety_net_config=configuration.SafetyNetConfig(name='name_value'),
            update_mask=field_mask_pb2.FieldMask(paths=['paths_value']),
        )


def test_get_debug_token_rest(transport: str = 'rest', request_type=configuration.GetDebugTokenRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.DebugToken(
            name='name_value',
            display_name='display_name_value',
            token='token_value',
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.DebugToken.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.get_debug_token(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.DebugToken)
    assert response.name == 'name_value'
    assert response.display_name == 'display_name_value'
    assert response.token == 'token_value'


def test_get_debug_token_rest_from_dict():
    test_get_debug_token_rest(request_type=dict)


def test_get_debug_token_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.DebugToken()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.DebugToken.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_debug_token(
            name='name_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'name_value' in http_call[1] + str(body) + str(params)


def test_get_debug_token_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_debug_token(
            configuration.GetDebugTokenRequest(),
            name='name_value',
        )


def test_list_debug_tokens_rest(transport: str = 'rest', request_type=configuration.ListDebugTokensRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.ListDebugTokensResponse(
            debug_tokens=[configuration.DebugToken(name='name_value')],
            next_page_token='next_page_token_value',
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.ListDebugTokensResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.list_debug_tokens(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, pagers.ListDebugTokensPager)
    assert response.debug_tokens == [configuration.DebugToken(name='name_value')]
    assert response.next_page_token == 'next_page_token_value'


def test_list_debug_tokens_rest_from_dict():
    test_list_debug_tokens_rest(request_type=dict)


def test_list_debug_tokens_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.ListDebugTokensResponse()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.ListDebugTokensResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.list_debug_tokens(
            parent='parent_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'parent_value' in http_call[1] + str(body) + str(params)


def test_list_debug_tokens_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.list_debug_tokens(
            configuration.ListDebugTokensRequest(),
            parent='parent_value',
        )


def test_list_debug_tokens_pager():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Set the response as a series of pages
        response = (
            configuration.ListDebugTokensResponse(
                debug_tokens=[
                    configuration.DebugToken(),
                    configuration.DebugToken(),
                    configuration.DebugToken(),
                ],
                next_page_token='abc',
            ),
            configuration.ListDebugTokensResponse(
                debug_tokens=[],
                next_page_token='def',
            ),
            configuration.ListDebugTokensResponse(
                debug_tokens=[
                    configuration.DebugToken(),
                ],
                next_page_token='ghi',
            ),
            configuration.ListDebugTokensResponse(
                debug_tokens=[
                    configuration.DebugToken(),
                    configuration.DebugToken(),
                ],
            ),
        )
        # Two responses for two calls
        response = response + response

        # Wrap the values into proper Response objs
        response = tuple(configuration.ListDebugTokensResponse.to_json(x) for x in response)
        return_values = tuple(Response() for i in response)
        for return_val, response_val in zip(return_values, response):
            return_val._content = response_val.encode('UTF-8')
            return_val.status_code = 200
        req.side_effect = return_values

        metadata = ()
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ('parent', ''),
            )),
        )
        pager = client.list_debug_tokens(request={})

        assert pager._metadata == metadata

        results = list(pager)
        assert len(results) == 6
        assert all(isinstance(i, configuration.DebugToken)
                   for i in results)

        pages = list(client.list_debug_tokens(request={}).pages)
        for page_, token in zip(pages, ['abc','def','ghi', '']):
            assert page_.raw_page.next_page_token == token


def test_create_debug_token_rest(transport: str = 'rest', request_type=configuration.CreateDebugTokenRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.DebugToken(
            name='name_value',
            display_name='display_name_value',
            token='token_value',
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.DebugToken.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.create_debug_token(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.DebugToken)
    assert response.name == 'name_value'
    assert response.display_name == 'display_name_value'
    assert response.token == 'token_value'


def test_create_debug_token_rest_from_dict():
    test_create_debug_token_rest(request_type=dict)


def test_create_debug_token_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.DebugToken()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.DebugToken.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        debug_token = configuration.DebugToken(name='name_value')
        client.create_debug_token(
            parent='parent_value',
            debug_token=debug_token,
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'parent_value' in http_call[1] + str(body) + str(params)
        assert configuration.DebugToken.to_json(debug_token, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)


def test_create_debug_token_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.create_debug_token(
            configuration.CreateDebugTokenRequest(),
            parent='parent_value',
            debug_token=configuration.DebugToken(name='name_value'),
        )


def test_update_debug_token_rest(transport: str = 'rest', request_type=configuration.UpdateDebugTokenRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.DebugToken(
            name='name_value',
            display_name='display_name_value',
            token='token_value',
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.DebugToken.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.update_debug_token(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.DebugToken)
    assert response.name == 'name_value'
    assert response.display_name == 'display_name_value'
    assert response.token == 'token_value'


def test_update_debug_token_rest_from_dict():
    test_update_debug_token_rest(request_type=dict)


def test_update_debug_token_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.DebugToken()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.DebugToken.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        debug_token = configuration.DebugToken(name='name_value')
        update_mask = field_mask_pb2.FieldMask(paths=['paths_value'])
        client.update_debug_token(
            debug_token=debug_token,
            update_mask=update_mask,
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert configuration.DebugToken.to_json(debug_token, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)
        assert field_mask_pb2.FieldMask.to_json(update_mask, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)


def test_update_debug_token_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.update_debug_token(
            configuration.UpdateDebugTokenRequest(),
            debug_token=configuration.DebugToken(name='name_value'),
            update_mask=field_mask_pb2.FieldMask(paths=['paths_value']),
        )


def test_delete_debug_token_rest(transport: str = 'rest', request_type=configuration.DeleteDebugTokenRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = None

        # Wrap the value into a proper Response obj
        json_return_value = empty_pb2.Empty.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.delete_debug_token(request)

    # Establish that the response is the type that we expect.
    assert response is None


def test_delete_debug_token_rest_from_dict():
    test_delete_debug_token_rest(request_type=dict)


def test_delete_debug_token_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = None

        # Wrap the value into a proper Response obj
        json_return_value = empty_pb2.Empty.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.delete_debug_token(
            name='name_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'name_value' in http_call[1] + str(body) + str(params)


def test_delete_debug_token_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.delete_debug_token(
            configuration.DeleteDebugTokenRequest(),
            name='name_value',
        )


def test_get_service_rest(transport: str = 'rest', request_type=configuration.GetServiceRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.Service(
            name='name_value',
            enforcement_mode=configuration.Service.EnforcementMode.UNENFORCED,
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.Service.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.get_service(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.Service)
    assert response.name == 'name_value'
    assert response.enforcement_mode == configuration.Service.EnforcementMode.UNENFORCED


def test_get_service_rest_from_dict():
    test_get_service_rest(request_type=dict)


def test_get_service_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.Service()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.Service.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_service(
            name='name_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'name_value' in http_call[1] + str(body) + str(params)


def test_get_service_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_service(
            configuration.GetServiceRequest(),
            name='name_value',
        )


def test_list_services_rest(transport: str = 'rest', request_type=configuration.ListServicesRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.ListServicesResponse(
            services=[configuration.Service(name='name_value')],
            next_page_token='next_page_token_value',
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.ListServicesResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.list_services(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, pagers.ListServicesPager)
    assert response.services == [configuration.Service(name='name_value')]
    assert response.next_page_token == 'next_page_token_value'


def test_list_services_rest_from_dict():
    test_list_services_rest(request_type=dict)


def test_list_services_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.ListServicesResponse()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.ListServicesResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.list_services(
            parent='parent_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'parent_value' in http_call[1] + str(body) + str(params)


def test_list_services_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.list_services(
            configuration.ListServicesRequest(),
            parent='parent_value',
        )


def test_list_services_pager():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Set the response as a series of pages
        response = (
            configuration.ListServicesResponse(
                services=[
                    configuration.Service(),
                    configuration.Service(),
                    configuration.Service(),
                ],
                next_page_token='abc',
            ),
            configuration.ListServicesResponse(
                services=[],
                next_page_token='def',
            ),
            configuration.ListServicesResponse(
                services=[
                    configuration.Service(),
                ],
                next_page_token='ghi',
            ),
            configuration.ListServicesResponse(
                services=[
                    configuration.Service(),
                    configuration.Service(),
                ],
            ),
        )
        # Two responses for two calls
        response = response + response

        # Wrap the values into proper Response objs
        response = tuple(configuration.ListServicesResponse.to_json(x) for x in response)
        return_values = tuple(Response() for i in response)
        for return_val, response_val in zip(return_values, response):
            return_val._content = response_val.encode('UTF-8')
            return_val.status_code = 200
        req.side_effect = return_values

        metadata = ()
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ('parent', ''),
            )),
        )
        pager = client.list_services(request={})

        assert pager._metadata == metadata

        results = list(pager)
        assert len(results) == 6
        assert all(isinstance(i, configuration.Service)
                   for i in results)

        pages = list(client.list_services(request={}).pages)
        for page_, token in zip(pages, ['abc','def','ghi', '']):
            assert page_.raw_page.next_page_token == token


def test_update_service_rest(transport: str = 'rest', request_type=configuration.UpdateServiceRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.Service(
            name='name_value',
            enforcement_mode=configuration.Service.EnforcementMode.UNENFORCED,
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.Service.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.update_service(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.Service)
    assert response.name == 'name_value'
    assert response.enforcement_mode == configuration.Service.EnforcementMode.UNENFORCED


def test_update_service_rest_from_dict():
    test_update_service_rest(request_type=dict)


def test_update_service_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.Service()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.Service.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        service = configuration.Service(name='name_value')
        update_mask = field_mask_pb2.FieldMask(paths=['paths_value'])
        client.update_service(
            service=service,
            update_mask=update_mask,
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert configuration.Service.to_json(service, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)
        assert field_mask_pb2.FieldMask.to_json(update_mask, including_default_value_fields=False, use_integers_for_enums=False) in http_call[1] + str(body) + str(params)


def test_update_service_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.update_service(
            configuration.UpdateServiceRequest(),
            service=configuration.Service(name='name_value'),
            update_mask=field_mask_pb2.FieldMask(paths=['paths_value']),
        )


def test_batch_update_services_rest(transport: str = 'rest', request_type=configuration.BatchUpdateServicesRequest):
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.BatchUpdateServicesResponse(
            services=[configuration.Service(name='name_value')],
        )

        # Wrap the value into a proper Response obj
        json_return_value = configuration.BatchUpdateServicesResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.batch_update_services(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, configuration.BatchUpdateServicesResponse)
    assert response.services == [configuration.Service(name='name_value')]


def test_batch_update_services_rest_from_dict():
    test_batch_update_services_rest(request_type=dict)


def test_batch_update_services_rest_flattened():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = configuration.BatchUpdateServicesResponse()

        # Wrap the value into a proper Response obj
        json_return_value = configuration.BatchUpdateServicesResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.batch_update_services(
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')


def test_batch_update_services_rest_flattened_error():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.batch_update_services(
            configuration.BatchUpdateServicesRequest(),
        )


def test_credentials_transport_error():
    # It is an error to provide credentials and a transport instance.
    transport = transports.ConfigServiceRestTransport(
        credentials=ga_credentials.AnonymousCredentials(),
    )
    with pytest.raises(ValueError):
        client = ConfigServiceClient(
            credentials=ga_credentials.AnonymousCredentials(),
            transport=transport,
        )

    # It is an error to provide a credentials file and a transport instance.
    transport = transports.ConfigServiceRestTransport(
        credentials=ga_credentials.AnonymousCredentials(),
    )
    with pytest.raises(ValueError):
        client = ConfigServiceClient(
            client_options={"credentials_file": "credentials.json"},
            transport=transport,
        )

    # It is an error to provide scopes and a transport instance.
    transport = transports.ConfigServiceRestTransport(
        credentials=ga_credentials.AnonymousCredentials(),
    )
    with pytest.raises(ValueError):
        client = ConfigServiceClient(
            client_options={"scopes": ["1", "2"]},
            transport=transport,
        )


def test_transport_instance():
    # A client may be instantiated with a custom transport instance.
    transport = transports.ConfigServiceRestTransport(
        credentials=ga_credentials.AnonymousCredentials(),
    )
    client = ConfigServiceClient(transport=transport)
    assert client.transport is transport


@pytest.mark.parametrize("transport_class", [
    transports.ConfigServiceRestTransport,
])
def test_transport_adc(transport_class):
    # Test default credentials are used if not provided.
    with mock.patch.object(google.auth, 'default') as adc:
        adc.return_value = (ga_credentials.AnonymousCredentials(), None)
        transport_class()
        adc.assert_called_once()


def test_config_service_base_transport_error():
    # Passing both a credentials object and credentials_file should raise an error
    with pytest.raises(core_exceptions.DuplicateCredentialArgs):
        transport = transports.ConfigServiceTransport(
            credentials=ga_credentials.AnonymousCredentials(),
            credentials_file="credentials.json"
        )


def test_config_service_base_transport():
    # Instantiate the base transport.
    with mock.patch('google.firebase.appcheck_v1beta.services.config_service.transports.ConfigServiceTransport.__init__') as Transport:
        Transport.return_value = None
        transport = transports.ConfigServiceTransport(
            credentials=ga_credentials.AnonymousCredentials(),
        )

    # Every method on the transport should just blindly
    # raise NotImplementedError.
    methods = (
        'get_app_attest_config',
        'batch_get_app_attest_configs',
        'update_app_attest_config',
        'get_device_check_config',
        'batch_get_device_check_configs',
        'update_device_check_config',
        'get_recaptcha_config',
        'batch_get_recaptcha_configs',
        'update_recaptcha_config',
        'get_safety_net_config',
        'batch_get_safety_net_configs',
        'update_safety_net_config',
        'get_debug_token',
        'list_debug_tokens',
        'create_debug_token',
        'update_debug_token',
        'delete_debug_token',
        'get_service',
        'list_services',
        'update_service',
        'batch_update_services',
    )
    for method in methods:
        with pytest.raises(NotImplementedError):
            getattr(transport, method)(request=object())


@requires_google_auth_gte_1_25_0
def test_config_service_base_transport_with_credentials_file():
    # Instantiate the base transport with a credentials file
    with mock.patch.object(google.auth, 'load_credentials_from_file', autospec=True) as load_creds, mock.patch('google.firebase.appcheck_v1beta.services.config_service.transports.ConfigServiceTransport._prep_wrapped_messages') as Transport:
        Transport.return_value = None
        load_creds.return_value = (ga_credentials.AnonymousCredentials(), None)
        transport = transports.ConfigServiceTransport(
            credentials_file="credentials.json",
            quota_project_id="octopus",
        )
        load_creds.assert_called_once_with("credentials.json",
            scopes=None,
            default_scopes=(
            'https://www.googleapis.com/auth/cloud-platform',
            'https://www.googleapis.com/auth/firebase',
),
            quota_project_id="octopus",
        )


@requires_google_auth_lt_1_25_0
def test_config_service_base_transport_with_credentials_file_old_google_auth():
    # Instantiate the base transport with a credentials file
    with mock.patch.object(google.auth, 'load_credentials_from_file', autospec=True) as load_creds, mock.patch('google.firebase.appcheck_v1beta.services.config_service.transports.ConfigServiceTransport._prep_wrapped_messages') as Transport:
        Transport.return_value = None
        load_creds.return_value = (ga_credentials.AnonymousCredentials(), None)
        transport = transports.ConfigServiceTransport(
            credentials_file="credentials.json",
            quota_project_id="octopus",
        )
        load_creds.assert_called_once_with("credentials.json", scopes=(
            'https://www.googleapis.com/auth/cloud-platform',
            'https://www.googleapis.com/auth/firebase',
            ),
            quota_project_id="octopus",
        )


def test_config_service_base_transport_with_adc():
    # Test the default credentials are used if credentials and credentials_file are None.
    with mock.patch.object(google.auth, 'default', autospec=True) as adc, mock.patch('google.firebase.appcheck_v1beta.services.config_service.transports.ConfigServiceTransport._prep_wrapped_messages') as Transport:
        Transport.return_value = None
        adc.return_value = (ga_credentials.AnonymousCredentials(), None)
        transport = transports.ConfigServiceTransport()
        adc.assert_called_once()


@requires_google_auth_gte_1_25_0
def test_config_service_auth_adc():
    # If no credentials are provided, we should use ADC credentials.
    with mock.patch.object(google.auth, 'default', autospec=True) as adc:
        adc.return_value = (ga_credentials.AnonymousCredentials(), None)
        ConfigServiceClient()
        adc.assert_called_once_with(
            scopes=None,
            default_scopes=(
            'https://www.googleapis.com/auth/cloud-platform',
            'https://www.googleapis.com/auth/firebase',
),
            quota_project_id=None,
        )


@requires_google_auth_lt_1_25_0
def test_config_service_auth_adc_old_google_auth():
    # If no credentials are provided, we should use ADC credentials.
    with mock.patch.object(google.auth, 'default', autospec=True) as adc:
        adc.return_value = (ga_credentials.AnonymousCredentials(), None)
        ConfigServiceClient()
        adc.assert_called_once_with(
            scopes=(                'https://www.googleapis.com/auth/cloud-platform',                'https://www.googleapis.com/auth/firebase',),
            quota_project_id=None,
        )


def test_config_service_http_transport_client_cert_source_for_mtls():
    cred = ga_credentials.AnonymousCredentials()
    with mock.patch("google.auth.transport.requests.AuthorizedSession.configure_mtls_channel") as mock_configure_mtls_channel:
        transports.ConfigServiceRestTransport (
            credentials=cred,
            client_cert_source_for_mtls=client_cert_source_callback
        )
        mock_configure_mtls_channel.assert_called_once_with(client_cert_source_callback)

def test_config_service_host_no_port():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        client_options=client_options.ClientOptions(api_endpoint='firebaseappcheck.googleapis.com'),
    )
    assert client.transport._host == 'firebaseappcheck.googleapis.com:443'


def test_config_service_host_with_port():
    client = ConfigServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        client_options=client_options.ClientOptions(api_endpoint='firebaseappcheck.googleapis.com:8000'),
    )
    assert client.transport._host == 'firebaseappcheck.googleapis.com:8000'


def test_app_attest_config_path():
    project = "squid"
    app = "clam"
    expected = "projects/{project}/apps/{app}/appAttestConfig".format(project=project, app=app, )
    actual = ConfigServiceClient.app_attest_config_path(project, app)
    assert expected == actual


def test_parse_app_attest_config_path():
    expected = {
        "project": "whelk",
        "app": "octopus",
    }
    path = ConfigServiceClient.app_attest_config_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_app_attest_config_path(path)
    assert expected == actual

def test_debug_token_path():
    project = "oyster"
    app = "nudibranch"
    debug_token = "cuttlefish"
    expected = "projects/{project}/apps/{app}/debugTokens/{debug_token}".format(project=project, app=app, debug_token=debug_token, )
    actual = ConfigServiceClient.debug_token_path(project, app, debug_token)
    assert expected == actual


def test_parse_debug_token_path():
    expected = {
        "project": "mussel",
        "app": "winkle",
        "debug_token": "nautilus",
    }
    path = ConfigServiceClient.debug_token_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_debug_token_path(path)
    assert expected == actual

def test_device_check_config_path():
    project = "scallop"
    app = "abalone"
    expected = "projects/{project}/apps/{app}/deviceCheckConfig".format(project=project, app=app, )
    actual = ConfigServiceClient.device_check_config_path(project, app)
    assert expected == actual


def test_parse_device_check_config_path():
    expected = {
        "project": "squid",
        "app": "clam",
    }
    path = ConfigServiceClient.device_check_config_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_device_check_config_path(path)
    assert expected == actual

def test_recaptcha_config_path():
    project = "whelk"
    app = "octopus"
    expected = "projects/{project}/apps/{app}/recaptchaConfig".format(project=project, app=app, )
    actual = ConfigServiceClient.recaptcha_config_path(project, app)
    assert expected == actual


def test_parse_recaptcha_config_path():
    expected = {
        "project": "oyster",
        "app": "nudibranch",
    }
    path = ConfigServiceClient.recaptcha_config_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_recaptcha_config_path(path)
    assert expected == actual

def test_safety_net_config_path():
    project = "cuttlefish"
    app = "mussel"
    expected = "projects/{project}/apps/{app}/safetyNetConfig".format(project=project, app=app, )
    actual = ConfigServiceClient.safety_net_config_path(project, app)
    assert expected == actual


def test_parse_safety_net_config_path():
    expected = {
        "project": "winkle",
        "app": "nautilus",
    }
    path = ConfigServiceClient.safety_net_config_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_safety_net_config_path(path)
    assert expected == actual

def test_service_path():
    project = "scallop"
    service = "abalone"
    expected = "projects/{project}/services/{service}".format(project=project, service=service, )
    actual = ConfigServiceClient.service_path(project, service)
    assert expected == actual


def test_parse_service_path():
    expected = {
        "project": "squid",
        "service": "clam",
    }
    path = ConfigServiceClient.service_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_service_path(path)
    assert expected == actual

def test_common_billing_account_path():
    billing_account = "whelk"
    expected = "billingAccounts/{billing_account}".format(billing_account=billing_account, )
    actual = ConfigServiceClient.common_billing_account_path(billing_account)
    assert expected == actual


def test_parse_common_billing_account_path():
    expected = {
        "billing_account": "octopus",
    }
    path = ConfigServiceClient.common_billing_account_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_common_billing_account_path(path)
    assert expected == actual

def test_common_folder_path():
    folder = "oyster"
    expected = "folders/{folder}".format(folder=folder, )
    actual = ConfigServiceClient.common_folder_path(folder)
    assert expected == actual


def test_parse_common_folder_path():
    expected = {
        "folder": "nudibranch",
    }
    path = ConfigServiceClient.common_folder_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_common_folder_path(path)
    assert expected == actual

def test_common_organization_path():
    organization = "cuttlefish"
    expected = "organizations/{organization}".format(organization=organization, )
    actual = ConfigServiceClient.common_organization_path(organization)
    assert expected == actual


def test_parse_common_organization_path():
    expected = {
        "organization": "mussel",
    }
    path = ConfigServiceClient.common_organization_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_common_organization_path(path)
    assert expected == actual

def test_common_project_path():
    project = "winkle"
    expected = "projects/{project}".format(project=project, )
    actual = ConfigServiceClient.common_project_path(project)
    assert expected == actual


def test_parse_common_project_path():
    expected = {
        "project": "nautilus",
    }
    path = ConfigServiceClient.common_project_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_common_project_path(path)
    assert expected == actual

def test_common_location_path():
    project = "scallop"
    location = "abalone"
    expected = "projects/{project}/locations/{location}".format(project=project, location=location, )
    actual = ConfigServiceClient.common_location_path(project, location)
    assert expected == actual


def test_parse_common_location_path():
    expected = {
        "project": "squid",
        "location": "clam",
    }
    path = ConfigServiceClient.common_location_path(**expected)

    # Check that the path construction is reversible.
    actual = ConfigServiceClient.parse_common_location_path(path)
    assert expected == actual


def test_client_withDEFAULT_CLIENT_INFO():
    client_info = gapic_v1.client_info.ClientInfo()

    with mock.patch.object(transports.ConfigServiceTransport, '_prep_wrapped_messages') as prep:
        client = ConfigServiceClient(
            credentials=ga_credentials.AnonymousCredentials(),
            client_info=client_info,
        )
        prep.assert_called_once_with(client_info)

    with mock.patch.object(transports.ConfigServiceTransport, '_prep_wrapped_messages') as prep:
        transport_class = ConfigServiceClient.get_transport_class()
        transport = transport_class(
            credentials=ga_credentials.AnonymousCredentials(),
            client_info=client_info,
        )
        prep.assert_called_once_with(client_info)
