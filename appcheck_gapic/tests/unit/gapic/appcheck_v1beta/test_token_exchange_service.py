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
from google.firebase.appcheck_v1beta.services.token_exchange_service import TokenExchangeServiceClient
from google.firebase.appcheck_v1beta.services.token_exchange_service import transports
from google.firebase.appcheck_v1beta.services.token_exchange_service.transports.base import _GOOGLE_AUTH_VERSION
from google.firebase.appcheck_v1beta.types import token_exchange_service
from google.oauth2 import service_account
from google.protobuf import duration_pb2  # type: ignore
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

    assert TokenExchangeServiceClient._get_default_mtls_endpoint(None) is None
    assert TokenExchangeServiceClient._get_default_mtls_endpoint(api_endpoint) == api_mtls_endpoint
    assert TokenExchangeServiceClient._get_default_mtls_endpoint(api_mtls_endpoint) == api_mtls_endpoint
    assert TokenExchangeServiceClient._get_default_mtls_endpoint(sandbox_endpoint) == sandbox_mtls_endpoint
    assert TokenExchangeServiceClient._get_default_mtls_endpoint(sandbox_mtls_endpoint) == sandbox_mtls_endpoint
    assert TokenExchangeServiceClient._get_default_mtls_endpoint(non_googleapi) == non_googleapi


@pytest.mark.parametrize("client_class", [
    TokenExchangeServiceClient,
])
def test_token_exchange_service_client_from_service_account_info(client_class):
    creds = ga_credentials.AnonymousCredentials()
    with mock.patch.object(service_account.Credentials, 'from_service_account_info') as factory:
        factory.return_value = creds
        info = {"valid": True}
        client = client_class.from_service_account_info(info)
        assert client.transport._credentials == creds
        assert isinstance(client, client_class)

        assert client.transport._host == 'firebaseappcheck.googleapis.com:443'


@pytest.mark.parametrize("transport_class,transport_name", [
    (transports.TokenExchangeServiceRestTransport, "rest"),
])
def test_token_exchange_service_client_service_account_always_use_jwt(transport_class, transport_name):
    with mock.patch.object(service_account.Credentials, 'with_always_use_jwt_access', create=True) as use_jwt:
        creds = service_account.Credentials(None, None, None)
        transport = transport_class(credentials=creds, always_use_jwt_access=True)
        use_jwt.assert_called_once_with(True)

    with mock.patch.object(service_account.Credentials, 'with_always_use_jwt_access', create=True) as use_jwt:
        creds = service_account.Credentials(None, None, None)
        transport = transport_class(credentials=creds, always_use_jwt_access=False)
        use_jwt.assert_not_called()


@pytest.mark.parametrize("client_class", [
    TokenExchangeServiceClient,
])
def test_token_exchange_service_client_from_service_account_file(client_class):
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


def test_token_exchange_service_client_get_transport_class():
    transport = TokenExchangeServiceClient.get_transport_class()
    available_transports = [
        transports.TokenExchangeServiceRestTransport,
    ]
    assert transport in available_transports

    transport = TokenExchangeServiceClient.get_transport_class("rest")
    assert transport == transports.TokenExchangeServiceRestTransport


@pytest.mark.parametrize("client_class,transport_class,transport_name", [
    (TokenExchangeServiceClient, transports.TokenExchangeServiceRestTransport, "rest"),
])
@mock.patch.object(TokenExchangeServiceClient, "DEFAULT_ENDPOINT", modify_default_endpoint(TokenExchangeServiceClient))
def test_token_exchange_service_client_client_options(client_class, transport_class, transport_name):
    # Check that if channel is provided we won't create a new one.
    with mock.patch.object(TokenExchangeServiceClient, 'get_transport_class') as gtc:
        transport = transport_class(
            credentials=ga_credentials.AnonymousCredentials()
        )
        client = client_class(transport=transport)
        gtc.assert_not_called()

    # Check that if channel is provided via str we will create a new one.
    with mock.patch.object(TokenExchangeServiceClient, 'get_transport_class') as gtc:
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
    (TokenExchangeServiceClient, transports.TokenExchangeServiceRestTransport, "rest", "true"),
    (TokenExchangeServiceClient, transports.TokenExchangeServiceRestTransport, "rest", "false"),
])
@mock.patch.object(TokenExchangeServiceClient, "DEFAULT_ENDPOINT", modify_default_endpoint(TokenExchangeServiceClient))
@mock.patch.dict(os.environ, {"GOOGLE_API_USE_MTLS_ENDPOINT": "auto"})
def test_token_exchange_service_client_mtls_env_auto(client_class, transport_class, transport_name, use_client_cert_env):
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
    (TokenExchangeServiceClient, transports.TokenExchangeServiceRestTransport, "rest"),
])
def test_token_exchange_service_client_client_options_scopes(client_class, transport_class, transport_name):
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
    (TokenExchangeServiceClient, transports.TokenExchangeServiceRestTransport, "rest"),
])
def test_token_exchange_service_client_client_options_credentials_file(client_class, transport_class, transport_name):
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


def test_get_public_jwk_set_rest(transport: str = 'rest', request_type=token_exchange_service.GetPublicJwkSetRequest):
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.PublicJwkSet(
            keys=[token_exchange_service.PublicJwk(kty='kty_value')],
        )

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.PublicJwkSet.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.get_public_jwk_set(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, token_exchange_service.PublicJwkSet)
    assert response.keys == [token_exchange_service.PublicJwk(kty='kty_value')]


def test_get_public_jwk_set_rest_from_dict():
    test_get_public_jwk_set_rest(request_type=dict)


def test_get_public_jwk_set_rest_flattened():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.PublicJwkSet()

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.PublicJwkSet.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_public_jwk_set(
            name='name_value',
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')
        assert 'name_value' in http_call[1] + str(body) + str(params)


def test_get_public_jwk_set_rest_flattened_error():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_public_jwk_set(
            token_exchange_service.GetPublicJwkSetRequest(),
            name='name_value',
        )


def test_exchange_safety_net_token_rest(transport: str = 'rest', request_type=token_exchange_service.ExchangeSafetyNetTokenRequest):
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse(
            attestation_token='attestation_token_value',
            ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.exchange_safety_net_token(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, token_exchange_service.AttestationTokenResponse)
    assert response.attestation_token == 'attestation_token_value'
    assert response.ttl == duration_pb2.Duration(seconds=751)


def test_exchange_safety_net_token_rest_from_dict():
    test_exchange_safety_net_token_rest(request_type=dict)


def test_exchange_safety_net_token_rest_flattened():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse()

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.exchange_safety_net_token(
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')


def test_exchange_safety_net_token_rest_flattened_error():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.exchange_safety_net_token(
            token_exchange_service.ExchangeSafetyNetTokenRequest(),
        )


def test_exchange_device_check_token_rest(transport: str = 'rest', request_type=token_exchange_service.ExchangeDeviceCheckTokenRequest):
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse(
            attestation_token='attestation_token_value',
            ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.exchange_device_check_token(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, token_exchange_service.AttestationTokenResponse)
    assert response.attestation_token == 'attestation_token_value'
    assert response.ttl == duration_pb2.Duration(seconds=751)


def test_exchange_device_check_token_rest_from_dict():
    test_exchange_device_check_token_rest(request_type=dict)


def test_exchange_device_check_token_rest_flattened():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse()

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.exchange_device_check_token(
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')


def test_exchange_device_check_token_rest_flattened_error():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.exchange_device_check_token(
            token_exchange_service.ExchangeDeviceCheckTokenRequest(),
        )


def test_exchange_recaptcha_token_rest(transport: str = 'rest', request_type=token_exchange_service.ExchangeRecaptchaTokenRequest):
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse(
            attestation_token='attestation_token_value',
            ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.exchange_recaptcha_token(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, token_exchange_service.AttestationTokenResponse)
    assert response.attestation_token == 'attestation_token_value'
    assert response.ttl == duration_pb2.Duration(seconds=751)


def test_exchange_recaptcha_token_rest_from_dict():
    test_exchange_recaptcha_token_rest(request_type=dict)


def test_exchange_recaptcha_token_rest_flattened():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse()

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.exchange_recaptcha_token(
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')


def test_exchange_recaptcha_token_rest_flattened_error():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.exchange_recaptcha_token(
            token_exchange_service.ExchangeRecaptchaTokenRequest(),
        )


def test_exchange_custom_token_rest(transport: str = 'rest', request_type=token_exchange_service.ExchangeCustomTokenRequest):
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse(
            attestation_token='attestation_token_value',
            ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.exchange_custom_token(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, token_exchange_service.AttestationTokenResponse)
    assert response.attestation_token == 'attestation_token_value'
    assert response.ttl == duration_pb2.Duration(seconds=751)


def test_exchange_custom_token_rest_from_dict():
    test_exchange_custom_token_rest(request_type=dict)


def test_exchange_custom_token_rest_flattened():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse()

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.exchange_custom_token(
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')


def test_exchange_custom_token_rest_flattened_error():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.exchange_custom_token(
            token_exchange_service.ExchangeCustomTokenRequest(),
        )


def test_exchange_debug_token_rest(transport: str = 'rest', request_type=token_exchange_service.ExchangeDebugTokenRequest):
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse(
            attestation_token='attestation_token_value',
            ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.exchange_debug_token(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, token_exchange_service.AttestationTokenResponse)
    assert response.attestation_token == 'attestation_token_value'
    assert response.ttl == duration_pb2.Duration(seconds=751)


def test_exchange_debug_token_rest_from_dict():
    test_exchange_debug_token_rest(request_type=dict)


def test_exchange_debug_token_rest_flattened():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse()

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.exchange_debug_token(
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')


def test_exchange_debug_token_rest_flattened_error():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.exchange_debug_token(
            token_exchange_service.ExchangeDebugTokenRequest(),
        )


def test_generate_app_attest_challenge_rest(transport: str = 'rest', request_type=token_exchange_service.GenerateAppAttestChallengeRequest):
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AppAttestChallengeResponse(
            challenge=b'challenge_blob',
            ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AppAttestChallengeResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.generate_app_attest_challenge(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, token_exchange_service.AppAttestChallengeResponse)
    assert response.challenge == b'challenge_blob'
    assert response.ttl == duration_pb2.Duration(seconds=751)


def test_generate_app_attest_challenge_rest_from_dict():
    test_generate_app_attest_challenge_rest(request_type=dict)


def test_generate_app_attest_challenge_rest_flattened():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AppAttestChallengeResponse()

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AppAttestChallengeResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.generate_app_attest_challenge(
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')


def test_generate_app_attest_challenge_rest_flattened_error():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.generate_app_attest_challenge(
            token_exchange_service.GenerateAppAttestChallengeRequest(),
        )


def test_exchange_app_attest_attestation_rest(transport: str = 'rest', request_type=token_exchange_service.ExchangeAppAttestAttestationRequest):
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.ExchangeAppAttestAttestationResponse(
            artifact=b'artifact_blob',
            attestation_token=token_exchange_service.AttestationTokenResponse(attestation_token='attestation_token_value'),
        )

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.ExchangeAppAttestAttestationResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.exchange_app_attest_attestation(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, token_exchange_service.ExchangeAppAttestAttestationResponse)
    assert response.artifact == b'artifact_blob'
    assert response.attestation_token == token_exchange_service.AttestationTokenResponse(attestation_token='attestation_token_value')


def test_exchange_app_attest_attestation_rest_from_dict():
    test_exchange_app_attest_attestation_rest(request_type=dict)


def test_exchange_app_attest_attestation_rest_flattened():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.ExchangeAppAttestAttestationResponse()

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.ExchangeAppAttestAttestationResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.exchange_app_attest_attestation(
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')


def test_exchange_app_attest_attestation_rest_flattened_error():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.exchange_app_attest_attestation(
            token_exchange_service.ExchangeAppAttestAttestationRequest(),
        )


def test_exchange_app_attest_assertion_rest(transport: str = 'rest', request_type=token_exchange_service.ExchangeAppAttestAssertionRequest):
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse(
            attestation_token='attestation_token_value',
            ttl=duration_pb2.Duration(seconds=751),
        )

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value
        response = client.exchange_app_attest_assertion(request)

    # Establish that the response is the type that we expect.
    assert isinstance(response, token_exchange_service.AttestationTokenResponse)
    assert response.attestation_token == 'attestation_token_value'
    assert response.ttl == duration_pb2.Duration(seconds=751)


def test_exchange_app_attest_assertion_rest_from_dict():
    test_exchange_app_attest_assertion_rest(request_type=dict)


def test_exchange_app_attest_assertion_rest_flattened():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Mock the http request call within the method and fake a response.
    with mock.patch.object(Session, 'request') as req:
        # Designate an appropriate value for the returned response.
        return_value = token_exchange_service.AttestationTokenResponse()

        # Wrap the value into a proper Response obj
        json_return_value = token_exchange_service.AttestationTokenResponse.to_json(return_value)
        response_value = Response()
        response_value.status_code = 200
        response_value._content = json_return_value.encode('UTF-8')
        req.return_value = response_value

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.exchange_app_attest_assertion(
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(req.mock_calls) == 1
        _, http_call, http_params = req.mock_calls[0]
        body = http_params.get('data')
        params = http_params.get('params')


def test_exchange_app_attest_assertion_rest_flattened_error():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.exchange_app_attest_assertion(
            token_exchange_service.ExchangeAppAttestAssertionRequest(),
        )


def test_credentials_transport_error():
    # It is an error to provide credentials and a transport instance.
    transport = transports.TokenExchangeServiceRestTransport(
        credentials=ga_credentials.AnonymousCredentials(),
    )
    with pytest.raises(ValueError):
        client = TokenExchangeServiceClient(
            credentials=ga_credentials.AnonymousCredentials(),
            transport=transport,
        )

    # It is an error to provide a credentials file and a transport instance.
    transport = transports.TokenExchangeServiceRestTransport(
        credentials=ga_credentials.AnonymousCredentials(),
    )
    with pytest.raises(ValueError):
        client = TokenExchangeServiceClient(
            client_options={"credentials_file": "credentials.json"},
            transport=transport,
        )

    # It is an error to provide scopes and a transport instance.
    transport = transports.TokenExchangeServiceRestTransport(
        credentials=ga_credentials.AnonymousCredentials(),
    )
    with pytest.raises(ValueError):
        client = TokenExchangeServiceClient(
            client_options={"scopes": ["1", "2"]},
            transport=transport,
        )


def test_transport_instance():
    # A client may be instantiated with a custom transport instance.
    transport = transports.TokenExchangeServiceRestTransport(
        credentials=ga_credentials.AnonymousCredentials(),
    )
    client = TokenExchangeServiceClient(transport=transport)
    assert client.transport is transport


@pytest.mark.parametrize("transport_class", [
    transports.TokenExchangeServiceRestTransport,
])
def test_transport_adc(transport_class):
    # Test default credentials are used if not provided.
    with mock.patch.object(google.auth, 'default') as adc:
        adc.return_value = (ga_credentials.AnonymousCredentials(), None)
        transport_class()
        adc.assert_called_once()


def test_token_exchange_service_base_transport_error():
    # Passing both a credentials object and credentials_file should raise an error
    with pytest.raises(core_exceptions.DuplicateCredentialArgs):
        transport = transports.TokenExchangeServiceTransport(
            credentials=ga_credentials.AnonymousCredentials(),
            credentials_file="credentials.json"
        )


def test_token_exchange_service_base_transport():
    # Instantiate the base transport.
    with mock.patch('google.firebase.appcheck_v1beta.services.token_exchange_service.transports.TokenExchangeServiceTransport.__init__') as Transport:
        Transport.return_value = None
        transport = transports.TokenExchangeServiceTransport(
            credentials=ga_credentials.AnonymousCredentials(),
        )

    # Every method on the transport should just blindly
    # raise NotImplementedError.
    methods = (
        'get_public_jwk_set',
        'exchange_safety_net_token',
        'exchange_device_check_token',
        'exchange_recaptcha_token',
        'exchange_custom_token',
        'exchange_debug_token',
        'generate_app_attest_challenge',
        'exchange_app_attest_attestation',
        'exchange_app_attest_assertion',
    )
    for method in methods:
        with pytest.raises(NotImplementedError):
            getattr(transport, method)(request=object())


@requires_google_auth_gte_1_25_0
def test_token_exchange_service_base_transport_with_credentials_file():
    # Instantiate the base transport with a credentials file
    with mock.patch.object(google.auth, 'load_credentials_from_file', autospec=True) as load_creds, mock.patch('google.firebase.appcheck_v1beta.services.token_exchange_service.transports.TokenExchangeServiceTransport._prep_wrapped_messages') as Transport:
        Transport.return_value = None
        load_creds.return_value = (ga_credentials.AnonymousCredentials(), None)
        transport = transports.TokenExchangeServiceTransport(
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
def test_token_exchange_service_base_transport_with_credentials_file_old_google_auth():
    # Instantiate the base transport with a credentials file
    with mock.patch.object(google.auth, 'load_credentials_from_file', autospec=True) as load_creds, mock.patch('google.firebase.appcheck_v1beta.services.token_exchange_service.transports.TokenExchangeServiceTransport._prep_wrapped_messages') as Transport:
        Transport.return_value = None
        load_creds.return_value = (ga_credentials.AnonymousCredentials(), None)
        transport = transports.TokenExchangeServiceTransport(
            credentials_file="credentials.json",
            quota_project_id="octopus",
        )
        load_creds.assert_called_once_with("credentials.json", scopes=(
            'https://www.googleapis.com/auth/cloud-platform',
            'https://www.googleapis.com/auth/firebase',
            ),
            quota_project_id="octopus",
        )


def test_token_exchange_service_base_transport_with_adc():
    # Test the default credentials are used if credentials and credentials_file are None.
    with mock.patch.object(google.auth, 'default', autospec=True) as adc, mock.patch('google.firebase.appcheck_v1beta.services.token_exchange_service.transports.TokenExchangeServiceTransport._prep_wrapped_messages') as Transport:
        Transport.return_value = None
        adc.return_value = (ga_credentials.AnonymousCredentials(), None)
        transport = transports.TokenExchangeServiceTransport()
        adc.assert_called_once()


@requires_google_auth_gte_1_25_0
def test_token_exchange_service_auth_adc():
    # If no credentials are provided, we should use ADC credentials.
    with mock.patch.object(google.auth, 'default', autospec=True) as adc:
        adc.return_value = (ga_credentials.AnonymousCredentials(), None)
        TokenExchangeServiceClient()
        adc.assert_called_once_with(
            scopes=None,
            default_scopes=(
            'https://www.googleapis.com/auth/cloud-platform',
            'https://www.googleapis.com/auth/firebase',
),
            quota_project_id=None,
        )


@requires_google_auth_lt_1_25_0
def test_token_exchange_service_auth_adc_old_google_auth():
    # If no credentials are provided, we should use ADC credentials.
    with mock.patch.object(google.auth, 'default', autospec=True) as adc:
        adc.return_value = (ga_credentials.AnonymousCredentials(), None)
        TokenExchangeServiceClient()
        adc.assert_called_once_with(
            scopes=(                'https://www.googleapis.com/auth/cloud-platform',                'https://www.googleapis.com/auth/firebase',),
            quota_project_id=None,
        )


def test_token_exchange_service_http_transport_client_cert_source_for_mtls():
    cred = ga_credentials.AnonymousCredentials()
    with mock.patch("google.auth.transport.requests.AuthorizedSession.configure_mtls_channel") as mock_configure_mtls_channel:
        transports.TokenExchangeServiceRestTransport (
            credentials=cred,
            client_cert_source_for_mtls=client_cert_source_callback
        )
        mock_configure_mtls_channel.assert_called_once_with(client_cert_source_callback)

def test_token_exchange_service_host_no_port():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        client_options=client_options.ClientOptions(api_endpoint='firebaseappcheck.googleapis.com'),
    )
    assert client.transport._host == 'firebaseappcheck.googleapis.com:443'


def test_token_exchange_service_host_with_port():
    client = TokenExchangeServiceClient(
        credentials=ga_credentials.AnonymousCredentials(),
        client_options=client_options.ClientOptions(api_endpoint='firebaseappcheck.googleapis.com:8000'),
    )
    assert client.transport._host == 'firebaseappcheck.googleapis.com:8000'


def test_public_jwk_set_path():
    expected = "jwks".format()
    actual = TokenExchangeServiceClient.public_jwk_set_path()
    assert expected == actual


def test_parse_public_jwk_set_path():
    expected = {
    }
    path = TokenExchangeServiceClient.public_jwk_set_path(**expected)

    # Check that the path construction is reversible.
    actual = TokenExchangeServiceClient.parse_public_jwk_set_path(path)
    assert expected == actual

def test_common_billing_account_path():
    billing_account = "squid"
    expected = "billingAccounts/{billing_account}".format(billing_account=billing_account, )
    actual = TokenExchangeServiceClient.common_billing_account_path(billing_account)
    assert expected == actual


def test_parse_common_billing_account_path():
    expected = {
        "billing_account": "clam",
    }
    path = TokenExchangeServiceClient.common_billing_account_path(**expected)

    # Check that the path construction is reversible.
    actual = TokenExchangeServiceClient.parse_common_billing_account_path(path)
    assert expected == actual

def test_common_folder_path():
    folder = "whelk"
    expected = "folders/{folder}".format(folder=folder, )
    actual = TokenExchangeServiceClient.common_folder_path(folder)
    assert expected == actual


def test_parse_common_folder_path():
    expected = {
        "folder": "octopus",
    }
    path = TokenExchangeServiceClient.common_folder_path(**expected)

    # Check that the path construction is reversible.
    actual = TokenExchangeServiceClient.parse_common_folder_path(path)
    assert expected == actual

def test_common_organization_path():
    organization = "oyster"
    expected = "organizations/{organization}".format(organization=organization, )
    actual = TokenExchangeServiceClient.common_organization_path(organization)
    assert expected == actual


def test_parse_common_organization_path():
    expected = {
        "organization": "nudibranch",
    }
    path = TokenExchangeServiceClient.common_organization_path(**expected)

    # Check that the path construction is reversible.
    actual = TokenExchangeServiceClient.parse_common_organization_path(path)
    assert expected == actual

def test_common_project_path():
    project = "cuttlefish"
    expected = "projects/{project}".format(project=project, )
    actual = TokenExchangeServiceClient.common_project_path(project)
    assert expected == actual


def test_parse_common_project_path():
    expected = {
        "project": "mussel",
    }
    path = TokenExchangeServiceClient.common_project_path(**expected)

    # Check that the path construction is reversible.
    actual = TokenExchangeServiceClient.parse_common_project_path(path)
    assert expected == actual

def test_common_location_path():
    project = "winkle"
    location = "nautilus"
    expected = "projects/{project}/locations/{location}".format(project=project, location=location, )
    actual = TokenExchangeServiceClient.common_location_path(project, location)
    assert expected == actual


def test_parse_common_location_path():
    expected = {
        "project": "scallop",
        "location": "abalone",
    }
    path = TokenExchangeServiceClient.common_location_path(**expected)

    # Check that the path construction is reversible.
    actual = TokenExchangeServiceClient.parse_common_location_path(path)
    assert expected == actual


def test_client_withDEFAULT_CLIENT_INFO():
    client_info = gapic_v1.client_info.ClientInfo()

    with mock.patch.object(transports.TokenExchangeServiceTransport, '_prep_wrapped_messages') as prep:
        client = TokenExchangeServiceClient(
            credentials=ga_credentials.AnonymousCredentials(),
            client_info=client_info,
        )
        prep.assert_called_once_with(client_info)

    with mock.patch.object(transports.TokenExchangeServiceTransport, '_prep_wrapped_messages') as prep:
        transport_class = TokenExchangeServiceClient.get_transport_class()
        transport = transport_class(
            credentials=ga_credentials.AnonymousCredentials(),
            client_info=client_info,
        )
        prep.assert_called_once_with(client_info)
