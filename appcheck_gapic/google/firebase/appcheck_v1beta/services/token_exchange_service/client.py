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
from collections import OrderedDict
from distutils import util
import os
import re
from typing import Callable, Dict, Optional, Sequence, Tuple, Type, Union
import pkg_resources

from google.api_core import client_options as client_options_lib  # type: ignore
from google.api_core import exceptions as core_exceptions         # type: ignore
from google.api_core import gapic_v1                              # type: ignore
from google.api_core import retry as retries                      # type: ignore
from google.auth import credentials as ga_credentials             # type: ignore
from google.auth.transport import mtls                            # type: ignore
from google.auth.transport.grpc import SslCredentials             # type: ignore
from google.auth.exceptions import MutualTLSChannelError          # type: ignore
from google.oauth2 import service_account                         # type: ignore

from google.firebase.appcheck_v1beta.types import token_exchange_service
from google.protobuf import duration_pb2  # type: ignore
from .transports.base import TokenExchangeServiceTransport, DEFAULT_CLIENT_INFO
from .transports.rest import TokenExchangeServiceRestTransport


class TokenExchangeServiceClientMeta(type):
    """Metaclass for the TokenExchangeService client.

    This provides class-level methods for building and retrieving
    support objects (e.g. transport) without polluting the client instance
    objects.
    """
    _transport_registry = OrderedDict()  # type: Dict[str, Type[TokenExchangeServiceTransport]]
    _transport_registry["rest"] = TokenExchangeServiceRestTransport

    def get_transport_class(cls,
            label: str = None,
        ) -> Type[TokenExchangeServiceTransport]:
        """Returns an appropriate transport class.

        Args:
            label: The name of the desired transport. If none is
                provided, then the first transport in the registry is used.

        Returns:
            The transport class to use.
        """
        # If a specific transport is requested, return that one.
        if label:
            return cls._transport_registry[label]

        # No transport is requested; return the default (that is, the first one
        # in the dictionary).
        return next(iter(cls._transport_registry.values()))


class TokenExchangeServiceClient(metaclass=TokenExchangeServiceClientMeta):
    """A service to validate certification material issued to apps by app
    or device attestation providers, and exchange them for *App Check
    tokens* (see
    [AttestationTokenResponse][google.firebase.appcheck.v1beta.AttestationTokenResponse]),
    used to access Firebase services protected by App Check.
    """

    @staticmethod
    def _get_default_mtls_endpoint(api_endpoint):
        """Converts api endpoint to mTLS endpoint.

        Convert "*.sandbox.googleapis.com" and "*.googleapis.com" to
        "*.mtls.sandbox.googleapis.com" and "*.mtls.googleapis.com" respectively.
        Args:
            api_endpoint (Optional[str]): the api endpoint to convert.
        Returns:
            str: converted mTLS api endpoint.
        """
        if not api_endpoint:
            return api_endpoint

        mtls_endpoint_re = re.compile(
            r"(?P<name>[^.]+)(?P<mtls>\.mtls)?(?P<sandbox>\.sandbox)?(?P<googledomain>\.googleapis\.com)?"
        )

        m = mtls_endpoint_re.match(api_endpoint)
        name, mtls, sandbox, googledomain = m.groups()
        if mtls or not googledomain:
            return api_endpoint

        if sandbox:
            return api_endpoint.replace(
                "sandbox.googleapis.com", "mtls.sandbox.googleapis.com"
            )

        return api_endpoint.replace(".googleapis.com", ".mtls.googleapis.com")

    DEFAULT_ENDPOINT = "firebaseappcheck.googleapis.com"
    DEFAULT_MTLS_ENDPOINT = _get_default_mtls_endpoint.__func__(  # type: ignore
        DEFAULT_ENDPOINT
    )

    @classmethod
    def from_service_account_info(cls, info: dict, *args, **kwargs):
        """Creates an instance of this client using the provided credentials
            info.

        Args:
            info (dict): The service account private key info.
            args: Additional arguments to pass to the constructor.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            TokenExchangeServiceClient: The constructed client.
        """
        credentials = service_account.Credentials.from_service_account_info(info)
        kwargs["credentials"] = credentials
        return cls(*args, **kwargs)

    @classmethod
    def from_service_account_file(cls, filename: str, *args, **kwargs):
        """Creates an instance of this client using the provided credentials
            file.

        Args:
            filename (str): The path to the service account private key json
                file.
            args: Additional arguments to pass to the constructor.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            TokenExchangeServiceClient: The constructed client.
        """
        credentials = service_account.Credentials.from_service_account_file(
            filename)
        kwargs["credentials"] = credentials
        return cls(*args, **kwargs)

    from_service_account_json = from_service_account_file

    @property
    def transport(self) -> TokenExchangeServiceTransport:
        """Returns the transport used by the client instance.

        Returns:
            TokenExchangeServiceTransport: The transport used by the client
                instance.
        """
        return self._transport

    @staticmethod
    def public_jwk_set_path() -> str:
        """Returns a fully-qualified public_jwk_set string."""
        return "jwks".format()

    @staticmethod
    def parse_public_jwk_set_path(path: str) -> Dict[str,str]:
        """Parses a public_jwk_set path into its component segments."""
        m = re.match(r"^jwks$", path)
        return m.groupdict() if m else {}

    @staticmethod
    def common_billing_account_path(billing_account: str, ) -> str:
        """Returns a fully-qualified billing_account string."""
        return "billingAccounts/{billing_account}".format(billing_account=billing_account, )

    @staticmethod
    def parse_common_billing_account_path(path: str) -> Dict[str,str]:
        """Parse a billing_account path into its component segments."""
        m = re.match(r"^billingAccounts/(?P<billing_account>.+?)$", path)
        return m.groupdict() if m else {}

    @staticmethod
    def common_folder_path(folder: str, ) -> str:
        """Returns a fully-qualified folder string."""
        return "folders/{folder}".format(folder=folder, )

    @staticmethod
    def parse_common_folder_path(path: str) -> Dict[str,str]:
        """Parse a folder path into its component segments."""
        m = re.match(r"^folders/(?P<folder>.+?)$", path)
        return m.groupdict() if m else {}

    @staticmethod
    def common_organization_path(organization: str, ) -> str:
        """Returns a fully-qualified organization string."""
        return "organizations/{organization}".format(organization=organization, )

    @staticmethod
    def parse_common_organization_path(path: str) -> Dict[str,str]:
        """Parse a organization path into its component segments."""
        m = re.match(r"^organizations/(?P<organization>.+?)$", path)
        return m.groupdict() if m else {}

    @staticmethod
    def common_project_path(project: str, ) -> str:
        """Returns a fully-qualified project string."""
        return "projects/{project}".format(project=project, )

    @staticmethod
    def parse_common_project_path(path: str) -> Dict[str,str]:
        """Parse a project path into its component segments."""
        m = re.match(r"^projects/(?P<project>.+?)$", path)
        return m.groupdict() if m else {}

    @staticmethod
    def common_location_path(project: str, location: str, ) -> str:
        """Returns a fully-qualified location string."""
        return "projects/{project}/locations/{location}".format(project=project, location=location, )

    @staticmethod
    def parse_common_location_path(path: str) -> Dict[str,str]:
        """Parse a location path into its component segments."""
        m = re.match(r"^projects/(?P<project>.+?)/locations/(?P<location>.+?)$", path)
        return m.groupdict() if m else {}

    def __init__(self, *,
            credentials: Optional[ga_credentials.Credentials] = None,
            transport: Union[str, TokenExchangeServiceTransport, None] = None,
            client_options: Optional[client_options_lib.ClientOptions] = None,
            client_info: gapic_v1.client_info.ClientInfo = DEFAULT_CLIENT_INFO,
            ) -> None:
        """Instantiates the token exchange service client.

        Args:
            credentials (Optional[google.auth.credentials.Credentials]): The
                authorization credentials to attach to requests. These
                credentials identify the application to the service; if none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
            transport (Union[str, TokenExchangeServiceTransport]): The
                transport to use. If set to None, a transport is chosen
                automatically.
            client_options (google.api_core.client_options.ClientOptions): Custom options for the
                client. It won't take effect if a ``transport`` instance is provided.
                (1) The ``api_endpoint`` property can be used to override the
                default endpoint provided by the client. GOOGLE_API_USE_MTLS_ENDPOINT
                environment variable can also be used to override the endpoint:
                "always" (always use the default mTLS endpoint), "never" (always
                use the default regular endpoint) and "auto" (auto switch to the
                default mTLS endpoint if client certificate is present, this is
                the default value). However, the ``api_endpoint`` property takes
                precedence if provided.
                (2) If GOOGLE_API_USE_CLIENT_CERTIFICATE environment variable
                is "true", then the ``client_cert_source`` property can be used
                to provide client certificate for mutual TLS transport. If
                not provided, the default SSL client certificate will be used if
                present. If GOOGLE_API_USE_CLIENT_CERTIFICATE is "false" or not
                set, no client certificate will be used.
            client_info (google.api_core.gapic_v1.client_info.ClientInfo):
                The client info used to send a user-agent string along with
                API requests. If ``None``, then default info will be used.
                Generally, you only need to set this if you're developing
                your own client library.

        Raises:
            google.auth.exceptions.MutualTLSChannelError: If mutual TLS transport
                creation failed for any reason.
        """
        if isinstance(client_options, dict):
            client_options = client_options_lib.from_dict(client_options)
        if client_options is None:
            client_options = client_options_lib.ClientOptions()

        # Create SSL credentials for mutual TLS if needed.
        use_client_cert = bool(util.strtobool(os.getenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")))

        client_cert_source_func = None
        is_mtls = False
        if use_client_cert:
            if client_options.client_cert_source:
                is_mtls = True
                client_cert_source_func = client_options.client_cert_source
            else:
                is_mtls = mtls.has_default_client_cert_source()
                if is_mtls:
                    client_cert_source_func = mtls.default_client_cert_source()
                else:
                    client_cert_source_func = None

        # Figure out which api endpoint to use.
        if client_options.api_endpoint is not None:
            api_endpoint = client_options.api_endpoint
        else:
            use_mtls_env = os.getenv("GOOGLE_API_USE_MTLS_ENDPOINT", "auto")
            if use_mtls_env == "never":
                api_endpoint = self.DEFAULT_ENDPOINT
            elif use_mtls_env == "always":
                api_endpoint = self.DEFAULT_MTLS_ENDPOINT
            elif use_mtls_env == "auto":
                if is_mtls:
                    api_endpoint = self.DEFAULT_MTLS_ENDPOINT
                else:
                    api_endpoint = self.DEFAULT_ENDPOINT
            else:
                raise MutualTLSChannelError(
                    "Unsupported GOOGLE_API_USE_MTLS_ENDPOINT value. Accepted "
                    "values: never, auto, always"
                )

        # Save or instantiate the transport.
        # Ordinarily, we provide the transport, but allowing a custom transport
        # instance provides an extensibility point for unusual situations.
        if isinstance(transport, TokenExchangeServiceTransport):
            # transport is a TokenExchangeServiceTransport instance.
            if credentials or client_options.credentials_file:
                raise ValueError("When providing a transport instance, "
                                 "provide its credentials directly.")
            if client_options.scopes:
                raise ValueError(
                    "When providing a transport instance, provide its scopes "
                    "directly."
                )
            self._transport = transport
        else:
            Transport = type(self).get_transport_class(transport)
            self._transport = Transport(
                credentials=credentials,
                credentials_file=client_options.credentials_file,
                host=api_endpoint,
                scopes=client_options.scopes,
                client_cert_source_for_mtls=client_cert_source_func,
                quota_project_id=client_options.quota_project_id,
                client_info=client_info,
            )

    def get_public_jwk_set(self,
            request: token_exchange_service.GetPublicJwkSetRequest = None,
            *,
            name: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.PublicJwkSet:
        r"""Returns a public JWK set as specified by `RFC
        7517 <https://tools.ietf.org/html/rfc7517>`__ that can be used
        to verify App Check tokens. Exactly one of the public keys in
        the returned set will successfully validate any App Check token
        that is currently valid.

        Args:
            request (google.firebase.appcheck_v1beta.types.GetPublicJwkSetRequest):
                The request object. Request message for the
                [GetPublicJwkSet][] method.
            name (str):
                Required. The relative resource name to the public JWK
                set. Must always be exactly the string ``jwks``.

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.PublicJwkSet:
                The currently active set of public keys that can be used to verify App Check
                   tokens.

                   This object is a JWK set as specified by [section 5
                   of RFC
                   7517](\ https://tools.ietf.org/html/rfc7517#section-5).

                   For security, the response **must not** be cached for
                   longer than one day.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a token_exchange_service.GetPublicJwkSetRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, token_exchange_service.GetPublicJwkSetRequest):
            request = token_exchange_service.GetPublicJwkSetRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.get_public_jwk_set]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("name", request.name),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # Done; return the response.
        return response

    def exchange_safety_net_token(self,
            request: token_exchange_service.ExchangeSafetyNetTokenRequest = None,
            *,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Validates a `SafetyNet
        token <https://developer.android.com/training/safetynet/attestation#request-attestation-step>`__.
        If valid, returns an App Check token encapsulated in an
        [AttestationTokenResponse][google.firebase.appcheck.v1beta.AttestationTokenResponse].

        Args:
            request (google.firebase.appcheck_v1beta.types.ExchangeSafetyNetTokenRequest):
                The request object. Request message for the
                [ExchangeSafetyNetToken][] method.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to access Firebase services
                   protected by App Check.

        """
        # Create or coerce a protobuf request object.
        # Minor optimization to avoid making a copy if the user passes
        # in a token_exchange_service.ExchangeSafetyNetTokenRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, token_exchange_service.ExchangeSafetyNetTokenRequest):
            request = token_exchange_service.ExchangeSafetyNetTokenRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.exchange_safety_net_token]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("app", request.app),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # Done; return the response.
        return response

    def exchange_device_check_token(self,
            request: token_exchange_service.ExchangeDeviceCheckTokenRequest = None,
            *,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Accepts a
        ```device_token`` <https://developer.apple.com/documentation/devicecheck/dcdevice>`__
        issued by DeviceCheck, and attempts to validate it with Apple.
        If valid, returns an App Check token encapsulated in an
        [AttestationTokenResponse][google.firebase.appcheck.v1beta.AttestationTokenResponse].

        Args:
            request (google.firebase.appcheck_v1beta.types.ExchangeDeviceCheckTokenRequest):
                The request object. Request message for the
                [ExchangeDeviceCheckToken][] method.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to access Firebase services
                   protected by App Check.

        """
        # Create or coerce a protobuf request object.
        # Minor optimization to avoid making a copy if the user passes
        # in a token_exchange_service.ExchangeDeviceCheckTokenRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, token_exchange_service.ExchangeDeviceCheckTokenRequest):
            request = token_exchange_service.ExchangeDeviceCheckTokenRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.exchange_device_check_token]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("app", request.app),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # Done; return the response.
        return response

    def exchange_recaptcha_token(self,
            request: token_exchange_service.ExchangeRecaptchaTokenRequest = None,
            *,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Validates a `reCAPTCHA v3 response
        token <https://developers.google.com/recaptcha/docs/v3>`__. If
        valid, returns an App Check token encapsulated in an
        [AttestationTokenResponse][google.firebase.appcheck.v1beta.AttestationTokenResponse].

        Args:
            request (google.firebase.appcheck_v1beta.types.ExchangeRecaptchaTokenRequest):
                The request object. Request message for the
                [ExchangeRecaptchaToken][] method.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to access Firebase services
                   protected by App Check.

        """
        # Create or coerce a protobuf request object.
        # Minor optimization to avoid making a copy if the user passes
        # in a token_exchange_service.ExchangeRecaptchaTokenRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, token_exchange_service.ExchangeRecaptchaTokenRequest):
            request = token_exchange_service.ExchangeRecaptchaTokenRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.exchange_recaptcha_token]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("app", request.app),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # Done; return the response.
        return response

    def exchange_custom_token(self,
            request: token_exchange_service.ExchangeCustomTokenRequest = None,
            *,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Validates a custom token signed using your project's Admin SDK
        service account credentials. If valid, returns an App Check
        token encapsulated in an
        [AttestationTokenResponse][google.firebase.appcheck.v1beta.AttestationTokenResponse].

        Args:
            request (google.firebase.appcheck_v1beta.types.ExchangeCustomTokenRequest):
                The request object. Request message for the
                [ExchangeCustomToken][] method.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to access Firebase services
                   protected by App Check.

        """
        # Create or coerce a protobuf request object.
        # Minor optimization to avoid making a copy if the user passes
        # in a token_exchange_service.ExchangeCustomTokenRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, token_exchange_service.ExchangeCustomTokenRequest):
            request = token_exchange_service.ExchangeCustomTokenRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.exchange_custom_token]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("app", request.app),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # Done; return the response.
        return response

    def exchange_debug_token(self,
            request: token_exchange_service.ExchangeDebugTokenRequest = None,
            *,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Validates a debug token secret that you have previously created
        using
        [CreateDebugToken][google.firebase.appcheck.v1beta.ConfigService.CreateDebugToken].
        If valid, returns an App Check token encapsulated in an
        [AttestationTokenResponse][google.firebase.appcheck.v1beta.AttestationTokenResponse].

        Note that a restrictive quota is enforced on this method to
        prevent accidental exposure of the app to abuse.

        Args:
            request (google.firebase.appcheck_v1beta.types.ExchangeDebugTokenRequest):
                The request object. Request message for the
                [ExchangeDebugToken][] method.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to access Firebase services
                   protected by App Check.

        """
        # Create or coerce a protobuf request object.
        # Minor optimization to avoid making a copy if the user passes
        # in a token_exchange_service.ExchangeDebugTokenRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, token_exchange_service.ExchangeDebugTokenRequest):
            request = token_exchange_service.ExchangeDebugTokenRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.exchange_debug_token]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("app", request.app),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # Done; return the response.
        return response

    def generate_app_attest_challenge(self,
            request: token_exchange_service.GenerateAppAttestChallengeRequest = None,
            *,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AppAttestChallengeResponse:
        r"""Initiates the App Attest flow by generating a
        challenge which will be used as a type of nonce for this
        attestation.

        Args:
            request (google.firebase.appcheck_v1beta.types.GenerateAppAttestChallengeRequest):
                The request object. Request message for
                GenerateAppAttestChallenge
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.AppAttestChallengeResponse:
                Response object for
                GenerateAppAttestChallenge

        """
        # Create or coerce a protobuf request object.
        # Minor optimization to avoid making a copy if the user passes
        # in a token_exchange_service.GenerateAppAttestChallengeRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, token_exchange_service.GenerateAppAttestChallengeRequest):
            request = token_exchange_service.GenerateAppAttestChallengeRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.generate_app_attest_challenge]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("app", request.app),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # Done; return the response.
        return response

    def exchange_app_attest_attestation(self,
            request: token_exchange_service.ExchangeAppAttestAttestationRequest = None,
            *,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.ExchangeAppAttestAttestationResponse:
        r"""Accepts a AppAttest CBOR Attestation, and uses the
        developer's preconfigured team and bundle IDs to verify
        the token with Apple. Returns an Attestation Artifact
        that can later be exchanged for an AttestationToken in
        ExchangeAppAttestAssertion.

        Args:
            request (google.firebase.appcheck_v1beta.types.ExchangeAppAttestAttestationRequest):
                The request object. Request message for
                ExchangeAppAttestAttestation
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.ExchangeAppAttestAttestationResponse:
                Response message for
                ExchangeAppAttestAttestation and
                ExchangeAppAttestDebugAttestation

        """
        # Create or coerce a protobuf request object.
        # Minor optimization to avoid making a copy if the user passes
        # in a token_exchange_service.ExchangeAppAttestAttestationRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, token_exchange_service.ExchangeAppAttestAttestationRequest):
            request = token_exchange_service.ExchangeAppAttestAttestationRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.exchange_app_attest_attestation]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("app", request.app),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # Done; return the response.
        return response

    def exchange_app_attest_assertion(self,
            request: token_exchange_service.ExchangeAppAttestAssertionRequest = None,
            *,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Accepts a AppAttest Artifact and Assertion, and uses the
        developer's preconfigured auth token to verify the token with
        Apple. Returns an AttestationToken with the App ID as specified
        by the ``app`` field included as attested claims.

        Args:
            request (google.firebase.appcheck_v1beta.types.ExchangeAppAttestAssertionRequest):
                The request object. Request message for
                ExchangeAppAttestAssertion
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to access Firebase services
                   protected by App Check.

        """
        # Create or coerce a protobuf request object.
        # Minor optimization to avoid making a copy if the user passes
        # in a token_exchange_service.ExchangeAppAttestAssertionRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, token_exchange_service.ExchangeAppAttestAssertionRequest):
            request = token_exchange_service.ExchangeAppAttestAssertionRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.exchange_app_attest_assertion]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("app", request.app),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # Done; return the response.
        return response





try:
    DEFAULT_CLIENT_INFO = gapic_v1.client_info.ClientInfo(
        gapic_version=pkg_resources.get_distribution(
            "google-firebase-appcheck",
        ).version,
    )
except pkg_resources.DistributionNotFound:
    DEFAULT_CLIENT_INFO = gapic_v1.client_info.ClientInfo()


__all__ = (
    "TokenExchangeServiceClient",
)
