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

from google.firebase.appcheck_v1beta.services.config_service import pagers
from google.firebase.appcheck_v1beta.types import configuration
from google.protobuf import duration_pb2  # type: ignore
from google.protobuf import field_mask_pb2  # type: ignore
from .transports.base import ConfigServiceTransport, DEFAULT_CLIENT_INFO
from .transports.rest import ConfigServiceRestTransport


class ConfigServiceClientMeta(type):
    """Metaclass for the ConfigService client.

    This provides class-level methods for building and retrieving
    support objects (e.g. transport) without polluting the client instance
    objects.
    """
    _transport_registry = OrderedDict()  # type: Dict[str, Type[ConfigServiceTransport]]
    _transport_registry["rest"] = ConfigServiceRestTransport

    def get_transport_class(cls,
            label: str = None,
        ) -> Type[ConfigServiceTransport]:
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


class ConfigServiceClient(metaclass=ConfigServiceClientMeta):
    """Manages configuration parameters used by the
    [TokenExchangeService][google.firebase.appcheck.v1beta.TokenExchangeService]
    and enforcement settings for Firebase services protected by App
    Check.
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
            ConfigServiceClient: The constructed client.
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
            ConfigServiceClient: The constructed client.
        """
        credentials = service_account.Credentials.from_service_account_file(
            filename)
        kwargs["credentials"] = credentials
        return cls(*args, **kwargs)

    from_service_account_json = from_service_account_file

    @property
    def transport(self) -> ConfigServiceTransport:
        """Returns the transport used by the client instance.

        Returns:
            ConfigServiceTransport: The transport used by the client
                instance.
        """
        return self._transport

    @staticmethod
    def app_attest_config_path(project: str,app: str,) -> str:
        """Returns a fully-qualified app_attest_config string."""
        return "projects/{project}/apps/{app}/appAttestConfig".format(project=project, app=app, )

    @staticmethod
    def parse_app_attest_config_path(path: str) -> Dict[str,str]:
        """Parses a app_attest_config path into its component segments."""
        m = re.match(r"^projects/(?P<project>.+?)/apps/(?P<app>.+?)/appAttestConfig$", path)
        return m.groupdict() if m else {}

    @staticmethod
    def debug_token_path(project: str,app: str,debug_token: str,) -> str:
        """Returns a fully-qualified debug_token string."""
        return "projects/{project}/apps/{app}/debugTokens/{debug_token}".format(project=project, app=app, debug_token=debug_token, )

    @staticmethod
    def parse_debug_token_path(path: str) -> Dict[str,str]:
        """Parses a debug_token path into its component segments."""
        m = re.match(r"^projects/(?P<project>.+?)/apps/(?P<app>.+?)/debugTokens/(?P<debug_token>.+?)$", path)
        return m.groupdict() if m else {}

    @staticmethod
    def device_check_config_path(project: str,app: str,) -> str:
        """Returns a fully-qualified device_check_config string."""
        return "projects/{project}/apps/{app}/deviceCheckConfig".format(project=project, app=app, )

    @staticmethod
    def parse_device_check_config_path(path: str) -> Dict[str,str]:
        """Parses a device_check_config path into its component segments."""
        m = re.match(r"^projects/(?P<project>.+?)/apps/(?P<app>.+?)/deviceCheckConfig$", path)
        return m.groupdict() if m else {}

    @staticmethod
    def recaptcha_config_path(project: str,app: str,) -> str:
        """Returns a fully-qualified recaptcha_config string."""
        return "projects/{project}/apps/{app}/recaptchaConfig".format(project=project, app=app, )

    @staticmethod
    def parse_recaptcha_config_path(path: str) -> Dict[str,str]:
        """Parses a recaptcha_config path into its component segments."""
        m = re.match(r"^projects/(?P<project>.+?)/apps/(?P<app>.+?)/recaptchaConfig$", path)
        return m.groupdict() if m else {}

    @staticmethod
    def safety_net_config_path(project: str,app: str,) -> str:
        """Returns a fully-qualified safety_net_config string."""
        return "projects/{project}/apps/{app}/safetyNetConfig".format(project=project, app=app, )

    @staticmethod
    def parse_safety_net_config_path(path: str) -> Dict[str,str]:
        """Parses a safety_net_config path into its component segments."""
        m = re.match(r"^projects/(?P<project>.+?)/apps/(?P<app>.+?)/safetyNetConfig$", path)
        return m.groupdict() if m else {}

    @staticmethod
    def service_path(project: str,service: str,) -> str:
        """Returns a fully-qualified service string."""
        return "projects/{project}/services/{service}".format(project=project, service=service, )

    @staticmethod
    def parse_service_path(path: str) -> Dict[str,str]:
        """Parses a service path into its component segments."""
        m = re.match(r"^projects/(?P<project>.+?)/services/(?P<service>.+?)$", path)
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
            transport: Union[str, ConfigServiceTransport, None] = None,
            client_options: Optional[client_options_lib.ClientOptions] = None,
            client_info: gapic_v1.client_info.ClientInfo = DEFAULT_CLIENT_INFO,
            ) -> None:
        """Instantiates the config service client.

        Args:
            credentials (Optional[google.auth.credentials.Credentials]): The
                authorization credentials to attach to requests. These
                credentials identify the application to the service; if none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
            transport (Union[str, ConfigServiceTransport]): The
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
        if isinstance(transport, ConfigServiceTransport):
            # transport is a ConfigServiceTransport instance.
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

    def get_app_attest_config(self,
            request: configuration.GetAppAttestConfigRequest = None,
            *,
            name: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.AppAttestConfig:
        r"""Gets the
        [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]
        for the specified app.

        Args:
            request (google.firebase.appcheck_v1beta.types.GetAppAttestConfigRequest):
                The request object. Request message for the
                [GetAppAttestConfig][google.firebase.appcheck.v1beta.ConfigService.GetAppAttestConfig]
                method.
            name (str):
                Required. The relative resource name of the
                [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig],
                in the format:

                ::

                   projects/{project_number}/apps/{app_id}/appAttestConfig

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.AppAttestConfig:
                An app's App Attest configuration object. This configuration controls certain
                   properties of the [App Check
                   token][google.firebase.appcheck.v1beta.AttestationTokenResponse]
                   returned by
                   [ExchangeAppAttestAttestation][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeAppAttestAttestation]
                   and
                   [ExchangeAppAttestAttestation][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeAppAttestAssertion],
                   such as its
                   [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                   Note that the Team ID registered with your app is
                   used as part of the validation process. Please
                   register it via the Firebase Console or
                   programmatically via the [Firebase Management
                   Service](\ https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.iosApps/patch).

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.GetAppAttestConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.GetAppAttestConfigRequest):
            request = configuration.GetAppAttestConfigRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.get_app_attest_config]

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

    def batch_get_app_attest_configs(self,
            request: configuration.BatchGetAppAttestConfigsRequest = None,
            *,
            parent: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.BatchGetAppAttestConfigsResponse:
        r"""Gets the
        [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]s
        for the specified list of apps atomically.

        Args:
            request (google.firebase.appcheck_v1beta.types.BatchGetAppAttestConfigsRequest):
                The request object. Request message for the
                [BatchGetAppAttestConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetAppAttestConfigs]
                method.
            parent (str):
                Required. The parent project name shared by all
                [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]s
                being retrieved, in the format

                ::

                   projects/{project_number}

                The parent collection in the ``name`` field of any
                resource being retrieved must match this field, or the
                entire batch fails.

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.BatchGetAppAttestConfigsResponse:
                Response message for the
                   [BatchGetAppAttestConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetAppAttestConfigs]
                   method.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.BatchGetAppAttestConfigsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.BatchGetAppAttestConfigsRequest):
            request = configuration.BatchGetAppAttestConfigsRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.batch_get_app_attest_configs]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("parent", request.parent),
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

    def update_app_attest_config(self,
            request: configuration.UpdateAppAttestConfigRequest = None,
            *,
            app_attest_config: configuration.AppAttestConfig = None,
            update_mask: field_mask_pb2.FieldMask = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.AppAttestConfig:
        r"""Updates the
        [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]
        for the specified app.

        While this configuration is incomplete or invalid, the app will
        be unable to exchange AppAttest tokens for App Check tokens.

        Args:
            request (google.firebase.appcheck_v1beta.types.UpdateAppAttestConfigRequest):
                The request object. Request message for the
                [UpdateAppAttestConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateAppAttestConfig]
                method.
            app_attest_config (google.firebase.appcheck_v1beta.types.AppAttestConfig):
                Required. The
                [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]
                to update.

                The
                [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]'s
                ``name`` field is used to identify the configuration to
                be updated, in the format:

                ::

                   projects/{project_number}/apps/{app_id}/appAttestConfig

                This corresponds to the ``app_attest_config`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (google.protobuf.field_mask_pb2.FieldMask):
                Required. A comma-separated list of names of fields in
                the
                [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]
                Gets to update. Example: ``token_ttl``.

                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.AppAttestConfig:
                An app's App Attest configuration object. This configuration controls certain
                   properties of the [App Check
                   token][google.firebase.appcheck.v1beta.AttestationTokenResponse]
                   returned by
                   [ExchangeAppAttestAttestation][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeAppAttestAttestation]
                   and
                   [ExchangeAppAttestAttestation][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeAppAttestAssertion],
                   such as its
                   [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                   Note that the Team ID registered with your app is
                   used as part of the validation process. Please
                   register it via the Firebase Console or
                   programmatically via the [Firebase Management
                   Service](\ https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.iosApps/patch).

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([app_attest_config, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.UpdateAppAttestConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.UpdateAppAttestConfigRequest):
            request = configuration.UpdateAppAttestConfigRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if app_attest_config is not None:
                request.app_attest_config = app_attest_config
            if update_mask is not None:
                request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.update_app_attest_config]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("app_attest_config.name", request.app_attest_config.name),
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

    def get_device_check_config(self,
            request: configuration.GetDeviceCheckConfigRequest = None,
            *,
            name: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.DeviceCheckConfig:
        r"""Gets the
        [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]
        for the specified app.

        For security reasons, the
        [``private_key``][google.firebase.appcheck.v1beta.DeviceCheckConfig.private_key]
        field is never populated in the response.

        Args:
            request (google.firebase.appcheck_v1beta.types.GetDeviceCheckConfigRequest):
                The request object. Request message for the
                [GetDeviceCheckConfig][google.firebase.appcheck.v1beta.ConfigService.GetDeviceCheckConfig]
                method.
            name (str):
                Required. The relative resource name of the
                [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig],
                in the format:

                ::

                   projects/{project_number}/apps/{app_id}/deviceCheckConfig

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.DeviceCheckConfig:
                An app's DeviceCheck configuration object. This configuration is used by
                   [ExchangeDeviceCheckToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeDeviceCheckToken]
                   to validate device tokens issued to apps by
                   DeviceCheck. It also controls certain properties of
                   the returned [App Check
                   token][google.firebase.appcheck.v1beta.AttestationTokenResponse],
                   such as its
                   [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                   Note that the Team ID registered with your app is
                   used as part of the validation process. Please
                   register it via the Firebase Console or
                   programmatically via the [Firebase Management
                   Service](\ https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.iosApps/patch).

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.GetDeviceCheckConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.GetDeviceCheckConfigRequest):
            request = configuration.GetDeviceCheckConfigRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.get_device_check_config]

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

    def batch_get_device_check_configs(self,
            request: configuration.BatchGetDeviceCheckConfigsRequest = None,
            *,
            parent: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.BatchGetDeviceCheckConfigsResponse:
        r"""Gets the
        [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]s
        for the specified list of apps atomically.

        For security reasons, the
        [``private_key``][google.firebase.appcheck.v1beta.DeviceCheckConfig.private_key]
        field is never populated in the response.

        Args:
            request (google.firebase.appcheck_v1beta.types.BatchGetDeviceCheckConfigsRequest):
                The request object. Request message for the
                [BatchGetDeviceCheckConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetDeviceCheckConfigs]
                method.
            parent (str):
                Required. The parent project name shared by all
                [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]s
                being retrieved, in the format

                ::

                   projects/{project_number}

                The parent collection in the ``name`` field of any
                resource being retrieved must match this field, or the
                entire batch fails.

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.BatchGetDeviceCheckConfigsResponse:
                Response message for the
                   [BatchGetDeviceCheckConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetDeviceCheckConfigs]
                   method.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.BatchGetDeviceCheckConfigsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.BatchGetDeviceCheckConfigsRequest):
            request = configuration.BatchGetDeviceCheckConfigsRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.batch_get_device_check_configs]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("parent", request.parent),
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

    def update_device_check_config(self,
            request: configuration.UpdateDeviceCheckConfigRequest = None,
            *,
            device_check_config: configuration.DeviceCheckConfig = None,
            update_mask: field_mask_pb2.FieldMask = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.DeviceCheckConfig:
        r"""Updates the
        [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]
        for the specified app.

        While this configuration is incomplete or invalid, the app will
        be unable to exchange DeviceCheck tokens for App Check tokens.

        For security reasons, the
        [``private_key``][google.firebase.appcheck.v1beta.DeviceCheckConfig.private_key]
        field is never populated in the response.

        Args:
            request (google.firebase.appcheck_v1beta.types.UpdateDeviceCheckConfigRequest):
                The request object. Request message for the
                [UpdateDeviceCheckConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateDeviceCheckConfig]
                method.
            device_check_config (google.firebase.appcheck_v1beta.types.DeviceCheckConfig):
                Required. The
                [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]
                to update.

                The
                [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]'s
                ``name`` field is used to identify the configuration to
                be updated, in the format:

                ::

                   projects/{project_number}/apps/{app_id}/deviceCheckConfig

                This corresponds to the ``device_check_config`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (google.protobuf.field_mask_pb2.FieldMask):
                Required. A comma-separated list of names of fields in
                the
                [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]
                Gets to update. Example: ``key_id,private_key``.

                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.DeviceCheckConfig:
                An app's DeviceCheck configuration object. This configuration is used by
                   [ExchangeDeviceCheckToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeDeviceCheckToken]
                   to validate device tokens issued to apps by
                   DeviceCheck. It also controls certain properties of
                   the returned [App Check
                   token][google.firebase.appcheck.v1beta.AttestationTokenResponse],
                   such as its
                   [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                   Note that the Team ID registered with your app is
                   used as part of the validation process. Please
                   register it via the Firebase Console or
                   programmatically via the [Firebase Management
                   Service](\ https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.iosApps/patch).

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([device_check_config, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.UpdateDeviceCheckConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.UpdateDeviceCheckConfigRequest):
            request = configuration.UpdateDeviceCheckConfigRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if device_check_config is not None:
                request.device_check_config = device_check_config
            if update_mask is not None:
                request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.update_device_check_config]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("device_check_config.name", request.device_check_config.name),
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

    def get_recaptcha_config(self,
            request: configuration.GetRecaptchaConfigRequest = None,
            *,
            name: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.RecaptchaConfig:
        r"""Gets the
        [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]
        for the specified app.

        For security reasons, the
        [``site_secret``][google.firebase.appcheck.v1beta.RecaptchaConfig.site_secret]
        field is never populated in the response.

        Args:
            request (google.firebase.appcheck_v1beta.types.GetRecaptchaConfigRequest):
                The request object. Request message for the
                [GetRecaptchaConfig][google.firebase.appcheck.v1beta.ConfigService.GetRecaptchaConfig]
                method.
            name (str):
                Required. The relative resource name of the
                [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig],
                in the format:

                ::

                   projects/{project_number}/apps/{app_id}/recaptchaConfig

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.RecaptchaConfig:
                An app's reCAPTCHA v3 configuration object. This configuration is used by
                   [ExchangeRecaptchaToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeRecaptchaToken]
                   to validate reCAPTCHA tokens issued to apps by
                   reCAPTCHA v3. It also controls certain properties of
                   the returned [App Check
                   token][google.firebase.appcheck.v1beta.AttestationTokenResponse],
                   such as its
                   [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.GetRecaptchaConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.GetRecaptchaConfigRequest):
            request = configuration.GetRecaptchaConfigRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.get_recaptcha_config]

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

    def batch_get_recaptcha_configs(self,
            request: configuration.BatchGetRecaptchaConfigsRequest = None,
            *,
            parent: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.BatchGetRecaptchaConfigsResponse:
        r"""Gets the
        [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]s
        for the specified list of apps atomically.

        For security reasons, the
        [``site_secret``][google.firebase.appcheck.v1beta.RecaptchaConfig.site_secret]
        field is never populated in the response.

        Args:
            request (google.firebase.appcheck_v1beta.types.BatchGetRecaptchaConfigsRequest):
                The request object. Request message for the
                [BatchGetRecaptchaConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetRecaptchaConfigs]
                method.
            parent (str):
                Required. The parent project name shared by all
                [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]s
                being retrieved, in the format

                ::

                   projects/{project_number}

                The parent collection in the ``name`` field of any
                resource being retrieved must match this field, or the
                entire batch fails.

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.BatchGetRecaptchaConfigsResponse:
                Response message for the
                   [BatchGetRecaptchaConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetRecaptchaConfigs]
                   method.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.BatchGetRecaptchaConfigsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.BatchGetRecaptchaConfigsRequest):
            request = configuration.BatchGetRecaptchaConfigsRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.batch_get_recaptcha_configs]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("parent", request.parent),
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

    def update_recaptcha_config(self,
            request: configuration.UpdateRecaptchaConfigRequest = None,
            *,
            recaptcha_config: configuration.RecaptchaConfig = None,
            update_mask: field_mask_pb2.FieldMask = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.RecaptchaConfig:
        r"""Updates the
        [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]
        for the specified app.

        While this configuration is incomplete or invalid, the app will
        be unable to exchange reCAPTCHA tokens for App Check tokens.

        For security reasons, the
        [``site_secret``][google.firebase.appcheck.v1beta.RecaptchaConfig.site_secret]
        field is never populated in the response.

        Args:
            request (google.firebase.appcheck_v1beta.types.UpdateRecaptchaConfigRequest):
                The request object. Request message for the
                [UpdateRecaptchaConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateRecaptchaConfig]
                method.
            recaptcha_config (google.firebase.appcheck_v1beta.types.RecaptchaConfig):
                Required. The
                [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]
                to update.

                The
                [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]'s
                ``name`` field is used to identify the configuration to
                be updated, in the format:

                ::

                   projects/{project_number}/apps/{app_id}/recaptchaConfig

                This corresponds to the ``recaptcha_config`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (google.protobuf.field_mask_pb2.FieldMask):
                Required. A comma-separated list of names of fields in
                the
                [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]
                to update. Example: ``site_secret``.

                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.RecaptchaConfig:
                An app's reCAPTCHA v3 configuration object. This configuration is used by
                   [ExchangeRecaptchaToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeRecaptchaToken]
                   to validate reCAPTCHA tokens issued to apps by
                   reCAPTCHA v3. It also controls certain properties of
                   the returned [App Check
                   token][google.firebase.appcheck.v1beta.AttestationTokenResponse],
                   such as its
                   [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([recaptcha_config, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.UpdateRecaptchaConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.UpdateRecaptchaConfigRequest):
            request = configuration.UpdateRecaptchaConfigRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if recaptcha_config is not None:
                request.recaptcha_config = recaptcha_config
            if update_mask is not None:
                request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.update_recaptcha_config]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("recaptcha_config.name", request.recaptcha_config.name),
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

    def get_safety_net_config(self,
            request: configuration.GetSafetyNetConfigRequest = None,
            *,
            name: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.SafetyNetConfig:
        r"""Gets the
        [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]
        for the specified app.

        Args:
            request (google.firebase.appcheck_v1beta.types.GetSafetyNetConfigRequest):
                The request object. Request message for the
                [GetSafetyNetConfig][google.firebase.appcheck.v1beta.ConfigService.GetSafetyNetConfig]
                method.
            name (str):
                Required. The relative resource name of the
                [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig],
                in the format:

                ::

                   projects/{project_number}/apps/{app_id}/safetyNetConfig

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.SafetyNetConfig:
                An app's SafetyNet configuration object. This configuration controls certain
                   properties of the [App Check
                   token][google.firebase.appcheck.v1beta.AttestationTokenResponse]
                   returned by
                   [ExchangeSafetyNetToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeSafetyNetToken],
                   such as its
                   [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                   Note that your registered SHA-256 certificate
                   fingerprints are used to validate tokens issued by
                   SafetyNet; please register them via the Firebase
                   Console or programmatically via the [Firebase
                   Management
                   Service](\ https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.androidApps.sha/create).

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.GetSafetyNetConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.GetSafetyNetConfigRequest):
            request = configuration.GetSafetyNetConfigRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.get_safety_net_config]

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

    def batch_get_safety_net_configs(self,
            request: configuration.BatchGetSafetyNetConfigsRequest = None,
            *,
            parent: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.BatchGetSafetyNetConfigsResponse:
        r"""Gets the
        [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]s
        for the specified list of apps atomically.

        Args:
            request (google.firebase.appcheck_v1beta.types.BatchGetSafetyNetConfigsRequest):
                The request object. Request message for the
                [BatchGetSafetyNetConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetSafetyNetConfigs]
                method.
            parent (str):
                Required. The parent project name shared by all
                [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]s
                being retrieved, in the format

                ::

                   projects/{project_number}

                The parent collection in the ``name`` field of any
                resource being retrieved must match this field, or the
                entire batch fails.

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.BatchGetSafetyNetConfigsResponse:
                Response message for the
                   [BatchGetSafetyNetConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetSafetyNetConfigs]
                   method.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.BatchGetSafetyNetConfigsRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.BatchGetSafetyNetConfigsRequest):
            request = configuration.BatchGetSafetyNetConfigsRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.batch_get_safety_net_configs]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("parent", request.parent),
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

    def update_safety_net_config(self,
            request: configuration.UpdateSafetyNetConfigRequest = None,
            *,
            safety_net_config: configuration.SafetyNetConfig = None,
            update_mask: field_mask_pb2.FieldMask = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.SafetyNetConfig:
        r"""Updates the
        [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]
        for the specified app.

        While this configuration is incomplete or invalid, the app will
        be unable to exchange SafetyNet tokens for App Check tokens.

        Args:
            request (google.firebase.appcheck_v1beta.types.UpdateSafetyNetConfigRequest):
                The request object. Request message for the
                [UpdateSafetyNetConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateSafetyNetConfig]
                method.
            safety_net_config (google.firebase.appcheck_v1beta.types.SafetyNetConfig):
                Required. The
                [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]
                to update.

                The
                [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]'s
                ``name`` field is used to identify the configuration to
                be updated, in the format:

                ::

                   projects/{project_number}/apps/{app_id}/safetyNetConfig

                This corresponds to the ``safety_net_config`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (google.protobuf.field_mask_pb2.FieldMask):
                Required. A comma-separated list of names of fields in
                the
                [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]
                Gets to update. Example: ``token_ttl``.

                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.SafetyNetConfig:
                An app's SafetyNet configuration object. This configuration controls certain
                   properties of the [App Check
                   token][google.firebase.appcheck.v1beta.AttestationTokenResponse]
                   returned by
                   [ExchangeSafetyNetToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeSafetyNetToken],
                   such as its
                   [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                   Note that your registered SHA-256 certificate
                   fingerprints are used to validate tokens issued by
                   SafetyNet; please register them via the Firebase
                   Console or programmatically via the [Firebase
                   Management
                   Service](\ https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.androidApps.sha/create).

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([safety_net_config, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.UpdateSafetyNetConfigRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.UpdateSafetyNetConfigRequest):
            request = configuration.UpdateSafetyNetConfigRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if safety_net_config is not None:
                request.safety_net_config = safety_net_config
            if update_mask is not None:
                request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.update_safety_net_config]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("safety_net_config.name", request.safety_net_config.name),
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

    def get_debug_token(self,
            request: configuration.GetDebugTokenRequest = None,
            *,
            name: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.DebugToken:
        r"""Gets the specified
        [DebugToken][google.firebase.appcheck.v1beta.DebugToken].

        For security reasons, the
        [``token``][google.firebase.appcheck.v1beta.DebugToken.token]
        field is never populated in the response.

        Args:
            request (google.firebase.appcheck_v1beta.types.GetDebugTokenRequest):
                The request object. Request message for the
                [GetDebugToken][google.firebase.appcheck.v1beta.ConfigService.GetDebugToken]
                method.
            name (str):
                Required. The relative resource name of the debug token,
                in the format:

                ::

                   projects/{project_number}/apps/{app_id}/debugTokens/{debug_token_id}

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.DebugToken:
                A *debug token* is a secret used during the development or integration
                   testing of an app. It essentially allows the
                   development or integration testing to bypass app
                   attestation while still allowing App Check to enforce
                   protection on supported production Firebase services.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.GetDebugTokenRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.GetDebugTokenRequest):
            request = configuration.GetDebugTokenRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.get_debug_token]

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

    def list_debug_tokens(self,
            request: configuration.ListDebugTokensRequest = None,
            *,
            parent: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> pagers.ListDebugTokensPager:
        r"""Lists all
        [DebugToken][google.firebase.appcheck.v1beta.DebugToken]s for
        the specified app.

        For security reasons, the
        [``token``][google.firebase.appcheck.v1beta.DebugToken.token]
        field is never populated in the response.

        Args:
            request (google.firebase.appcheck_v1beta.types.ListDebugTokensRequest):
                The request object. Request message for the
                [ListDebugTokens][google.firebase.appcheck.v1beta.ConfigService.ListDebugTokens]
                method.
            parent (str):
                Required. The relative resource name of the parent app
                for which to list each associated
                [DebugToken][google.firebase.appcheck.v1beta.DebugToken],
                in the format:

                ::

                   projects/{project_number}/apps/{app_id}

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.services.config_service.pagers.ListDebugTokensPager:
                Response message for the
                   [ListDebugTokens][google.firebase.appcheck.v1beta.ConfigService.ListDebugTokens]
                   method.

                Iterating over this object will yield results and
                resolve additional pages automatically.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.ListDebugTokensRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.ListDebugTokensRequest):
            request = configuration.ListDebugTokensRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.list_debug_tokens]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("parent", request.parent),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # This method is paged; wrap the response in a pager, which provides
        # an `__iter__` convenience method.
        response = pagers.ListDebugTokensPager(
            method=rpc,
            request=request,
            response=response,
            metadata=metadata,
        )

        # Done; return the response.
        return response

    def create_debug_token(self,
            request: configuration.CreateDebugTokenRequest = None,
            *,
            parent: str = None,
            debug_token: configuration.DebugToken = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.DebugToken:
        r"""Creates a new
        [DebugToken][google.firebase.appcheck.v1beta.DebugToken] for the
        specified app.

        For security reasons, after the creation operation completes,
        the
        [``token``][google.firebase.appcheck.v1beta.DebugToken.token]
        field cannot be updated or retrieved, but you can revoke the
        debug token using
        [DeleteDebugToken][google.firebase.appcheck.v1beta.ConfigService.DeleteDebugToken].

        Each app can have a maximum of 20 debug tokens.

        Args:
            request (google.firebase.appcheck_v1beta.types.CreateDebugTokenRequest):
                The request object. Request message for the
                [CreateDebugToken][google.firebase.appcheck.v1beta.ConfigService.CreateDebugToken]
                method.
            parent (str):
                Required. The relative resource name of the parent app
                in which the specified
                [DebugToken][google.firebase.appcheck.v1beta.DebugToken]
                will be created, in the format:

                ::

                   projects/{project_number}/apps/{app_id}

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            debug_token (google.firebase.appcheck_v1beta.types.DebugToken):
                Required. The
                [DebugToken][google.firebase.appcheck.v1beta.DebugToken]
                to create.

                For security reasons, after creation, the ``token``
                field of the
                [DebugToken][google.firebase.appcheck.v1beta.DebugToken]
                will never be populated in any response.

                This corresponds to the ``debug_token`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.DebugToken:
                A *debug token* is a secret used during the development or integration
                   testing of an app. It essentially allows the
                   development or integration testing to bypass app
                   attestation while still allowing App Check to enforce
                   protection on supported production Firebase services.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent, debug_token])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.CreateDebugTokenRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.CreateDebugTokenRequest):
            request = configuration.CreateDebugTokenRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if parent is not None:
                request.parent = parent
            if debug_token is not None:
                request.debug_token = debug_token

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.create_debug_token]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("parent", request.parent),
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

    def update_debug_token(self,
            request: configuration.UpdateDebugTokenRequest = None,
            *,
            debug_token: configuration.DebugToken = None,
            update_mask: field_mask_pb2.FieldMask = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.DebugToken:
        r"""Updates the specified
        [DebugToken][google.firebase.appcheck.v1beta.DebugToken].

        For security reasons, the
        [``token``][google.firebase.appcheck.v1beta.DebugToken.token]
        field cannot be updated, nor will it be populated in the
        response, but you can revoke the debug token using
        [DeleteDebugToken][google.firebase.appcheck.v1beta.ConfigService.DeleteDebugToken].

        Args:
            request (google.firebase.appcheck_v1beta.types.UpdateDebugTokenRequest):
                The request object. Request message for the
                [UpdateDebugToken][google.firebase.appcheck.v1beta.ConfigService.UpdateDebugToken]
                method.
            debug_token (google.firebase.appcheck_v1beta.types.DebugToken):
                Required. The
                [DebugToken][google.firebase.appcheck.v1beta.DebugToken]
                to update.

                The
                [DebugToken][google.firebase.appcheck.v1beta.DebugToken]'s
                ``name`` field is used to identify the
                [DebugToken][google.firebase.appcheck.v1beta.DebugToken]
                to be updated, in the format:

                ::

                   projects/{project_number}/apps/{app_id}/debugTokens/{debug_token_id}

                This corresponds to the ``debug_token`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (google.protobuf.field_mask_pb2.FieldMask):
                Required. A comma-separated list of names of fields in
                the
                [DebugToken][google.firebase.appcheck.v1beta.DebugToken]
                to update. Example: ``display_name``.

                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.DebugToken:
                A *debug token* is a secret used during the development or integration
                   testing of an app. It essentially allows the
                   development or integration testing to bypass app
                   attestation while still allowing App Check to enforce
                   protection on supported production Firebase services.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([debug_token, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.UpdateDebugTokenRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.UpdateDebugTokenRequest):
            request = configuration.UpdateDebugTokenRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if debug_token is not None:
                request.debug_token = debug_token
            if update_mask is not None:
                request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.update_debug_token]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("debug_token.name", request.debug_token.name),
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

    def delete_debug_token(self,
            request: configuration.DeleteDebugTokenRequest = None,
            *,
            name: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> None:
        r"""Deletes the specified
        [DebugToken][google.firebase.appcheck.v1beta.DebugToken].

        A deleted debug token cannot be used to exchange for an App
        Check token. Use this method when you suspect the secret
        [``token``][google.firebase.appcheck.v1beta.DebugToken.token]
        has been compromised or when you no longer need the debug token.

        Args:
            request (google.firebase.appcheck_v1beta.types.DeleteDebugTokenRequest):
                The request object. Request message for the
                [DeleteDebugToken][google.firebase.appcheck.v1beta.ConfigService.DeleteDebugToken]
                method.
            name (str):
                Required. The relative resource name of the
                [DebugToken][google.firebase.appcheck.v1beta.DebugToken]
                to delete, in the format:

                ::

                   projects/{project_number}/apps/{app_id}/debugTokens/{debug_token_id}

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.
        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.DeleteDebugTokenRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.DeleteDebugTokenRequest):
            request = configuration.DeleteDebugTokenRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.delete_debug_token]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("name", request.name),
            )),
        )

        # Send the request.
        rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

    def get_service(self,
            request: configuration.GetServiceRequest = None,
            *,
            name: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.Service:
        r"""Gets the [Service][google.firebase.appcheck.v1beta.Service]
        configuration for the specified service name.

        Args:
            request (google.firebase.appcheck_v1beta.types.GetServiceRequest):
                The request object. Request message for the
                [GetService][google.firebase.appcheck.v1beta.ConfigService.GetService]
                method.
            name (str):
                Required. The relative resource name of the
                [Service][google.firebase.appcheck.v1beta.Service] to
                retrieve, in the format:

                ::

                   projects/{project_number}/services/{service_id}

                Note that the ``service_id`` element must be a supported
                service ID. Currently, the following service IDs are
                supported:

                -  ``firebasestorage.googleapis.com`` (Cloud Storage for
                   Firebase)
                -  ``firebasedatabase.googleapis.com`` (Firebase
                   Realtime Database)

                This corresponds to the ``name`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.Service:
                The enforcement configuration for a
                Firebase service supported by App Check.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([name])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.GetServiceRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.GetServiceRequest):
            request = configuration.GetServiceRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if name is not None:
                request.name = name

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.get_service]

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

    def list_services(self,
            request: configuration.ListServicesRequest = None,
            *,
            parent: str = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> pagers.ListServicesPager:
        r"""Lists all [Service][google.firebase.appcheck.v1beta.Service]
        configurations for the specified project.

        Only [Service][google.firebase.appcheck.v1beta.Service]s which
        were explicitly configured using
        [UpdateService][google.firebase.appcheck.v1beta.ConfigService.UpdateService]
        or
        [BatchUpdateServices][google.firebase.appcheck.v1beta.ConfigService.BatchUpdateServices]
        will be returned.

        Args:
            request (google.firebase.appcheck_v1beta.types.ListServicesRequest):
                The request object. Request message for the
                [ListServices][google.firebase.appcheck.v1beta.ConfigService.ListServices]
                method.
            parent (str):
                Required. The relative resource name of the parent
                project for which to list each associated
                [Service][google.firebase.appcheck.v1beta.Service], in
                the format:

                ::

                   projects/{project_number}

                This corresponds to the ``parent`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.services.config_service.pagers.ListServicesPager:
                Response message for the
                   [ListServices][google.firebase.appcheck.v1beta.ConfigService.ListServices]
                   method.

                Iterating over this object will yield results and
                resolve additional pages automatically.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([parent])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.ListServicesRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.ListServicesRequest):
            request = configuration.ListServicesRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if parent is not None:
                request.parent = parent

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.list_services]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("parent", request.parent),
            )),
        )

        # Send the request.
        response = rpc(
            request,
            retry=retry,
            timeout=timeout,
            metadata=metadata,
        )

        # This method is paged; wrap the response in a pager, which provides
        # an `__iter__` convenience method.
        response = pagers.ListServicesPager(
            method=rpc,
            request=request,
            response=response,
            metadata=metadata,
        )

        # Done; return the response.
        return response

    def update_service(self,
            request: configuration.UpdateServiceRequest = None,
            *,
            service: configuration.Service = None,
            update_mask: field_mask_pb2.FieldMask = None,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.Service:
        r"""Updates the specified
        [Service][google.firebase.appcheck.v1beta.Service]
        configuration.

        Args:
            request (google.firebase.appcheck_v1beta.types.UpdateServiceRequest):
                The request object. Request message for the
                [UpdateService][google.firebase.appcheck.v1beta.ConfigService.UpdateService]
                method as well as an individual update message for the
                [BatchUpdateServices][google.firebase.appcheck.v1beta.ConfigService.BatchUpdateServices]
                method.
            service (google.firebase.appcheck_v1beta.types.Service):
                Required. The
                [Service][google.firebase.appcheck.v1beta.Service] to
                update.

                The [Service][google.firebase.appcheck.v1beta.Service]'s
                ``name`` field is used to identify the
                [Service][google.firebase.appcheck.v1beta.Service] to be
                updated, in the format:

                ::

                   projects/{project_number}/services/{service_id}

                Note that the ``service_id`` element must be a supported
                service ID. Currently, the following service IDs are
                supported:

                -  ``firebasestorage.googleapis.com`` (Cloud Storage for
                   Firebase)
                -  ``firebasedatabase.googleapis.com`` (Firebase
                   Realtime Database)

                This corresponds to the ``service`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            update_mask (google.protobuf.field_mask_pb2.FieldMask):
                Required. A comma-separated list of names of fields in
                the [Service][google.firebase.appcheck.v1beta.Service]
                to update. Example: ``enforcement_mode``.

                This corresponds to the ``update_mask`` field
                on the ``request`` instance; if ``request`` is provided, this
                should not be set.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.Service:
                The enforcement configuration for a
                Firebase service supported by App Check.

        """
        # Create or coerce a protobuf request object.
        # Sanity check: If we got a request object, we should *not* have
        # gotten any keyword arguments that map to the request.
        has_flattened_params = any([service, update_mask])
        if request is not None and has_flattened_params:
            raise ValueError('If the `request` argument is set, then none of '
                             'the individual field arguments should be set.')

        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.UpdateServiceRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.UpdateServiceRequest):
            request = configuration.UpdateServiceRequest(request)
            # If we have keyword arguments corresponding to fields on the
            # request, apply these.
            if service is not None:
                request.service = service
            if update_mask is not None:
                request.update_mask = update_mask

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.update_service]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("service.name", request.service.name),
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

    def batch_update_services(self,
            request: configuration.BatchUpdateServicesRequest = None,
            *,
            retry: retries.Retry = gapic_v1.method.DEFAULT,
            timeout: float = None,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.BatchUpdateServicesResponse:
        r"""Updates the specified
        [Service][google.firebase.appcheck.v1beta.Service]
        configurations atomically.

        Args:
            request (google.firebase.appcheck_v1beta.types.BatchUpdateServicesRequest):
                The request object. Request message for the
                [BatchUpdateServices][google.firebase.appcheck.v1beta.ConfigService.BatchUpdateServices]
                method.
            retry (google.api_core.retry.Retry): Designation of what errors, if any,
                should be retried.
            timeout (float): The timeout for this request.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            google.firebase.appcheck_v1beta.types.BatchUpdateServicesResponse:
                Response message for the
                   [BatchUpdateServices][google.firebase.appcheck.v1beta.ConfigService.BatchUpdateServices]
                   method.

        """
        # Create or coerce a protobuf request object.
        # Minor optimization to avoid making a copy if the user passes
        # in a configuration.BatchUpdateServicesRequest.
        # There's no risk of modifying the input as we've already verified
        # there are no flattened fields.
        if not isinstance(request, configuration.BatchUpdateServicesRequest):
            request = configuration.BatchUpdateServicesRequest(request)

        # Wrap the RPC method; this adds retry and timeout information,
        # and friendly error handling.
        rpc = self._transport._wrapped_methods[self._transport.batch_update_services]

        # Certain fields should be provided within the metadata header;
        # add these here.
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((
                ("parent", request.parent),
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
    "ConfigServiceClient",
)
