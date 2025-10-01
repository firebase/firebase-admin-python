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
import abc
from typing import Awaitable, Callable, Dict, Optional, Sequence, Union
import packaging.version
import pkg_resources
from requests import __version__ as requests_version

import google.auth  # type: ignore
import google.api_core  # type: ignore
from google.api_core import exceptions as core_exceptions  # type: ignore
from google.api_core import gapic_v1    # type: ignore
from google.api_core import retry as retries  # type: ignore
from google.auth import credentials as ga_credentials  # type: ignore
from google.oauth2 import service_account # type: ignore

from google.firebase.appcheck_v1beta.types import configuration
from google.protobuf import empty_pb2  # type: ignore

try:
    DEFAULT_CLIENT_INFO = gapic_v1.client_info.ClientInfo(
        gapic_version=pkg_resources.get_distribution(
            'google-firebase-appcheck',
        ).version,
        grpc_version=None,
        rest_version=requests_version,
    )
except pkg_resources.DistributionNotFound:
    DEFAULT_CLIENT_INFO = gapic_v1.client_info.ClientInfo()

try:
    # google.auth.__version__ was added in 1.26.0
    _GOOGLE_AUTH_VERSION = google.auth.__version__
except AttributeError:
    try:  # try pkg_resources if it is available
        _GOOGLE_AUTH_VERSION = pkg_resources.get_distribution("google-auth").version
    except pkg_resources.DistributionNotFound:  # pragma: NO COVER
        _GOOGLE_AUTH_VERSION = None


class ConfigServiceTransport(abc.ABC):
    """Abstract transport class for ConfigService."""

    AUTH_SCOPES = (
        'https://www.googleapis.com/auth/cloud-platform',
        'https://www.googleapis.com/auth/firebase',
    )

    DEFAULT_HOST: str = 'firebaseappcheck.googleapis.com'
    def __init__(
            self, *,
            host: str = DEFAULT_HOST,
            credentials: ga_credentials.Credentials = None,
            credentials_file: Optional[str] = None,
            scopes: Optional[Sequence[str]] = None,
            quota_project_id: Optional[str] = None,
            client_info: gapic_v1.client_info.ClientInfo = DEFAULT_CLIENT_INFO,
            always_use_jwt_access: Optional[bool] = False,
            **kwargs,
            ) -> None:
        """Instantiate the transport.

        Args:
            host (Optional[str]):
                 The hostname to connect to.
            credentials (Optional[google.auth.credentials.Credentials]): The
                authorization credentials to attach to requests. These
                credentials identify the application to the service; if none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
            credentials_file (Optional[str]): A file with credentials that can
                be loaded with :func:`google.auth.load_credentials_from_file`.
                This argument is mutually exclusive with credentials.
            scopes (Optional[Sequence[str]]): A list of scopes.
            quota_project_id (Optional[str]): An optional project to use for billing
                and quota.
            client_info (google.api_core.gapic_v1.client_info.ClientInfo):
                The client info used to send a user-agent string along with
                API requests. If ``None``, then default info will be used.
                Generally, you only need to set this if you're developing
                your own client library.
            always_use_jwt_access (Optional[bool]): Whether self signed JWT should
                be used for service account credentials.
        """
        # Save the hostname. Default to port 443 (HTTPS) if none is specified.
        if ':' not in host:
            host += ':443'
        self._host = host

        scopes_kwargs = self._get_scopes_kwargs(self._host, scopes)

        # Save the scopes.
        self._scopes = scopes

        # If no credentials are provided, then determine the appropriate
        # defaults.
        if credentials and credentials_file:
            raise core_exceptions.DuplicateCredentialArgs("'credentials_file' and 'credentials' are mutually exclusive")

        if credentials_file is not None:
            credentials, _ = google.auth.load_credentials_from_file(
                                credentials_file,
                                **scopes_kwargs,
                                quota_project_id=quota_project_id
                            )

        elif credentials is None:
            credentials, _ = google.auth.default(**scopes_kwargs, quota_project_id=quota_project_id)

        # If the credentials is service account credentials, then always try to use self signed JWT.
        if always_use_jwt_access and isinstance(credentials, service_account.Credentials) and hasattr(service_account.Credentials, "with_always_use_jwt_access"):
            credentials = credentials.with_always_use_jwt_access(True)

        # Save the credentials.
        self._credentials = credentials

    # TODO(busunkim): This method is in the base transport
    # to avoid duplicating code across the transport classes. These functions
    # should be deleted once the minimum required versions of google-auth is increased.

    # TODO: Remove this function once google-auth >= 1.25.0 is required
    @classmethod
    def _get_scopes_kwargs(cls, host: str, scopes: Optional[Sequence[str]]) -> Dict[str, Optional[Sequence[str]]]:
        """Returns scopes kwargs to pass to google-auth methods depending on the google-auth version"""

        scopes_kwargs = {}

        if _GOOGLE_AUTH_VERSION and (
            packaging.version.parse(_GOOGLE_AUTH_VERSION)
            >= packaging.version.parse("1.25.0")
        ):
            scopes_kwargs = {"scopes": scopes, "default_scopes": cls.AUTH_SCOPES}
        else:
            scopes_kwargs = {"scopes": scopes or cls.AUTH_SCOPES}

        return scopes_kwargs

    def _prep_wrapped_messages(self, client_info):
        # Precompute the wrapped methods.
        self._wrapped_methods = {
            self.get_app_attest_config: gapic_v1.method.wrap_method(
                self.get_app_attest_config,
                default_timeout=None,
                client_info=client_info,
            ),
            self.batch_get_app_attest_configs: gapic_v1.method.wrap_method(
                self.batch_get_app_attest_configs,
                default_timeout=None,
                client_info=client_info,
            ),
            self.update_app_attest_config: gapic_v1.method.wrap_method(
                self.update_app_attest_config,
                default_timeout=None,
                client_info=client_info,
            ),
            self.get_device_check_config: gapic_v1.method.wrap_method(
                self.get_device_check_config,
                default_timeout=None,
                client_info=client_info,
            ),
            self.batch_get_device_check_configs: gapic_v1.method.wrap_method(
                self.batch_get_device_check_configs,
                default_timeout=None,
                client_info=client_info,
            ),
            self.update_device_check_config: gapic_v1.method.wrap_method(
                self.update_device_check_config,
                default_timeout=None,
                client_info=client_info,
            ),
            self.get_recaptcha_config: gapic_v1.method.wrap_method(
                self.get_recaptcha_config,
                default_timeout=None,
                client_info=client_info,
            ),
            self.batch_get_recaptcha_configs: gapic_v1.method.wrap_method(
                self.batch_get_recaptcha_configs,
                default_timeout=None,
                client_info=client_info,
            ),
            self.update_recaptcha_config: gapic_v1.method.wrap_method(
                self.update_recaptcha_config,
                default_timeout=None,
                client_info=client_info,
            ),
            self.get_safety_net_config: gapic_v1.method.wrap_method(
                self.get_safety_net_config,
                default_timeout=None,
                client_info=client_info,
            ),
            self.batch_get_safety_net_configs: gapic_v1.method.wrap_method(
                self.batch_get_safety_net_configs,
                default_timeout=None,
                client_info=client_info,
            ),
            self.update_safety_net_config: gapic_v1.method.wrap_method(
                self.update_safety_net_config,
                default_timeout=None,
                client_info=client_info,
            ),
            self.get_debug_token: gapic_v1.method.wrap_method(
                self.get_debug_token,
                default_timeout=None,
                client_info=client_info,
            ),
            self.list_debug_tokens: gapic_v1.method.wrap_method(
                self.list_debug_tokens,
                default_timeout=None,
                client_info=client_info,
            ),
            self.create_debug_token: gapic_v1.method.wrap_method(
                self.create_debug_token,
                default_timeout=None,
                client_info=client_info,
            ),
            self.update_debug_token: gapic_v1.method.wrap_method(
                self.update_debug_token,
                default_timeout=None,
                client_info=client_info,
            ),
            self.delete_debug_token: gapic_v1.method.wrap_method(
                self.delete_debug_token,
                default_timeout=None,
                client_info=client_info,
            ),
            self.get_service: gapic_v1.method.wrap_method(
                self.get_service,
                default_timeout=None,
                client_info=client_info,
            ),
            self.list_services: gapic_v1.method.wrap_method(
                self.list_services,
                default_timeout=None,
                client_info=client_info,
            ),
            self.update_service: gapic_v1.method.wrap_method(
                self.update_service,
                default_timeout=None,
                client_info=client_info,
            ),
            self.batch_update_services: gapic_v1.method.wrap_method(
                self.batch_update_services,
                default_timeout=None,
                client_info=client_info,
            ),
         }

    @property
    def get_app_attest_config(self) -> Callable[
            [configuration.GetAppAttestConfigRequest],
            Union[
                configuration.AppAttestConfig,
                Awaitable[configuration.AppAttestConfig]
            ]]:
        raise NotImplementedError()

    @property
    def batch_get_app_attest_configs(self) -> Callable[
            [configuration.BatchGetAppAttestConfigsRequest],
            Union[
                configuration.BatchGetAppAttestConfigsResponse,
                Awaitable[configuration.BatchGetAppAttestConfigsResponse]
            ]]:
        raise NotImplementedError()

    @property
    def update_app_attest_config(self) -> Callable[
            [configuration.UpdateAppAttestConfigRequest],
            Union[
                configuration.AppAttestConfig,
                Awaitable[configuration.AppAttestConfig]
            ]]:
        raise NotImplementedError()

    @property
    def get_device_check_config(self) -> Callable[
            [configuration.GetDeviceCheckConfigRequest],
            Union[
                configuration.DeviceCheckConfig,
                Awaitable[configuration.DeviceCheckConfig]
            ]]:
        raise NotImplementedError()

    @property
    def batch_get_device_check_configs(self) -> Callable[
            [configuration.BatchGetDeviceCheckConfigsRequest],
            Union[
                configuration.BatchGetDeviceCheckConfigsResponse,
                Awaitable[configuration.BatchGetDeviceCheckConfigsResponse]
            ]]:
        raise NotImplementedError()

    @property
    def update_device_check_config(self) -> Callable[
            [configuration.UpdateDeviceCheckConfigRequest],
            Union[
                configuration.DeviceCheckConfig,
                Awaitable[configuration.DeviceCheckConfig]
            ]]:
        raise NotImplementedError()

    @property
    def get_recaptcha_config(self) -> Callable[
            [configuration.GetRecaptchaConfigRequest],
            Union[
                configuration.RecaptchaConfig,
                Awaitable[configuration.RecaptchaConfig]
            ]]:
        raise NotImplementedError()

    @property
    def batch_get_recaptcha_configs(self) -> Callable[
            [configuration.BatchGetRecaptchaConfigsRequest],
            Union[
                configuration.BatchGetRecaptchaConfigsResponse,
                Awaitable[configuration.BatchGetRecaptchaConfigsResponse]
            ]]:
        raise NotImplementedError()

    @property
    def update_recaptcha_config(self) -> Callable[
            [configuration.UpdateRecaptchaConfigRequest],
            Union[
                configuration.RecaptchaConfig,
                Awaitable[configuration.RecaptchaConfig]
            ]]:
        raise NotImplementedError()

    @property
    def get_safety_net_config(self) -> Callable[
            [configuration.GetSafetyNetConfigRequest],
            Union[
                configuration.SafetyNetConfig,
                Awaitable[configuration.SafetyNetConfig]
            ]]:
        raise NotImplementedError()

    @property
    def batch_get_safety_net_configs(self) -> Callable[
            [configuration.BatchGetSafetyNetConfigsRequest],
            Union[
                configuration.BatchGetSafetyNetConfigsResponse,
                Awaitable[configuration.BatchGetSafetyNetConfigsResponse]
            ]]:
        raise NotImplementedError()

    @property
    def update_safety_net_config(self) -> Callable[
            [configuration.UpdateSafetyNetConfigRequest],
            Union[
                configuration.SafetyNetConfig,
                Awaitable[configuration.SafetyNetConfig]
            ]]:
        raise NotImplementedError()

    @property
    def get_debug_token(self) -> Callable[
            [configuration.GetDebugTokenRequest],
            Union[
                configuration.DebugToken,
                Awaitable[configuration.DebugToken]
            ]]:
        raise NotImplementedError()

    @property
    def list_debug_tokens(self) -> Callable[
            [configuration.ListDebugTokensRequest],
            Union[
                configuration.ListDebugTokensResponse,
                Awaitable[configuration.ListDebugTokensResponse]
            ]]:
        raise NotImplementedError()

    @property
    def create_debug_token(self) -> Callable[
            [configuration.CreateDebugTokenRequest],
            Union[
                configuration.DebugToken,
                Awaitable[configuration.DebugToken]
            ]]:
        raise NotImplementedError()

    @property
    def update_debug_token(self) -> Callable[
            [configuration.UpdateDebugTokenRequest],
            Union[
                configuration.DebugToken,
                Awaitable[configuration.DebugToken]
            ]]:
        raise NotImplementedError()

    @property
    def delete_debug_token(self) -> Callable[
            [configuration.DeleteDebugTokenRequest],
            Union[
                empty_pb2.Empty,
                Awaitable[empty_pb2.Empty]
            ]]:
        raise NotImplementedError()

    @property
    def get_service(self) -> Callable[
            [configuration.GetServiceRequest],
            Union[
                configuration.Service,
                Awaitable[configuration.Service]
            ]]:
        raise NotImplementedError()

    @property
    def list_services(self) -> Callable[
            [configuration.ListServicesRequest],
            Union[
                configuration.ListServicesResponse,
                Awaitable[configuration.ListServicesResponse]
            ]]:
        raise NotImplementedError()

    @property
    def update_service(self) -> Callable[
            [configuration.UpdateServiceRequest],
            Union[
                configuration.Service,
                Awaitable[configuration.Service]
            ]]:
        raise NotImplementedError()

    @property
    def batch_update_services(self) -> Callable[
            [configuration.BatchUpdateServicesRequest],
            Union[
                configuration.BatchUpdateServicesResponse,
                Awaitable[configuration.BatchUpdateServicesResponse]
            ]]:
        raise NotImplementedError()


__all__ = (
    'ConfigServiceTransport',
)
