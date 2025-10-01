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

from google.firebase.appcheck_v1beta.types import token_exchange_service

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


class TokenExchangeServiceTransport(abc.ABC):
    """Abstract transport class for TokenExchangeService."""

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
            self.get_public_jwk_set: gapic_v1.method.wrap_method(
                self.get_public_jwk_set,
                default_timeout=None,
                client_info=client_info,
            ),
            self.exchange_safety_net_token: gapic_v1.method.wrap_method(
                self.exchange_safety_net_token,
                default_timeout=None,
                client_info=client_info,
            ),
            self.exchange_device_check_token: gapic_v1.method.wrap_method(
                self.exchange_device_check_token,
                default_timeout=None,
                client_info=client_info,
            ),
            self.exchange_recaptcha_token: gapic_v1.method.wrap_method(
                self.exchange_recaptcha_token,
                default_timeout=None,
                client_info=client_info,
            ),
            self.exchange_custom_token: gapic_v1.method.wrap_method(
                self.exchange_custom_token,
                default_timeout=None,
                client_info=client_info,
            ),
            self.exchange_debug_token: gapic_v1.method.wrap_method(
                self.exchange_debug_token,
                default_timeout=None,
                client_info=client_info,
            ),
            self.generate_app_attest_challenge: gapic_v1.method.wrap_method(
                self.generate_app_attest_challenge,
                default_timeout=None,
                client_info=client_info,
            ),
            self.exchange_app_attest_attestation: gapic_v1.method.wrap_method(
                self.exchange_app_attest_attestation,
                default_timeout=None,
                client_info=client_info,
            ),
            self.exchange_app_attest_assertion: gapic_v1.method.wrap_method(
                self.exchange_app_attest_assertion,
                default_timeout=None,
                client_info=client_info,
            ),
         }

    @property
    def get_public_jwk_set(self) -> Callable[
            [token_exchange_service.GetPublicJwkSetRequest],
            Union[
                token_exchange_service.PublicJwkSet,
                Awaitable[token_exchange_service.PublicJwkSet]
            ]]:
        raise NotImplementedError()

    @property
    def exchange_safety_net_token(self) -> Callable[
            [token_exchange_service.ExchangeSafetyNetTokenRequest],
            Union[
                token_exchange_service.AttestationTokenResponse,
                Awaitable[token_exchange_service.AttestationTokenResponse]
            ]]:
        raise NotImplementedError()

    @property
    def exchange_device_check_token(self) -> Callable[
            [token_exchange_service.ExchangeDeviceCheckTokenRequest],
            Union[
                token_exchange_service.AttestationTokenResponse,
                Awaitable[token_exchange_service.AttestationTokenResponse]
            ]]:
        raise NotImplementedError()

    @property
    def exchange_recaptcha_token(self) -> Callable[
            [token_exchange_service.ExchangeRecaptchaTokenRequest],
            Union[
                token_exchange_service.AttestationTokenResponse,
                Awaitable[token_exchange_service.AttestationTokenResponse]
            ]]:
        raise NotImplementedError()

    @property
    def exchange_custom_token(self) -> Callable[
            [token_exchange_service.ExchangeCustomTokenRequest],
            Union[
                token_exchange_service.AttestationTokenResponse,
                Awaitable[token_exchange_service.AttestationTokenResponse]
            ]]:
        raise NotImplementedError()

    @property
    def exchange_debug_token(self) -> Callable[
            [token_exchange_service.ExchangeDebugTokenRequest],
            Union[
                token_exchange_service.AttestationTokenResponse,
                Awaitable[token_exchange_service.AttestationTokenResponse]
            ]]:
        raise NotImplementedError()

    @property
    def generate_app_attest_challenge(self) -> Callable[
            [token_exchange_service.GenerateAppAttestChallengeRequest],
            Union[
                token_exchange_service.AppAttestChallengeResponse,
                Awaitable[token_exchange_service.AppAttestChallengeResponse]
            ]]:
        raise NotImplementedError()

    @property
    def exchange_app_attest_attestation(self) -> Callable[
            [token_exchange_service.ExchangeAppAttestAttestationRequest],
            Union[
                token_exchange_service.ExchangeAppAttestAttestationResponse,
                Awaitable[token_exchange_service.ExchangeAppAttestAttestationResponse]
            ]]:
        raise NotImplementedError()

    @property
    def exchange_app_attest_assertion(self) -> Callable[
            [token_exchange_service.ExchangeAppAttestAssertionRequest],
            Union[
                token_exchange_service.AttestationTokenResponse,
                Awaitable[token_exchange_service.AttestationTokenResponse]
            ]]:
        raise NotImplementedError()


__all__ = (
    'TokenExchangeServiceTransport',
)
