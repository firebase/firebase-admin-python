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
import warnings
from typing import Callable, Dict, Optional, Sequence, Tuple

from google.api_core import gapic_v1       # type: ignore
from google.api_core import exceptions as core_exceptions  # type: ignore
from google.auth import credentials as ga_credentials      # type: ignore
from google.auth.transport.grpc import SslCredentials      # type: ignore

import grpc  # type: ignore

from google.auth.transport.requests import AuthorizedSession

from google.firebase.appcheck_v1beta.types import token_exchange_service

from .base import TokenExchangeServiceTransport, DEFAULT_CLIENT_INFO


class TokenExchangeServiceRestTransport(TokenExchangeServiceTransport):
    """REST backend transport for TokenExchangeService.

    A service to validate certification material issued to apps by app
    or device attestation providers, and exchange them for *App Check
    tokens* (see
    [AttestationTokenResponse][google.firebase.appcheck.v1beta.AttestationTokenResponse]),
    used to access Firebase services protected by App Check.

    This class defines the same methods as the primary client, so the
    primary client can load the underlying transport implementation
    and call it.

    It sends JSON representations of protocol buffers over HTTP/1.1
    """
    def __init__(self, *,
            host: str = 'firebaseappcheck.googleapis.com',
            credentials: ga_credentials.Credentials = None,
            credentials_file: str = None,
            scopes: Sequence[str] = None,
            client_cert_source_for_mtls: Callable[[], Tuple[bytes, bytes]] = None,
            quota_project_id: Optional[str] = None,
            client_info: gapic_v1.client_info.ClientInfo = DEFAULT_CLIENT_INFO,
            always_use_jwt_access: Optional[bool] = False,
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
                This argument is ignored if ``channel`` is provided.
            scopes (Optional(Sequence[str])): A list of scopes. This argument is
                ignored if ``channel`` is provided.
            client_cert_source_for_mtls (Callable[[], Tuple[bytes, bytes]]): Client
                certificate to configure mutual TLS HTTP channel. It is ignored
                if ``channel`` is provided.
            quota_project_id (Optional[str]): An optional project to use for billing
                and quota.
            client_info (google.api_core.gapic_v1.client_info.ClientInfo):
                The client info used to send a user-agent string along with
                API requests. If ``None``, then default info will be used.
                Generally, you only need to set this if you're developing
                your own client library.
        """
        # Run the base constructor
        # TODO(yon-mg): resolve other ctor params i.e. scopes, quota, etc.
        # TODO: When custom host (api_endpoint) is set, `scopes` must *also* be set on the
        # credentials object
        super().__init__(
            host=host,
            credentials=credentials,
            client_info=client_info,
            always_use_jwt_access=always_use_jwt_access,
        )
        self._session = AuthorizedSession(self._credentials, default_host=self.DEFAULT_HOST)
        if client_cert_source_for_mtls:
            self._session.configure_mtls_channel(client_cert_source_for_mtls)
        self._prep_wrapped_messages(client_info)

    def get_public_jwk_set(self,
            request: token_exchange_service.GetPublicJwkSetRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.PublicJwkSet:
        r"""Call the get public jwk set method over HTTP.

        Args:
            request (~.token_exchange_service.GetPublicJwkSetRequest):
                The request object. Request message for the [GetPublicJwkSet][] method.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.token_exchange_service.PublicJwkSet:
                The currently active set of public keys that can be used
                to verify App Check tokens.

                This object is a JWK set as specified by `section 5 of
                RFC
                7517 <https://tools.ietf.org/html/rfc7517#section-5>`__.

                For security, the response **must not** be cached for
                longer than one day.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{name=jwks}'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['name'] = request.name

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.get(
            url,
            headers=headers,
            params=query_params,
        )

        # In case of error, raise the appropriate core_exceptions.GoogleAPICallError exception
        # subclass.
        if response.status_code >= 400:
            raise core_exceptions.from_http_response(response)

        # Return the response
        return token_exchange_service.PublicJwkSet.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def exchange_safety_net_token(self,
            request: token_exchange_service.ExchangeSafetyNetTokenRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Call the exchange safety net token method over HTTP.

        Args:
            request (~.token_exchange_service.ExchangeSafetyNetTokenRequest):
                The request object. Request message for the [ExchangeSafetyNetToken][]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.token_exchange_service.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to
                access Firebase services protected by App Check.

        """

        # Jsonify the request body
        body = token_exchange_service.ExchangeSafetyNetTokenRequest.to_json(
            request,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{app=projects/*/apps/*}:exchangeSafetyNetToken'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['app'] = request.app
        query_params['safetyNetToken'] = request.safety_net_token

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.post(
            url,
            headers=headers,
            params=query_params,
            data=body,
        )

        # In case of error, raise the appropriate core_exceptions.GoogleAPICallError exception
        # subclass.
        if response.status_code >= 400:
            raise core_exceptions.from_http_response(response)

        # Return the response
        return token_exchange_service.AttestationTokenResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def exchange_device_check_token(self,
            request: token_exchange_service.ExchangeDeviceCheckTokenRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Call the exchange device check
        token method over HTTP.

        Args:
            request (~.token_exchange_service.ExchangeDeviceCheckTokenRequest):
                The request object. Request message for the [ExchangeDeviceCheckToken][]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.token_exchange_service.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to
                access Firebase services protected by App Check.

        """

        # Jsonify the request body
        body = token_exchange_service.ExchangeDeviceCheckTokenRequest.to_json(
            request,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{app=projects/*/apps/*}:exchangeDeviceCheckToken'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['app'] = request.app
        query_params['deviceToken'] = request.device_token

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.post(
            url,
            headers=headers,
            params=query_params,
            data=body,
        )

        # In case of error, raise the appropriate core_exceptions.GoogleAPICallError exception
        # subclass.
        if response.status_code >= 400:
            raise core_exceptions.from_http_response(response)

        # Return the response
        return token_exchange_service.AttestationTokenResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def exchange_recaptcha_token(self,
            request: token_exchange_service.ExchangeRecaptchaTokenRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Call the exchange recaptcha token method over HTTP.

        Args:
            request (~.token_exchange_service.ExchangeRecaptchaTokenRequest):
                The request object. Request message for the [ExchangeRecaptchaToken][]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.token_exchange_service.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to
                access Firebase services protected by App Check.

        """

        # Jsonify the request body
        body = token_exchange_service.ExchangeRecaptchaTokenRequest.to_json(
            request,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{app=projects/*/apps/*}:exchangeRecaptchaToken'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['app'] = request.app
        query_params['recaptchaToken'] = request.recaptcha_token

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.post(
            url,
            headers=headers,
            params=query_params,
            data=body,
        )

        # In case of error, raise the appropriate core_exceptions.GoogleAPICallError exception
        # subclass.
        if response.status_code >= 400:
            raise core_exceptions.from_http_response(response)

        # Return the response
        return token_exchange_service.AttestationTokenResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def exchange_custom_token(self,
            request: token_exchange_service.ExchangeCustomTokenRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Call the exchange custom token method over HTTP.

        Args:
            request (~.token_exchange_service.ExchangeCustomTokenRequest):
                The request object. Request message for the [ExchangeCustomToken][] method.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.token_exchange_service.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to
                access Firebase services protected by App Check.

        """

        # Jsonify the request body
        body = token_exchange_service.ExchangeCustomTokenRequest.to_json(
            request,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{app=projects/*/apps/*}:exchangeCustomToken'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['app'] = request.app
        query_params['customToken'] = request.custom_token

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.post(
            url,
            headers=headers,
            params=query_params,
            data=body,
        )

        # In case of error, raise the appropriate core_exceptions.GoogleAPICallError exception
        # subclass.
        if response.status_code >= 400:
            raise core_exceptions.from_http_response(response)

        # Return the response
        return token_exchange_service.AttestationTokenResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def exchange_debug_token(self,
            request: token_exchange_service.ExchangeDebugTokenRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Call the exchange debug token method over HTTP.

        Args:
            request (~.token_exchange_service.ExchangeDebugTokenRequest):
                The request object. Request message for the [ExchangeDebugToken][] method.
            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.token_exchange_service.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to
                access Firebase services protected by App Check.

        """

        # Jsonify the request body
        body = token_exchange_service.ExchangeDebugTokenRequest.to_json(
            request,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{app=projects/*/apps/*}:exchangeDebugToken'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['app'] = request.app
        query_params['debugToken'] = request.debug_token

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.post(
            url,
            headers=headers,
            params=query_params,
            data=body,
        )

        # In case of error, raise the appropriate core_exceptions.GoogleAPICallError exception
        # subclass.
        if response.status_code >= 400:
            raise core_exceptions.from_http_response(response)

        # Return the response
        return token_exchange_service.AttestationTokenResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def generate_app_attest_challenge(self,
            request: token_exchange_service.GenerateAppAttestChallengeRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AppAttestChallengeResponse:
        r"""Call the generate app attest
        challenge method over HTTP.

        Args:
            request (~.token_exchange_service.GenerateAppAttestChallengeRequest):
                The request object. Request message for
                GenerateAppAttestChallenge

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.token_exchange_service.AppAttestChallengeResponse:
                Response object for
                GenerateAppAttestChallenge

        """

        # Jsonify the request body
        body = token_exchange_service.GenerateAppAttestChallengeRequest.to_json(
            request,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{app=projects/*/apps/*}:generateAppAttestChallenge'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['app'] = request.app

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.post(
            url,
            headers=headers,
            params=query_params,
            data=body,
        )

        # In case of error, raise the appropriate core_exceptions.GoogleAPICallError exception
        # subclass.
        if response.status_code >= 400:
            raise core_exceptions.from_http_response(response)

        # Return the response
        return token_exchange_service.AppAttestChallengeResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def exchange_app_attest_attestation(self,
            request: token_exchange_service.ExchangeAppAttestAttestationRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.ExchangeAppAttestAttestationResponse:
        r"""Call the exchange app attest
        attestation method over HTTP.

        Args:
            request (~.token_exchange_service.ExchangeAppAttestAttestationRequest):
                The request object. Request message for
                ExchangeAppAttestAttestation

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.token_exchange_service.ExchangeAppAttestAttestationResponse:
                Response message for
                ExchangeAppAttestAttestation and
                ExchangeAppAttestDebugAttestation

        """

        # Jsonify the request body
        body = token_exchange_service.ExchangeAppAttestAttestationRequest.to_json(
            request,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{app=projects/*/apps/*}:exchangeAppAttestAttestation'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['app'] = request.app
        query_params['attestationStatement'] = request.attestation_statement
        query_params['challenge'] = request.challenge
        query_params['keyId'] = request.key_id

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.post(
            url,
            headers=headers,
            params=query_params,
            data=body,
        )

        # In case of error, raise the appropriate core_exceptions.GoogleAPICallError exception
        # subclass.
        if response.status_code >= 400:
            raise core_exceptions.from_http_response(response)

        # Return the response
        return token_exchange_service.ExchangeAppAttestAttestationResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def exchange_app_attest_assertion(self,
            request: token_exchange_service.ExchangeAppAttestAssertionRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> token_exchange_service.AttestationTokenResponse:
        r"""Call the exchange app attest
        assertion method over HTTP.

        Args:
            request (~.token_exchange_service.ExchangeAppAttestAssertionRequest):
                The request object. Request message for
                ExchangeAppAttestAssertion

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.token_exchange_service.AttestationTokenResponse:
                Encapsulates an *App Check token*, which are used to
                access Firebase services protected by App Check.

        """

        # Jsonify the request body
        body = token_exchange_service.ExchangeAppAttestAssertionRequest.to_json(
            request,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{app=projects/*/apps/*}:exchangeAppAttestAssertion'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['app'] = request.app
        query_params['artifact'] = request.artifact
        query_params['assertion'] = request.assertion
        query_params['challenge'] = request.challenge

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.post(
            url,
            headers=headers,
            params=query_params,
            data=body,
        )

        # In case of error, raise the appropriate core_exceptions.GoogleAPICallError exception
        # subclass.
        if response.status_code >= 400:
            raise core_exceptions.from_http_response(response)

        # Return the response
        return token_exchange_service.AttestationTokenResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )


__all__ = (
    'TokenExchangeServiceRestTransport',
)
