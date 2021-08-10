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

from google.firebase.appcheck_v1beta.types import configuration
from google.protobuf import empty_pb2  # type: ignore

from .base import ConfigServiceTransport, DEFAULT_CLIENT_INFO


class ConfigServiceRestTransport(ConfigServiceTransport):
    """REST backend transport for ConfigService.

    Manages configuration parameters used by the
    [TokenExchangeService][google.firebase.appcheck.v1beta.TokenExchangeService]
    and enforcement settings for Firebase services protected by App
    Check.

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

    def get_app_attest_config(self,
            request: configuration.GetAppAttestConfigRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.AppAttestConfig:
        r"""Call the get app attest config method over HTTP.

        Args:
            request (~.configuration.GetAppAttestConfigRequest):
                The request object. Request message for the
                [GetAppAttestConfig][google.firebase.appcheck.v1beta.ConfigService.GetAppAttestConfig]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.AppAttestConfig:
                An app's App Attest configuration object. This
                configuration controls certain properties of the [App
                Check
                token][google.firebase.appcheck.v1beta.AttestationTokenResponse]
                returned by
                [ExchangeAppAttestAttestation][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeAppAttestAttestation]
                and
                [ExchangeAppAttestAttestation][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeAppAttestAssertion],
                such as its
                [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                Note that the Team ID registered with your app is used
                as part of the validation process. Please register it
                via the Firebase Console or programmatically via the
                `Firebase Management
                Service <https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.iosApps/patch>`__.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{name=projects/*/apps/*/appAttestConfig}'.format(
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
        return configuration.AppAttestConfig.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def batch_get_app_attest_configs(self,
            request: configuration.BatchGetAppAttestConfigsRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.BatchGetAppAttestConfigsResponse:
        r"""Call the batch get app attest
        configs method over HTTP.

        Args:
            request (~.configuration.BatchGetAppAttestConfigsRequest):
                The request object. Request message for the
                [BatchGetAppAttestConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetAppAttestConfigs]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.BatchGetAppAttestConfigsResponse:
                Response message for the
                [BatchGetAppAttestConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetAppAttestConfigs]
                method.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{parent=projects/*}/apps/-/appAttestConfig:batchGet'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['names'] = request.names
        query_params['parent'] = request.parent

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
        return configuration.BatchGetAppAttestConfigsResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def update_app_attest_config(self,
            request: configuration.UpdateAppAttestConfigRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.AppAttestConfig:
        r"""Call the update app attest config method over HTTP.

        Args:
            request (~.configuration.UpdateAppAttestConfigRequest):
                The request object. Request message for the
                [UpdateAppAttestConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateAppAttestConfig]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.AppAttestConfig:
                An app's App Attest configuration object. This
                configuration controls certain properties of the [App
                Check
                token][google.firebase.appcheck.v1beta.AttestationTokenResponse]
                returned by
                [ExchangeAppAttestAttestation][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeAppAttestAttestation]
                and
                [ExchangeAppAttestAttestation][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeAppAttestAssertion],
                such as its
                [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                Note that the Team ID registered with your app is used
                as part of the validation process. Please register it
                via the Firebase Console or programmatically via the
                `Firebase Management
                Service <https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.iosApps/patch>`__.

        """

        # Jsonify the request body
        body = configuration.AppAttestConfig.to_json(
            request.app_attest_config,
            including_default_value_fields=False,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{app_attest_config.name=projects/*/apps/*/appAttestConfig}'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['updateMask'] = request.update_mask

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.patch(
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
        return configuration.AppAttestConfig.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def get_device_check_config(self,
            request: configuration.GetDeviceCheckConfigRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.DeviceCheckConfig:
        r"""Call the get device check config method over HTTP.

        Args:
            request (~.configuration.GetDeviceCheckConfigRequest):
                The request object. Request message for the
                [GetDeviceCheckConfig][google.firebase.appcheck.v1beta.ConfigService.GetDeviceCheckConfig]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.DeviceCheckConfig:
                An app's DeviceCheck configuration object. This
                configuration is used by
                [ExchangeDeviceCheckToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeDeviceCheckToken]
                to validate device tokens issued to apps by DeviceCheck.
                It also controls certain properties of the returned [App
                Check
                token][google.firebase.appcheck.v1beta.AttestationTokenResponse],
                such as its
                [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                Note that the Team ID registered with your app is used
                as part of the validation process. Please register it
                via the Firebase Console or programmatically via the
                `Firebase Management
                Service <https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.iosApps/patch>`__.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{name=projects/*/apps/*/deviceCheckConfig}'.format(
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
        return configuration.DeviceCheckConfig.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def batch_get_device_check_configs(self,
            request: configuration.BatchGetDeviceCheckConfigsRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.BatchGetDeviceCheckConfigsResponse:
        r"""Call the batch get device check
        configs method over HTTP.

        Args:
            request (~.configuration.BatchGetDeviceCheckConfigsRequest):
                The request object. Request message for the
                [BatchGetDeviceCheckConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetDeviceCheckConfigs]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.BatchGetDeviceCheckConfigsResponse:
                Response message for the
                [BatchGetDeviceCheckConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetDeviceCheckConfigs]
                method.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{parent=projects/*}/apps/-/deviceCheckConfig:batchGet'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['names'] = request.names
        query_params['parent'] = request.parent

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
        return configuration.BatchGetDeviceCheckConfigsResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def update_device_check_config(self,
            request: configuration.UpdateDeviceCheckConfigRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.DeviceCheckConfig:
        r"""Call the update device check
        config method over HTTP.

        Args:
            request (~.configuration.UpdateDeviceCheckConfigRequest):
                The request object. Request message for the
                [UpdateDeviceCheckConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateDeviceCheckConfig]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.DeviceCheckConfig:
                An app's DeviceCheck configuration object. This
                configuration is used by
                [ExchangeDeviceCheckToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeDeviceCheckToken]
                to validate device tokens issued to apps by DeviceCheck.
                It also controls certain properties of the returned [App
                Check
                token][google.firebase.appcheck.v1beta.AttestationTokenResponse],
                such as its
                [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                Note that the Team ID registered with your app is used
                as part of the validation process. Please register it
                via the Firebase Console or programmatically via the
                `Firebase Management
                Service <https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.iosApps/patch>`__.

        """

        # Jsonify the request body
        body = configuration.DeviceCheckConfig.to_json(
            request.device_check_config,
            including_default_value_fields=False,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{device_check_config.name=projects/*/apps/*/deviceCheckConfig}'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['updateMask'] = request.update_mask

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.patch(
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
        return configuration.DeviceCheckConfig.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def get_recaptcha_config(self,
            request: configuration.GetRecaptchaConfigRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.RecaptchaConfig:
        r"""Call the get recaptcha config method over HTTP.

        Args:
            request (~.configuration.GetRecaptchaConfigRequest):
                The request object. Request message for the
                [GetRecaptchaConfig][google.firebase.appcheck.v1beta.ConfigService.GetRecaptchaConfig]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.RecaptchaConfig:
                An app's reCAPTCHA v3 configuration object. This
                configuration is used by
                [ExchangeRecaptchaToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeRecaptchaToken]
                to validate reCAPTCHA tokens issued to apps by reCAPTCHA
                v3. It also controls certain properties of the returned
                [App Check
                token][google.firebase.appcheck.v1beta.AttestationTokenResponse],
                such as its
                [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{name=projects/*/apps/*/recaptchaConfig}'.format(
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
        return configuration.RecaptchaConfig.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def batch_get_recaptcha_configs(self,
            request: configuration.BatchGetRecaptchaConfigsRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.BatchGetRecaptchaConfigsResponse:
        r"""Call the batch get recaptcha
        configs method over HTTP.

        Args:
            request (~.configuration.BatchGetRecaptchaConfigsRequest):
                The request object. Request message for the
                [BatchGetRecaptchaConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetRecaptchaConfigs]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.BatchGetRecaptchaConfigsResponse:
                Response message for the
                [BatchGetRecaptchaConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetRecaptchaConfigs]
                method.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{parent=projects/*}/apps/-/recaptchaConfig:batchGet'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['names'] = request.names
        query_params['parent'] = request.parent

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
        return configuration.BatchGetRecaptchaConfigsResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def update_recaptcha_config(self,
            request: configuration.UpdateRecaptchaConfigRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.RecaptchaConfig:
        r"""Call the update recaptcha config method over HTTP.

        Args:
            request (~.configuration.UpdateRecaptchaConfigRequest):
                The request object. Request message for the
                [UpdateRecaptchaConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateRecaptchaConfig]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.RecaptchaConfig:
                An app's reCAPTCHA v3 configuration object. This
                configuration is used by
                [ExchangeRecaptchaToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeRecaptchaToken]
                to validate reCAPTCHA tokens issued to apps by reCAPTCHA
                v3. It also controls certain properties of the returned
                [App Check
                token][google.firebase.appcheck.v1beta.AttestationTokenResponse],
                such as its
                [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

        """

        # Jsonify the request body
        body = configuration.RecaptchaConfig.to_json(
            request.recaptcha_config,
            including_default_value_fields=False,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{recaptcha_config.name=projects/*/apps/*/recaptchaConfig}'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['updateMask'] = request.update_mask

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.patch(
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
        return configuration.RecaptchaConfig.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def get_safety_net_config(self,
            request: configuration.GetSafetyNetConfigRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.SafetyNetConfig:
        r"""Call the get safety net config method over HTTP.

        Args:
            request (~.configuration.GetSafetyNetConfigRequest):
                The request object. Request message for the
                [GetSafetyNetConfig][google.firebase.appcheck.v1beta.ConfigService.GetSafetyNetConfig]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.SafetyNetConfig:
                An app's SafetyNet configuration object. This
                configuration controls certain properties of the [App
                Check
                token][google.firebase.appcheck.v1beta.AttestationTokenResponse]
                returned by
                [ExchangeSafetyNetToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeSafetyNetToken],
                such as its
                [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                Note that your registered SHA-256 certificate
                fingerprints are used to validate tokens issued by
                SafetyNet; please register them via the Firebase Console
                or programmatically via the `Firebase Management
                Service <https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.androidApps.sha/create>`__.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{name=projects/*/apps/*/safetyNetConfig}'.format(
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
        return configuration.SafetyNetConfig.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def batch_get_safety_net_configs(self,
            request: configuration.BatchGetSafetyNetConfigsRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.BatchGetSafetyNetConfigsResponse:
        r"""Call the batch get safety net
        configs method over HTTP.

        Args:
            request (~.configuration.BatchGetSafetyNetConfigsRequest):
                The request object. Request message for the
                [BatchGetSafetyNetConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetSafetyNetConfigs]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.BatchGetSafetyNetConfigsResponse:
                Response message for the
                [BatchGetSafetyNetConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetSafetyNetConfigs]
                method.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{parent=projects/*}/apps/-/safetyNetConfig:batchGet'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['names'] = request.names
        query_params['parent'] = request.parent

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
        return configuration.BatchGetSafetyNetConfigsResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def update_safety_net_config(self,
            request: configuration.UpdateSafetyNetConfigRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.SafetyNetConfig:
        r"""Call the update safety net config method over HTTP.

        Args:
            request (~.configuration.UpdateSafetyNetConfigRequest):
                The request object. Request message for the
                [UpdateSafetyNetConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateSafetyNetConfig]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.SafetyNetConfig:
                An app's SafetyNet configuration object. This
                configuration controls certain properties of the [App
                Check
                token][google.firebase.appcheck.v1beta.AttestationTokenResponse]
                returned by
                [ExchangeSafetyNetToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeSafetyNetToken],
                such as its
                [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

                Note that your registered SHA-256 certificate
                fingerprints are used to validate tokens issued by
                SafetyNet; please register them via the Firebase Console
                or programmatically via the `Firebase Management
                Service <https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.androidApps.sha/create>`__.

        """

        # Jsonify the request body
        body = configuration.SafetyNetConfig.to_json(
            request.safety_net_config,
            including_default_value_fields=False,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{safety_net_config.name=projects/*/apps/*/safetyNetConfig}'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['updateMask'] = request.update_mask

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.patch(
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
        return configuration.SafetyNetConfig.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def get_debug_token(self,
            request: configuration.GetDebugTokenRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.DebugToken:
        r"""Call the get debug token method over HTTP.

        Args:
            request (~.configuration.GetDebugTokenRequest):
                The request object. Request message for the
                [GetDebugToken][google.firebase.appcheck.v1beta.ConfigService.GetDebugToken]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.DebugToken:
                A *debug token* is a secret used during the development
                or integration testing of an app. It essentially allows
                the development or integration testing to bypass app
                attestation while still allowing App Check to enforce
                protection on supported production Firebase services.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{name=projects/*/apps/*/debugTokens/*}'.format(
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
        return configuration.DebugToken.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def list_debug_tokens(self,
            request: configuration.ListDebugTokensRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.ListDebugTokensResponse:
        r"""Call the list debug tokens method over HTTP.

        Args:
            request (~.configuration.ListDebugTokensRequest):
                The request object. Request message for the
                [ListDebugTokens][google.firebase.appcheck.v1beta.ConfigService.ListDebugTokens]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.ListDebugTokensResponse:
                Response message for the
                [ListDebugTokens][google.firebase.appcheck.v1beta.ConfigService.ListDebugTokens]
                method.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{parent=projects/*/apps/*}/debugTokens'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['pageSize'] = request.page_size
        query_params['pageToken'] = request.page_token
        query_params['parent'] = request.parent

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
        return configuration.ListDebugTokensResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def create_debug_token(self,
            request: configuration.CreateDebugTokenRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.DebugToken:
        r"""Call the create debug token method over HTTP.

        Args:
            request (~.configuration.CreateDebugTokenRequest):
                The request object. Request message for the
                [CreateDebugToken][google.firebase.appcheck.v1beta.ConfigService.CreateDebugToken]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.DebugToken:
                A *debug token* is a secret used during the development
                or integration testing of an app. It essentially allows
                the development or integration testing to bypass app
                attestation while still allowing App Check to enforce
                protection on supported production Firebase services.

        """

        # Jsonify the request body
        body = configuration.DebugToken.to_json(
            request.debug_token,
            including_default_value_fields=False,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{parent=projects/*/apps/*}/debugTokens'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['parent'] = request.parent

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
        return configuration.DebugToken.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def update_debug_token(self,
            request: configuration.UpdateDebugTokenRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.DebugToken:
        r"""Call the update debug token method over HTTP.

        Args:
            request (~.configuration.UpdateDebugTokenRequest):
                The request object. Request message for the
                [UpdateDebugToken][google.firebase.appcheck.v1beta.ConfigService.UpdateDebugToken]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.DebugToken:
                A *debug token* is a secret used during the development
                or integration testing of an app. It essentially allows
                the development or integration testing to bypass app
                attestation while still allowing App Check to enforce
                protection on supported production Firebase services.

        """

        # Jsonify the request body
        body = configuration.DebugToken.to_json(
            request.debug_token,
            including_default_value_fields=False,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{debug_token.name=projects/*/apps/*/debugTokens/*}'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['updateMask'] = request.update_mask

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.patch(
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
        return configuration.DebugToken.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def delete_debug_token(self,
            request: configuration.DeleteDebugTokenRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> empty_pb2.Empty:
        r"""Call the delete debug token method over HTTP.

        Args:
            request (~.configuration.DeleteDebugTokenRequest):
                The request object. Request message for the
                [DeleteDebugToken][google.firebase.appcheck.v1beta.ConfigService.DeleteDebugToken]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.
        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{name=projects/*/apps/*/debugTokens/*}'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['name'] = request.name

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.delete(
            url,
            headers=headers,
            params=query_params,
        )

        # In case of error, raise the appropriate core_exceptions.GoogleAPICallError exception
        # subclass.
        if response.status_code >= 400:
            raise core_exceptions.from_http_response(response)

    def get_service(self,
            request: configuration.GetServiceRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.Service:
        r"""Call the get service method over HTTP.

        Args:
            request (~.configuration.GetServiceRequest):
                The request object. Request message for the
                [GetService][google.firebase.appcheck.v1beta.ConfigService.GetService]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.Service:
                The enforcement configuration for a
                Firebase service supported by App Check.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{name=projects/*/services/*}'.format(
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
        return configuration.Service.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def list_services(self,
            request: configuration.ListServicesRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.ListServicesResponse:
        r"""Call the list services method over HTTP.

        Args:
            request (~.configuration.ListServicesRequest):
                The request object. Request message for the
                [ListServices][google.firebase.appcheck.v1beta.ConfigService.ListServices]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.ListServicesResponse:
                Response message for the
                [ListServices][google.firebase.appcheck.v1beta.ConfigService.ListServices]
                method.

        """

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{parent=projects/*}/services'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['pageSize'] = request.page_size
        query_params['pageToken'] = request.page_token
        query_params['parent'] = request.parent

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
        return configuration.ListServicesResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def update_service(self,
            request: configuration.UpdateServiceRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.Service:
        r"""Call the update service method over HTTP.

        Args:
            request (~.configuration.UpdateServiceRequest):
                The request object. Request message for the
                [UpdateService][google.firebase.appcheck.v1beta.ConfigService.UpdateService]
                method as well as an individual update message for the
                [BatchUpdateServices][google.firebase.appcheck.v1beta.ConfigService.BatchUpdateServices]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.Service:
                The enforcement configuration for a
                Firebase service supported by App Check.

        """

        # Jsonify the request body
        body = configuration.Service.to_json(
            request.service,
            including_default_value_fields=False,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{service.name=projects/*/services/*}'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['updateMask'] = request.update_mask

        # Send the request
        headers = dict(metadata)
        headers['Content-Type'] = 'application/json'
        response = self._session.patch(
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
        return configuration.Service.from_json(
            response.content,
            ignore_unknown_fields=True
        )

    def batch_update_services(self,
            request: configuration.BatchUpdateServicesRequest, *,
            metadata: Sequence[Tuple[str, str]] = (),
            ) -> configuration.BatchUpdateServicesResponse:
        r"""Call the batch update services method over HTTP.

        Args:
            request (~.configuration.BatchUpdateServicesRequest):
                The request object. Request message for the
                [BatchUpdateServices][google.firebase.appcheck.v1beta.ConfigService.BatchUpdateServices]
                method.

            metadata (Sequence[Tuple[str, str]]): Strings which should be
                sent along with the request as metadata.

        Returns:
            ~.configuration.BatchUpdateServicesResponse:
                Response message for the
                [BatchUpdateServices][google.firebase.appcheck.v1beta.ConfigService.BatchUpdateServices]
                method.

        """

        # Jsonify the request body
        body = configuration.BatchUpdateServicesRequest.to_json(
            request,
            use_integers_for_enums=False
        )

        # TODO(yon-mg): need to handle grpc transcoding and parse url correctly
        #               current impl assumes basic case of grpc transcoding
        url = 'https://{host}/v1beta/{parent=projects/*}/services:batchUpdate'.format(
            host=self._host,
        )

        # TODO(yon-mg): handle nested fields corerctly rather than using only top level fields
        #               not required for GCE
        query_params = {}
        query_params['parent'] = request.parent
        query_params['requests'] = request.requests
        query_params['updateMask'] = request.update_mask

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
        return configuration.BatchUpdateServicesResponse.from_json(
            response.content,
            ignore_unknown_fields=True
        )


__all__ = (
    'ConfigServiceRestTransport',
)
