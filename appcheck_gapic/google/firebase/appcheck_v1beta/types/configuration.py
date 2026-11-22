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
import proto  # type: ignore

from google.protobuf import duration_pb2  # type: ignore
from google.protobuf import field_mask_pb2  # type: ignore


__protobuf__ = proto.module(
    package='google.firebase.appcheck.v1beta',
    manifest={
        'AppAttestConfig',
        'GetAppAttestConfigRequest',
        'BatchGetAppAttestConfigsRequest',
        'BatchGetAppAttestConfigsResponse',
        'UpdateAppAttestConfigRequest',
        'DeviceCheckConfig',
        'GetDeviceCheckConfigRequest',
        'BatchGetDeviceCheckConfigsRequest',
        'BatchGetDeviceCheckConfigsResponse',
        'UpdateDeviceCheckConfigRequest',
        'RecaptchaConfig',
        'GetRecaptchaConfigRequest',
        'BatchGetRecaptchaConfigsRequest',
        'BatchGetRecaptchaConfigsResponse',
        'UpdateRecaptchaConfigRequest',
        'SafetyNetConfig',
        'GetSafetyNetConfigRequest',
        'BatchGetSafetyNetConfigsRequest',
        'BatchGetSafetyNetConfigsResponse',
        'UpdateSafetyNetConfigRequest',
        'DebugToken',
        'GetDebugTokenRequest',
        'ListDebugTokensRequest',
        'ListDebugTokensResponse',
        'CreateDebugTokenRequest',
        'UpdateDebugTokenRequest',
        'DeleteDebugTokenRequest',
        'Service',
        'GetServiceRequest',
        'ListServicesRequest',
        'ListServicesResponse',
        'UpdateServiceRequest',
        'BatchUpdateServicesRequest',
        'BatchUpdateServicesResponse',
    },
)


class AppAttestConfig(proto.Message):
    r"""An app's App Attest configuration object. This configuration
    controls certain properties of the [App Check
    token][google.firebase.appcheck.v1beta.AttestationTokenResponse]
    returned by
    [ExchangeAppAttestAttestation][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeAppAttestAttestation]
    and
    [ExchangeAppAttestAttestation][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeAppAttestAssertion],
    such as its
    [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

    Note that the Team ID registered with your app is used as part of
    the validation process. Please register it via the Firebase Console
    or programmatically via the `Firebase Management
    Service <https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.iosApps/patch>`__.

    Attributes:
        name (str):
            Required. The relative resource name of the App Attest
            configuration object, in the format:

            ::

               projects/{project_number}/apps/{app_id}/appAttestConfig
        token_ttl (google.protobuf.duration_pb2.Duration):
            Specifies the duration for which App Check
            tokens exchanged from App Attest artifacts will
            be valid. If unset, a default value of 1 hour is
            assumed. Must be between 30 minutes and 7 days,
            inclusive.
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )
    token_ttl = proto.Field(
        proto.MESSAGE,
        number=2,
        message=duration_pb2.Duration,
    )


class GetAppAttestConfigRequest(proto.Message):
    r"""Request message for the
    [GetAppAttestConfig][google.firebase.appcheck.v1beta.ConfigService.GetAppAttestConfig]
    method.

    Attributes:
        name (str):
            Required. The relative resource name of the
            [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig],
            in the format:

            ::

               projects/{project_number}/apps/{app_id}/appAttestConfig
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )


class BatchGetAppAttestConfigsRequest(proto.Message):
    r"""Request message for the
    [BatchGetAppAttestConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetAppAttestConfigs]
    method.

    Attributes:
        parent (str):
            Required. The parent project name shared by all
            [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]s
            being retrieved, in the format

            ::

               projects/{project_number}

            The parent collection in the ``name`` field of any resource
            being retrieved must match this field, or the entire batch
            fails.
        names (Sequence[str]):
            Required. The relative resource names of the
            [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]s
            to retrieve, in the format

            ::

               projects/{project_number}/apps/{app_id}/appAttestConfig

            A maximum of 100 objects can be retrieved in a batch.
    """

    parent = proto.Field(
        proto.STRING,
        number=1,
    )
    names = proto.RepeatedField(
        proto.STRING,
        number=2,
    )


class BatchGetAppAttestConfigsResponse(proto.Message):
    r"""Response message for the
    [BatchGetAppAttestConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetAppAttestConfigs]
    method.

    Attributes:
        configs (Sequence[google.firebase.appcheck_v1beta.types.AppAttestConfig]):
            [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]s
            retrieved.
    """

    configs = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message='AppAttestConfig',
    )


class UpdateAppAttestConfigRequest(proto.Message):
    r"""Request message for the
    [UpdateAppAttestConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateAppAttestConfig]
    method.

    Attributes:
        app_attest_config (google.firebase.appcheck_v1beta.types.AppAttestConfig):
            Required. The
            [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]
            to update.

            The
            [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]'s
            ``name`` field is used to identify the configuration to be
            updated, in the format:

            ::

               projects/{project_number}/apps/{app_id}/appAttestConfig
        update_mask (google.protobuf.field_mask_pb2.FieldMask):
            Required. A comma-separated list of names of fields in the
            [AppAttestConfig][google.firebase.appcheck.v1beta.AppAttestConfig]
            Gets to update. Example: ``token_ttl``.
    """

    app_attest_config = proto.Field(
        proto.MESSAGE,
        number=1,
        message='AppAttestConfig',
    )
    update_mask = proto.Field(
        proto.MESSAGE,
        number=2,
        message=field_mask_pb2.FieldMask,
    )


class DeviceCheckConfig(proto.Message):
    r"""An app's DeviceCheck configuration object. This configuration is
    used by
    [ExchangeDeviceCheckToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeDeviceCheckToken]
    to validate device tokens issued to apps by DeviceCheck. It also
    controls certain properties of the returned [App Check
    token][google.firebase.appcheck.v1beta.AttestationTokenResponse],
    such as its
    [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

    Note that the Team ID registered with your app is used as part of
    the validation process. Please register it via the Firebase Console
    or programmatically via the `Firebase Management
    Service <https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.iosApps/patch>`__.

    Attributes:
        name (str):
            Required. The relative resource name of the DeviceCheck
            configuration object, in the format:

            ::

               projects/{project_number}/apps/{app_id}/deviceCheckConfig
        token_ttl (google.protobuf.duration_pb2.Duration):
            Specifies the duration for which App Check
            tokens exchanged from DeviceCheck tokens will be
            valid. If unset, a default value of 1 hour is
            assumed. Must be between 30 minutes and 7 days,
            inclusive.
        key_id (str):
            Required. The key identifier of a private key
            enabled with DeviceCheck, created in your Apple
            Developer account.
        private_key (str):
            Required. Input only. The contents of the private key
            (``.p8``) file associated with the key specified by
            ``key_id``.

            For security reasons, this field will never be populated in
            any response.
        private_key_set (bool):
            Output only. Whether the ``private_key`` field was
            previously set. Since we will never return the
            ``private_key`` field, this field is the only way to find
            out whether it was previously set.
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )
    token_ttl = proto.Field(
        proto.MESSAGE,
        number=5,
        message=duration_pb2.Duration,
    )
    key_id = proto.Field(
        proto.STRING,
        number=2,
    )
    private_key = proto.Field(
        proto.STRING,
        number=3,
    )
    private_key_set = proto.Field(
        proto.BOOL,
        number=4,
    )


class GetDeviceCheckConfigRequest(proto.Message):
    r"""Request message for the
    [GetDeviceCheckConfig][google.firebase.appcheck.v1beta.ConfigService.GetDeviceCheckConfig]
    method.

    Attributes:
        name (str):
            Required. The relative resource name of the
            [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig],
            in the format:

            ::

               projects/{project_number}/apps/{app_id}/deviceCheckConfig
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )


class BatchGetDeviceCheckConfigsRequest(proto.Message):
    r"""Request message for the
    [BatchGetDeviceCheckConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetDeviceCheckConfigs]
    method.

    Attributes:
        parent (str):
            Required. The parent project name shared by all
            [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]s
            being retrieved, in the format

            ::

               projects/{project_number}

            The parent collection in the ``name`` field of any resource
            being retrieved must match this field, or the entire batch
            fails.
        names (Sequence[str]):
            Required. The relative resource names of the
            [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]s
            to retrieve, in the format

            ::

               projects/{project_number}/apps/{app_id}/deviceCheckConfig

            A maximum of 100 objects can be retrieved in a batch.
    """

    parent = proto.Field(
        proto.STRING,
        number=1,
    )
    names = proto.RepeatedField(
        proto.STRING,
        number=2,
    )


class BatchGetDeviceCheckConfigsResponse(proto.Message):
    r"""Response message for the
    [BatchGetDeviceCheckConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetDeviceCheckConfigs]
    method.

    Attributes:
        configs (Sequence[google.firebase.appcheck_v1beta.types.DeviceCheckConfig]):
            [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]s
            retrieved.
    """

    configs = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message='DeviceCheckConfig',
    )


class UpdateDeviceCheckConfigRequest(proto.Message):
    r"""Request message for the
    [UpdateDeviceCheckConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateDeviceCheckConfig]
    method.

    Attributes:
        device_check_config (google.firebase.appcheck_v1beta.types.DeviceCheckConfig):
            Required. The
            [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]
            to update.

            The
            [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]'s
            ``name`` field is used to identify the configuration to be
            updated, in the format:

            ::

               projects/{project_number}/apps/{app_id}/deviceCheckConfig
        update_mask (google.protobuf.field_mask_pb2.FieldMask):
            Required. A comma-separated list of names of fields in the
            [DeviceCheckConfig][google.firebase.appcheck.v1beta.DeviceCheckConfig]
            Gets to update. Example: ``key_id,private_key``.
    """

    device_check_config = proto.Field(
        proto.MESSAGE,
        number=1,
        message='DeviceCheckConfig',
    )
    update_mask = proto.Field(
        proto.MESSAGE,
        number=2,
        message=field_mask_pb2.FieldMask,
    )


class RecaptchaConfig(proto.Message):
    r"""An app's reCAPTCHA v3 configuration object. This configuration is
    used by
    [ExchangeRecaptchaToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeRecaptchaToken]
    to validate reCAPTCHA tokens issued to apps by reCAPTCHA v3. It also
    controls certain properties of the returned [App Check
    token][google.firebase.appcheck.v1beta.AttestationTokenResponse],
    such as its
    [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

    Attributes:
        token_ttl (google.protobuf.duration_pb2.Duration):
            Specifies the duration for which App Check
            tokens exchanged from reCAPTCHA tokens will be
            valid. If unset, a default value of 1 day is
            assumed. Must be between 30 minutes and 7 days,
            inclusive.
        name (str):
            Required. The relative resource name of the reCAPTCHA v3
            configuration object, in the format:

            ::

               projects/{project_number}/apps/{app_id}/recaptchaConfig
        site_secret (str):
            Required. Input only. The site secret used to
            identify your service for reCAPTCHA v3
            verification.
            For security reasons, this field will never be
            populated in any response.
        site_secret_set (bool):
            Output only. Whether the ``site_secret`` field was
            previously set. Since we will never return the
            ``site_secret`` field, this field is the only way to find
            out whether it was previously set.
    """

    token_ttl = proto.Field(
        proto.MESSAGE,
        number=4,
        message=duration_pb2.Duration,
    )
    name = proto.Field(
        proto.STRING,
        number=1,
    )
    site_secret = proto.Field(
        proto.STRING,
        number=2,
    )
    site_secret_set = proto.Field(
        proto.BOOL,
        number=3,
    )


class GetRecaptchaConfigRequest(proto.Message):
    r"""Request message for the
    [GetRecaptchaConfig][google.firebase.appcheck.v1beta.ConfigService.GetRecaptchaConfig]
    method.

    Attributes:
        name (str):
            Required. The relative resource name of the
            [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig],
            in the format:

            ::

               projects/{project_number}/apps/{app_id}/recaptchaConfig
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )


class BatchGetRecaptchaConfigsRequest(proto.Message):
    r"""Request message for the
    [BatchGetRecaptchaConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetRecaptchaConfigs]
    method.

    Attributes:
        parent (str):
            Required. The parent project name shared by all
            [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]s
            being retrieved, in the format

            ::

               projects/{project_number}

            The parent collection in the ``name`` field of any resource
            being retrieved must match this field, or the entire batch
            fails.
        names (Sequence[str]):
            Required. The relative resource names of the
            [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]s
            to retrieve, in the format:

            ::

               projects/{project_number}/apps/{app_id}/recaptchaConfig

            A maximum of 100 objects can be retrieved in a batch.
    """

    parent = proto.Field(
        proto.STRING,
        number=1,
    )
    names = proto.RepeatedField(
        proto.STRING,
        number=2,
    )


class BatchGetRecaptchaConfigsResponse(proto.Message):
    r"""Response message for the
    [BatchGetRecaptchaConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetRecaptchaConfigs]
    method.

    Attributes:
        configs (Sequence[google.firebase.appcheck_v1beta.types.RecaptchaConfig]):
            [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]s
            retrieved.
    """

    configs = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message='RecaptchaConfig',
    )


class UpdateRecaptchaConfigRequest(proto.Message):
    r"""Request message for the
    [UpdateRecaptchaConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateRecaptchaConfig]
    method.

    Attributes:
        recaptcha_config (google.firebase.appcheck_v1beta.types.RecaptchaConfig):
            Required. The
            [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]
            to update.

            The
            [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]'s
            ``name`` field is used to identify the configuration to be
            updated, in the format:

            ::

               projects/{project_number}/apps/{app_id}/recaptchaConfig
        update_mask (google.protobuf.field_mask_pb2.FieldMask):
            Required. A comma-separated list of names of fields in the
            [RecaptchaConfig][google.firebase.appcheck.v1beta.RecaptchaConfig]
            to update. Example: ``site_secret``.
    """

    recaptcha_config = proto.Field(
        proto.MESSAGE,
        number=1,
        message='RecaptchaConfig',
    )
    update_mask = proto.Field(
        proto.MESSAGE,
        number=2,
        message=field_mask_pb2.FieldMask,
    )


class SafetyNetConfig(proto.Message):
    r"""An app's SafetyNet configuration object. This configuration controls
    certain properties of the [App Check
    token][google.firebase.appcheck.v1beta.AttestationTokenResponse]
    returned by
    [ExchangeSafetyNetToken][google.firebase.appcheck.v1beta.TokenExchangeService.ExchangeSafetyNetToken],
    such as its
    [ttl][google.firebase.appcheck.v1beta.AttestationTokenResponse.ttl].

    Note that your registered SHA-256 certificate fingerprints are used
    to validate tokens issued by SafetyNet; please register them via the
    Firebase Console or programmatically via the `Firebase Management
    Service <https://firebase.google.com/docs/projects/api/reference/rest/v1beta1/projects.androidApps.sha/create>`__.

    Attributes:
        name (str):
            Required. The relative resource name of the SafetyNet
            configuration object, in the format:

            ::

               projects/{project_number}/apps/{app_id}/safetyNetConfig
        token_ttl (google.protobuf.duration_pb2.Duration):
            Specifies the duration for which App Check
            tokens exchanged from SafetyNet tokens will be
            valid. If unset, a default value of 1 hour is
            assumed. Must be between 30 minutes and 7 days,
            inclusive.
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )
    token_ttl = proto.Field(
        proto.MESSAGE,
        number=2,
        message=duration_pb2.Duration,
    )


class GetSafetyNetConfigRequest(proto.Message):
    r"""Request message for the
    [GetSafetyNetConfig][google.firebase.appcheck.v1beta.ConfigService.GetSafetyNetConfig]
    method.

    Attributes:
        name (str):
            Required. The relative resource name of the
            [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig],
            in the format:

            ::

               projects/{project_number}/apps/{app_id}/safetyNetConfig
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )


class BatchGetSafetyNetConfigsRequest(proto.Message):
    r"""Request message for the
    [BatchGetSafetyNetConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetSafetyNetConfigs]
    method.

    Attributes:
        parent (str):
            Required. The parent project name shared by all
            [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]s
            being retrieved, in the format

            ::

               projects/{project_number}

            The parent collection in the ``name`` field of any resource
            being retrieved must match this field, or the entire batch
            fails.
        names (Sequence[str]):
            Required. The relative resource names of the
            [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]s
            to retrieve, in the format

            ::

               projects/{project_number}/apps/{app_id}/safetyNetConfig

            A maximum of 100 objects can be retrieved in a batch.
    """

    parent = proto.Field(
        proto.STRING,
        number=1,
    )
    names = proto.RepeatedField(
        proto.STRING,
        number=2,
    )


class BatchGetSafetyNetConfigsResponse(proto.Message):
    r"""Response message for the
    [BatchGetSafetyNetConfigs][google.firebase.appcheck.v1beta.ConfigService.BatchGetSafetyNetConfigs]
    method.

    Attributes:
        configs (Sequence[google.firebase.appcheck_v1beta.types.SafetyNetConfig]):
            [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]s
            retrieved.
    """

    configs = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message='SafetyNetConfig',
    )


class UpdateSafetyNetConfigRequest(proto.Message):
    r"""Request message for the
    [UpdateSafetyNetConfig][google.firebase.appcheck.v1beta.ConfigService.UpdateSafetyNetConfig]
    method.

    Attributes:
        safety_net_config (google.firebase.appcheck_v1beta.types.SafetyNetConfig):
            Required. The
            [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]
            to update.

            The
            [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]'s
            ``name`` field is used to identify the configuration to be
            updated, in the format:

            ::

               projects/{project_number}/apps/{app_id}/safetyNetConfig
        update_mask (google.protobuf.field_mask_pb2.FieldMask):
            Required. A comma-separated list of names of fields in the
            [SafetyNetConfig][google.firebase.appcheck.v1beta.SafetyNetConfig]
            Gets to update. Example: ``token_ttl``.
    """

    safety_net_config = proto.Field(
        proto.MESSAGE,
        number=1,
        message='SafetyNetConfig',
    )
    update_mask = proto.Field(
        proto.MESSAGE,
        number=2,
        message=field_mask_pb2.FieldMask,
    )


class DebugToken(proto.Message):
    r"""A *debug token* is a secret used during the development or
    integration testing of an app. It essentially allows the development
    or integration testing to bypass app attestation while still
    allowing App Check to enforce protection on supported production
    Firebase services.

    Attributes:
        name (str):
            The relative resource name of the debug token, in the
            format:

            ::

               projects/{project_number}/apps/{app_id}/debugTokens/{debug_token_id}
        display_name (str):
            Required. A human readable display name used
            to identify this debug token.
        token (str):
            Input only. Immutable. The secret token itself. Must be
            provided during creation, and must be a UUID4, case
            insensitive.

            This field is immutable once set, and cannot be provided
            during an
            [UpdateDebugToken][google.firebase.appcheck.v1beta.ConfigService.UpdateDebugToken]
            request. You can, however, delete this debug token using
            [DeleteDebugToken][google.firebase.appcheck.v1beta.ConfigService.DeleteDebugToken]
            to revoke it.

            For security reasons, this field will never be populated in
            any response.
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )
    display_name = proto.Field(
        proto.STRING,
        number=2,
    )
    token = proto.Field(
        proto.STRING,
        number=3,
    )


class GetDebugTokenRequest(proto.Message):
    r"""Request message for the
    [GetDebugToken][google.firebase.appcheck.v1beta.ConfigService.GetDebugToken]
    method.

    Attributes:
        name (str):
            Required. The relative resource name of the debug token, in
            the format:

            ::

               projects/{project_number}/apps/{app_id}/debugTokens/{debug_token_id}
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )


class ListDebugTokensRequest(proto.Message):
    r"""Request message for the
    [ListDebugTokens][google.firebase.appcheck.v1beta.ConfigService.ListDebugTokens]
    method.

    Attributes:
        parent (str):
            Required. The relative resource name of the parent app for
            which to list each associated
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken], in
            the format:

            ::

               projects/{project_number}/apps/{app_id}
        page_size (int):
            The maximum number of
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken]s to
            return in the response. Note that an app can have at most 20
            debug tokens.

            The server may return fewer than this at its own discretion.
            If no value is specified (or too large a value is
            specified), the server will impose its own limit.
        page_token (str):
            Token returned from a previous call to
            [ListDebugTokens][google.firebase.appcheck.v1beta.ConfigService.ListDebugTokens]
            indicating where in the set of
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken]s to
            resume listing. Provide this to retrieve the subsequent
            page.

            When paginating, all other parameters provided to
            [ListDebugTokens][google.firebase.appcheck.v1beta.ConfigService.ListDebugTokens]
            must match the call that provided the page token; if they do
            not match, the result is undefined.
    """

    parent = proto.Field(
        proto.STRING,
        number=1,
    )
    page_size = proto.Field(
        proto.INT32,
        number=2,
    )
    page_token = proto.Field(
        proto.STRING,
        number=3,
    )


class ListDebugTokensResponse(proto.Message):
    r"""Response message for the
    [ListDebugTokens][google.firebase.appcheck.v1beta.ConfigService.ListDebugTokens]
    method.

    Attributes:
        debug_tokens (Sequence[google.firebase.appcheck_v1beta.types.DebugToken]):
            The
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken]s
            retrieved.
        next_page_token (str):
            If the result list is too large to fit in a single response,
            then a token is returned. If the string is empty or omitted,
            then this response is the last page of results.

            This token can be used in a subsequent call to
            [ListDebugTokens][google.firebase.appcheck.v1beta.ConfigService.ListDebugTokens]
            to find the next group of
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken]s.

            Page tokens are short-lived and should not be persisted.
    """

    @property
    def raw_page(self):
        return self

    debug_tokens = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message='DebugToken',
    )
    next_page_token = proto.Field(
        proto.STRING,
        number=2,
    )


class CreateDebugTokenRequest(proto.Message):
    r"""Request message for the
    [CreateDebugToken][google.firebase.appcheck.v1beta.ConfigService.CreateDebugToken]
    method.

    Attributes:
        parent (str):
            Required. The relative resource name of the parent app in
            which the specified
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken]
            will be created, in the format:

            ::

               projects/{project_number}/apps/{app_id}
        debug_token (google.firebase.appcheck_v1beta.types.DebugToken):
            Required. The
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken] to
            create.

            For security reasons, after creation, the ``token`` field of
            the [DebugToken][google.firebase.appcheck.v1beta.DebugToken]
            will never be populated in any response.
    """

    parent = proto.Field(
        proto.STRING,
        number=1,
    )
    debug_token = proto.Field(
        proto.MESSAGE,
        number=2,
        message='DebugToken',
    )


class UpdateDebugTokenRequest(proto.Message):
    r"""Request message for the
    [UpdateDebugToken][google.firebase.appcheck.v1beta.ConfigService.UpdateDebugToken]
    method.

    Attributes:
        debug_token (google.firebase.appcheck_v1beta.types.DebugToken):
            Required. The
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken] to
            update.

            The
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken]'s
            ``name`` field is used to identify the
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken] to
            be updated, in the format:

            ::

               projects/{project_number}/apps/{app_id}/debugTokens/{debug_token_id}
        update_mask (google.protobuf.field_mask_pb2.FieldMask):
            Required. A comma-separated list of names of fields in the
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken] to
            update. Example: ``display_name``.
    """

    debug_token = proto.Field(
        proto.MESSAGE,
        number=1,
        message='DebugToken',
    )
    update_mask = proto.Field(
        proto.MESSAGE,
        number=2,
        message=field_mask_pb2.FieldMask,
    )


class DeleteDebugTokenRequest(proto.Message):
    r"""Request message for the
    [DeleteDebugToken][google.firebase.appcheck.v1beta.ConfigService.DeleteDebugToken]
    method.

    Attributes:
        name (str):
            Required. The relative resource name of the
            [DebugToken][google.firebase.appcheck.v1beta.DebugToken] to
            delete, in the format:

            ::

               projects/{project_number}/apps/{app_id}/debugTokens/{debug_token_id}
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )


class Service(proto.Message):
    r"""The enforcement configuration for a Firebase service
    supported by App Check.

    Attributes:
        name (str):
            Required. The relative resource name of the service
            configuration object, in the format:

            ::

               projects/{project_number}/services/{service_id}

            Note that the ``service_id`` element must be a supported
            service ID. Currently, the following service IDs are
            supported:

            -  ``firebasestorage.googleapis.com`` (Cloud Storage for
               Firebase)
            -  ``firebasedatabase.googleapis.com`` (Firebase Realtime
               Database)
        enforcement_mode (google.firebase.appcheck_v1beta.types.Service.EnforcementMode):
            Required. The App Check enforcement mode for
            this service.
    """
    class EnforcementMode(proto.Enum):
        r"""The App Check enforcement mode for a Firebase service
        supported by App Check.
        """
        OFF = 0
        UNENFORCED = 1
        ENFORCED = 2

    name = proto.Field(
        proto.STRING,
        number=1,
    )
    enforcement_mode = proto.Field(
        proto.ENUM,
        number=2,
        enum=EnforcementMode,
    )


class GetServiceRequest(proto.Message):
    r"""Request message for the
    [GetService][google.firebase.appcheck.v1beta.ConfigService.GetService]
    method.

    Attributes:
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
            -  ``firebasedatabase.googleapis.com`` (Firebase Realtime
               Database)
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )


class ListServicesRequest(proto.Message):
    r"""Request message for the
    [ListServices][google.firebase.appcheck.v1beta.ConfigService.ListServices]
    method.

    Attributes:
        parent (str):
            Required. The relative resource name of the parent project
            for which to list each associated
            [Service][google.firebase.appcheck.v1beta.Service], in the
            format:

            ::

               projects/{project_number}
        page_size (int):
            The maximum number of
            [Service][google.firebase.appcheck.v1beta.Service]s to
            return in the response. Only explicitly configured services
            are returned.

            The server may return fewer than this at its own discretion.
            If no value is specified (or too large a value is
            specified), the server will impose its own limit.
        page_token (str):
            Token returned from a previous call to
            [ListServices][google.firebase.appcheck.v1beta.ConfigService.ListServices]
            indicating where in the set of
            [Service][google.firebase.appcheck.v1beta.Service]s to
            resume listing. Provide this to retrieve the subsequent
            page.

            When paginating, all other parameters provided to
            [ListServices][google.firebase.appcheck.v1beta.ConfigService.ListServices]
            must match the call that provided the page token; if they do
            not match, the result is undefined.
    """

    parent = proto.Field(
        proto.STRING,
        number=1,
    )
    page_size = proto.Field(
        proto.INT32,
        number=2,
    )
    page_token = proto.Field(
        proto.STRING,
        number=3,
    )


class ListServicesResponse(proto.Message):
    r"""Response message for the
    [ListServices][google.firebase.appcheck.v1beta.ConfigService.ListServices]
    method.

    Attributes:
        services (Sequence[google.firebase.appcheck_v1beta.types.Service]):
            The [Service][google.firebase.appcheck.v1beta.Service]s
            retrieved.
        next_page_token (str):
            If the result list is too large to fit in a single response,
            then a token is returned. If the string is empty or omitted,
            then this response is the last page of results.

            This token can be used in a subsequent call to
            [ListServices][google.firebase.appcheck.v1beta.ConfigService.ListServices]
            to find the next group of
            [Service][google.firebase.appcheck.v1beta.Service]s.

            Page tokens are short-lived and should not be persisted.
    """

    @property
    def raw_page(self):
        return self

    services = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message='Service',
    )
    next_page_token = proto.Field(
        proto.STRING,
        number=2,
    )


class UpdateServiceRequest(proto.Message):
    r"""Request message for the
    [UpdateService][google.firebase.appcheck.v1beta.ConfigService.UpdateService]
    method as well as an individual update message for the
    [BatchUpdateServices][google.firebase.appcheck.v1beta.ConfigService.BatchUpdateServices]
    method.

    Attributes:
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
            -  ``firebasedatabase.googleapis.com`` (Firebase Realtime
               Database)
        update_mask (google.protobuf.field_mask_pb2.FieldMask):
            Required. A comma-separated list of names of fields in the
            [Service][google.firebase.appcheck.v1beta.Service] to
            update. Example: ``enforcement_mode``.
    """

    service = proto.Field(
        proto.MESSAGE,
        number=1,
        message='Service',
    )
    update_mask = proto.Field(
        proto.MESSAGE,
        number=2,
        message=field_mask_pb2.FieldMask,
    )


class BatchUpdateServicesRequest(proto.Message):
    r"""Request message for the
    [BatchUpdateServices][google.firebase.appcheck.v1beta.ConfigService.BatchUpdateServices]
    method.

    Attributes:
        parent (str):
            Required. The parent project name shared by all
            [Service][google.firebase.appcheck.v1beta.Service]
            configurations being updated, in the format

            ::

               projects/{project_number}

            The parent collection in the ``name`` field of any resource
            being updated must match this field, or the entire batch
            fails.
        update_mask (google.protobuf.field_mask_pb2.FieldMask):
            Optional. A comma-separated list of names of fields in the
            [Service][google.firebase.appcheck.v1beta.Service]s to
            update. Example: ``display_name``.

            If this field is present, the ``update_mask`` field in the
            [UpdateServiceRequest][google.firebase.appcheck.v1beta.UpdateServiceRequest]
            messages must all match this field, or the entire batch
            fails and no updates will be committed.
        requests (Sequence[google.firebase.appcheck_v1beta.types.UpdateServiceRequest]):
            Required. The request messages specifying the
            [Service][google.firebase.appcheck.v1beta.Service]s to
            update.

            A maximum of 100 objects can be updated in a batch.
    """

    parent = proto.Field(
        proto.STRING,
        number=1,
    )
    update_mask = proto.Field(
        proto.MESSAGE,
        number=2,
        message=field_mask_pb2.FieldMask,
    )
    requests = proto.RepeatedField(
        proto.MESSAGE,
        number=3,
        message='UpdateServiceRequest',
    )


class BatchUpdateServicesResponse(proto.Message):
    r"""Response message for the
    [BatchUpdateServices][google.firebase.appcheck.v1beta.ConfigService.BatchUpdateServices]
    method.

    Attributes:
        services (Sequence[google.firebase.appcheck_v1beta.types.Service]):
            [Service][google.firebase.appcheck.v1beta.Service] objects
            after the updates have been applied.
    """

    services = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message='Service',
    )


__all__ = tuple(sorted(__protobuf__.manifest))
