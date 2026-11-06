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


__protobuf__ = proto.module(
    package='google.firebase.appcheck.v1beta',
    manifest={
        'GetPublicJwkSetRequest',
        'PublicJwkSet',
        'PublicJwk',
        'ExchangeSafetyNetTokenRequest',
        'ExchangeDeviceCheckTokenRequest',
        'ExchangeRecaptchaTokenRequest',
        'ExchangeCustomTokenRequest',
        'AttestationTokenResponse',
        'ExchangeDebugTokenRequest',
        'GenerateAppAttestChallengeRequest',
        'AppAttestChallengeResponse',
        'ExchangeAppAttestAttestationRequest',
        'ExchangeAppAttestAttestationResponse',
        'ExchangeAppAttestAssertionRequest',
    },
)


class GetPublicJwkSetRequest(proto.Message):
    r"""Request message for the [GetPublicJwkSet][] method.
    Attributes:
        name (str):
            Required. The relative resource name to the public JWK set.
            Must always be exactly the string ``jwks``.
    """

    name = proto.Field(
        proto.STRING,
        number=1,
    )


class PublicJwkSet(proto.Message):
    r"""The currently active set of public keys that can be used to verify
    App Check tokens.

    This object is a JWK set as specified by `section 5 of RFC
    7517 <https://tools.ietf.org/html/rfc7517#section-5>`__.

    For security, the response **must not** be cached for longer than
    one day.

    Attributes:
        keys (Sequence[google.firebase.appcheck_v1beta.types.PublicJwk]):
            The set of public keys. See `section 5.1 of RFC
            7517 <https://tools.ietf.org/html/rfc7517#section-5>`__.
    """

    keys = proto.RepeatedField(
        proto.MESSAGE,
        number=1,
        message='PublicJwk',
    )


class PublicJwk(proto.Message):
    r"""A JWK as specified by `section 4 of RFC
    7517 <https://tools.ietf.org/html/rfc7517#section-4>`__ and `section
    6.3.1 of RFC
    7518 <https://tools.ietf.org/html/rfc7518#section-6.3.1>`__.

    Attributes:
        kty (str):
            See `section 4.1 of RFC
            7517 <https://tools.ietf.org/html/rfc7517#section-4.1>`__.
        use (str):
            See `section 4.2 of RFC
            7517 <https://tools.ietf.org/html/rfc7517#section-4.2>`__.
        alg (str):
            See `section 4.4 of RFC
            7517 <https://tools.ietf.org/html/rfc7517#section-4.4>`__.
        kid (str):
            See `section 4.5 of RFC
            7517 <https://tools.ietf.org/html/rfc7517#section-4.5>`__.
        n (str):
            See `section 6.3.1.1 of RFC
            7518 <https://tools.ietf.org/html/rfc7518#section-6.3.1.1>`__.
        e (str):
            See `section 6.3.1.2 of RFC
            7518 <https://tools.ietf.org/html/rfc7518#section-6.3.1.2>`__.
    """

    kty = proto.Field(
        proto.STRING,
        number=1,
    )
    use = proto.Field(
        proto.STRING,
        number=2,
    )
    alg = proto.Field(
        proto.STRING,
        number=3,
    )
    kid = proto.Field(
        proto.STRING,
        number=4,
    )
    n = proto.Field(
        proto.STRING,
        number=5,
    )
    e = proto.Field(
        proto.STRING,
        number=6,
    )


class ExchangeSafetyNetTokenRequest(proto.Message):
    r"""Request message for the [ExchangeSafetyNetToken][] method.
    Attributes:
        app (str):
            Required. The relative resource name of the Android app, in
            the format:

            ::

               projects/{project_number}/apps/{app_id}

            If necessary, the ``project_number`` element can be replaced
            with the project ID of the Firebase project. Learn more
            about using project identifiers in Google's `AIP
            2510 <https://google.aip.dev/cloud/2510>`__ standard.
        safety_net_token (str):
            The `SafetyNet attestation
            response <https://developer.android.com/training/safetynet/attestation#request-attestation-step>`__
            issued to your app.
    """

    app = proto.Field(
        proto.STRING,
        number=1,
    )
    safety_net_token = proto.Field(
        proto.STRING,
        number=2,
    )


class ExchangeDeviceCheckTokenRequest(proto.Message):
    r"""Request message for the [ExchangeDeviceCheckToken][] method.
    Attributes:
        app (str):
            Required. The relative resource name of the iOS app, in the
            format:

            ::

               projects/{project_number}/apps/{app_id}

            If necessary, the ``project_number`` element can be replaced
            with the project ID of the Firebase project. Learn more
            about using project identifiers in Google's `AIP
            2510 <https://google.aip.dev/cloud/2510>`__ standard.
        device_token (str):
            The ``device_token`` as returned by Apple's client-side
            `DeviceCheck
            API <https://developer.apple.com/documentation/devicecheck/dcdevice>`__.
            This is the Base64 encoded ``Data`` (Swift) or ``NSData``
            (ObjC) object.
    """

    app = proto.Field(
        proto.STRING,
        number=1,
    )
    device_token = proto.Field(
        proto.STRING,
        number=2,
    )


class ExchangeRecaptchaTokenRequest(proto.Message):
    r"""Request message for the [ExchangeRecaptchaToken][] method.
    Attributes:
        app (str):
            Required. The relative resource name of the web app, in the
            format:

            ::

               projects/{project_number}/apps/{app_id}

            If necessary, the ``project_number`` element can be replaced
            with the project ID of the Firebase project. Learn more
            about using project identifiers in Google's `AIP
            2510 <https://google.aip.dev/cloud/2510>`__ standard.
        recaptcha_token (str):
            The reCAPTCHA token as returned by the `reCAPTCHA v3
            JavaScript
            API <https://developers.google.com/recaptcha/docs/v3>`__.
    """

    app = proto.Field(
        proto.STRING,
        number=1,
    )
    recaptcha_token = proto.Field(
        proto.STRING,
        number=2,
    )


class ExchangeCustomTokenRequest(proto.Message):
    r"""Request message for the [ExchangeCustomToken][] method.
    Attributes:
        app (str):
            Required. The relative resource name of the app, in the
            format:

            ::

               projects/{project_number}/apps/{app_id}

            If necessary, the ``project_number`` element can be replaced
            with the project ID of the Firebase project. Learn more
            about using project identifiers in Google's `AIP
            2510 <https://google.aip.dev/cloud/2510>`__ standard.
        custom_token (str):
            A custom token signed using your project's
            Admin SDK service account credentials.
    """

    app = proto.Field(
        proto.STRING,
        number=1,
    )
    custom_token = proto.Field(
        proto.STRING,
        number=2,
    )


class AttestationTokenResponse(proto.Message):
    r"""Encapsulates an *App Check token*, which are used to access Firebase
    services protected by App Check.

    Attributes:
        attestation_token (str):
            An App Check token.

            App Check tokens are signed
            `JWTs <https://tools.ietf.org/html/rfc7519>`__ containing
            claims that identify the attested app and Firebase project.
            This token is used to access Firebase services protected by
            App Check.
        ttl (google.protobuf.duration_pb2.Duration):
            The duration from the time this token is
            minted until its expiration. This field is
            intended to ease client-side token management,
            since the client may have clock skew, but is
            still able to accurately measure a duration.
    """

    attestation_token = proto.Field(
        proto.STRING,
        number=1,
    )
    ttl = proto.Field(
        proto.MESSAGE,
        number=2,
        message=duration_pb2.Duration,
    )


class ExchangeDebugTokenRequest(proto.Message):
    r"""Request message for the [ExchangeDebugToken][] method.
    Attributes:
        app (str):
            Required. The relative resource name of the app, in the
            format:

            ::

               projects/{project_number}/apps/{app_id}

            If necessary, the ``project_number`` element can be replaced
            with the project ID of the Firebase project. Learn more
            about using project identifiers in Google's `AIP
            2510 <https://google.aip.dev/cloud/2510>`__ standard.
        debug_token (str):
            A debug token secret. This string must match a debug token
            secret previously created using
            [CreateDebugToken][google.firebase.appcheck.v1beta.ConfigService.CreateDebugToken].
    """

    app = proto.Field(
        proto.STRING,
        number=1,
    )
    debug_token = proto.Field(
        proto.STRING,
        number=2,
    )


class GenerateAppAttestChallengeRequest(proto.Message):
    r"""Request message for GenerateAppAttestChallenge
    Attributes:
        app (str):
            Required. The full resource name to the iOS App. Format:
            "projects/{project_id}/apps/{app_id}".
    """

    app = proto.Field(
        proto.STRING,
        number=1,
    )


class AppAttestChallengeResponse(proto.Message):
    r"""Response object for GenerateAppAttestChallenge
    Attributes:
        challenge (bytes):
            A one time use challenge for the client to
            pass to Apple's App Attest API.
        ttl (google.protobuf.duration_pb2.Duration):
            The duration from the time this challenge is
            minted until it is expired. This field is
            intended to ease client-side token management,
            since the device may have clock skew, but is
            still able to accurately measure a duration.
            This expiration is intended to minimize the
            replay window within which a single challenge
            may be reused.
            See AIP 142 for naming of this field.
    """

    challenge = proto.Field(
        proto.BYTES,
        number=1,
    )
    ttl = proto.Field(
        proto.MESSAGE,
        number=2,
        message=duration_pb2.Duration,
    )


class ExchangeAppAttestAttestationRequest(proto.Message):
    r"""Request message for ExchangeAppAttestAttestation
    Attributes:
        app (str):
            Required. The full resource name to the iOS App. Format:
            "projects/{project_id}/apps/{app_id}".
        attestation_statement (bytes):
            The App Attest statement as returned by
            Apple's client-side App Attest API. This is the
            CBOR object returned by Apple, which will be
            Base64 encoded in the JSON API.
        challenge (bytes):
            The challenge previously generated by the FAC
            backend.
        key_id (bytes):
            The key ID generated by App Attest for the
            client app.
    """

    app = proto.Field(
        proto.STRING,
        number=1,
    )
    attestation_statement = proto.Field(
        proto.BYTES,
        number=2,
    )
    challenge = proto.Field(
        proto.BYTES,
        number=3,
    )
    key_id = proto.Field(
        proto.BYTES,
        number=4,
    )


class ExchangeAppAttestAttestationResponse(proto.Message):
    r"""Response message for ExchangeAppAttestAttestation and
    ExchangeAppAttestDebugAttestation

    Attributes:
        artifact (bytes):
            An artifact that should be passed back during
            the Assertion flow.
        attestation_token (google.firebase.appcheck_v1beta.types.AttestationTokenResponse):
            An attestation token which can be used to
            access Firebase APIs.
    """

    artifact = proto.Field(
        proto.BYTES,
        number=1,
    )
    attestation_token = proto.Field(
        proto.MESSAGE,
        number=2,
        message='AttestationTokenResponse',
    )


class ExchangeAppAttestAssertionRequest(proto.Message):
    r"""Request message for ExchangeAppAttestAssertion
    Attributes:
        app (str):
            Required. The full resource name to the iOS App. Format:
            "projects/{project_id}/apps/{app_id}".
        artifact (bytes):
            The artifact previously returned by
            ExchangeAppAttestAttestation.
        assertion (bytes):
            The CBOR encoded assertion provided by the
            Apple App Attest SDK.
        challenge (bytes):
            A one time challenge returned by
            GenerateAppAttestChallenge.
    """

    app = proto.Field(
        proto.STRING,
        number=1,
    )
    artifact = proto.Field(
        proto.BYTES,
        number=2,
    )
    assertion = proto.Field(
        proto.BYTES,
        number=3,
    )
    challenge = proto.Field(
        proto.BYTES,
        number=4,
    )


__all__ = tuple(sorted(__protobuf__.manifest))
