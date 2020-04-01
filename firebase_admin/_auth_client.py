# Copyright 2020 Google Inc.
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

"""Firebase auth client sub module."""

import time

import firebase_admin
from firebase_admin import _auth_providers
from firebase_admin import _auth_utils
from firebase_admin import _http_client
from firebase_admin import _token_gen
from firebase_admin import _user_import
from firebase_admin import _user_mgt


class Client:
    """Firebase Authentication client scoped to a specific tenant."""

    def __init__(self, app, tenant_id=None):
        if not app.project_id:
            raise ValueError("""Project ID is required to access the auth service.
            1. Use a service account credential, or
            2. set the project ID explicitly via Firebase App options, or
            3. set the project ID via the GOOGLE_CLOUD_PROJECT environment variable.""")

        credential = app.credential.get_credential()
        version_header = 'Python/Admin/{0}'.format(firebase_admin.__version__)
        http_client = _http_client.JsonHttpClient(
            credential=credential, headers={'X-Client-Version': version_header})

        self._tenant_id = tenant_id
        self._token_generator = _token_gen.TokenGenerator(app, http_client)
        self._token_verifier = _token_gen.TokenVerifier(app)
        self._user_manager = _user_mgt.UserManager(http_client, app.project_id, tenant_id)
        self._provider_manager = _auth_providers.ProviderConfigClient(
            http_client, app.project_id, tenant_id)

    @property
    def tenant_id(self):
        """Tenant ID associated with this client."""
        return self._tenant_id

    def create_custom_token(self, uid, developer_claims=None):
        """Builds and signs a Firebase custom auth token.

        Args:
            uid: ID of the user for whom the token is created.
            developer_claims: A dictionary of claims to be included in the token
                (optional).

        Returns:
            bytes: A token minted from the input parameters.

        Raises:
            ValueError: If input parameters are invalid.
            TokenSignError: If an error occurs while signing the token using the remote IAM service.
        """
        return self._token_generator.create_custom_token(
            uid, developer_claims, tenant_id=self.tenant_id)

    def verify_id_token(self, id_token, check_revoked=False):
        """Verifies the signature and data for the provided JWT.

        Accepts a signed token string, verifies that it is current, and issued
        to this project, and that it was correctly signed by Google.

        Args:
            id_token: A string of the encoded JWT.
            check_revoked: Boolean, If true, checks whether the token has been revoked (optional).

        Returns:
            dict: A dictionary of key-value pairs parsed from the decoded JWT.

        Raises:
            ValueError: If ``id_token`` is a not a string or is empty.
            InvalidIdTokenError: If ``id_token`` is not a valid Firebase ID token.
            ExpiredIdTokenError: If the specified ID token has expired.
            RevokedIdTokenError: If ``check_revoked`` is ``True`` and the ID token has been
                revoked.
            TenantIdMismatchError: If ``id_token`` belongs to a tenant that is different than
                this ``Client`` instance.
            CertificateFetchError: If an error occurs while fetching the public key certificates
                required to verify the ID token.
        """
        if not isinstance(check_revoked, bool):
            # guard against accidental wrong assignment.
            raise ValueError('Illegal check_revoked argument. Argument must be of type '
                             ' bool, but given "{0}".'.format(type(check_revoked)))

        verified_claims = self._token_verifier.verify_id_token(id_token)
        if self.tenant_id:
            token_tenant_id = verified_claims.get('firebase', {}).get('tenant')
            if self.tenant_id != token_tenant_id:
                raise _auth_utils.TenantIdMismatchError(
                    'Invalid tenant ID: {0}'.format(token_tenant_id))

        if check_revoked:
            self._check_jwt_revoked(verified_claims, _token_gen.RevokedIdTokenError, 'ID token')
        return verified_claims

    def revoke_refresh_tokens(self, uid):
        """Revokes all refresh tokens for an existing user.

        revoke_refresh_tokens updates the user's tokens_valid_after_timestamp to the current UTC
        in seconds since the epoch. It is important that the server on which this is called has its
        clock set correctly and synchronized.

        While this revokes all sessions for a specified user and disables any new ID tokens for
        existing sessions from getting minted, existing ID tokens may remain active until their
        natural expiration (one hour). To verify that ID tokens are revoked, use
        ``verify_id_token(idToken, check_revoked=True)``.

        Args:
            uid: A user ID string.

        Raises:
            ValueError: If the user ID is None, empty or malformed.
            FirebaseError: If an error occurs while revoking the refresh token.
        """
        self._user_manager.update_user(uid, valid_since=int(time.time()))

    def get_user(self, uid):
        """Gets the user data corresponding to the specified user ID.

        Args:
            uid: A user ID string.

        Returns:
            UserRecord: A UserRecord instance.

        Raises:
            ValueError: If the user ID is None, empty or malformed.
            UserNotFoundError: If the specified user ID does not exist.
            FirebaseError: If an error occurs while retrieving the user.
        """
        response = self._user_manager.get_user(uid=uid)
        return _user_mgt.UserRecord(response)

    def get_user_by_email(self, email):
        """Gets the user data corresponding to the specified user email.

        Args:
            email: A user email address string.

        Returns:
            UserRecord: A UserRecord instance.

        Raises:
            ValueError: If the email is None, empty or malformed.
            UserNotFoundError: If no user exists by the specified email address.
            FirebaseError: If an error occurs while retrieving the user.
        """
        response = self._user_manager.get_user(email=email)
        return _user_mgt.UserRecord(response)

    def get_user_by_phone_number(self, phone_number):
        """Gets the user data corresponding to the specified phone number.

        Args:
            phone_number: A phone number string.

        Returns:
            UserRecord: A UserRecord instance.

        Raises:
            ValueError: If the phone number is None, empty or malformed.
            UserNotFoundError: If no user exists by the specified phone number.
            FirebaseError: If an error occurs while retrieving the user.
        """
        response = self._user_manager.get_user(phone_number=phone_number)
        return _user_mgt.UserRecord(response)

    def list_users(self, page_token=None, max_results=_user_mgt.MAX_LIST_USERS_RESULTS):
        """Retrieves a page of user accounts from a Firebase project.

        The ``page_token`` argument governs the starting point of the page. The ``max_results``
        argument governs the maximum number of user accounts that may be included in the returned
        page. This function never returns None. If there are no user accounts in the Firebase
        project, this returns an empty page.

        Args:
            page_token: A non-empty page token string, which indicates the starting point of the
                page (optional). Defaults to ``None``, which will retrieve the first page of users.
            max_results: A positive integer indicating the maximum number of users to include in
                the returned page (optional). Defaults to 1000, which is also the maximum number
                allowed.

        Returns:
            ListUsersPage: A ListUsersPage instance.

        Raises:
            ValueError: If max_results or page_token are invalid.
            FirebaseError: If an error occurs while retrieving the user accounts.
        """
        def download(page_token, max_results):
            return self._user_manager.list_users(page_token, max_results)
        return _user_mgt.ListUsersPage(download, page_token, max_results)

    def create_user(self, **kwargs): # pylint: disable=differing-param-doc
        """Creates a new user account with the specified properties.

        Args:
            kwargs: A series of keyword arguments (optional).

        Keyword Args:
            uid: User ID to assign to the newly created user (optional).
            display_name: The user's display name (optional).
            email: The user's primary email (optional).
            email_verified: A boolean indicating whether or not the user's primary email is
                verified (optional).
            phone_number: The user's primary phone number (optional).
            photo_url: The user's photo URL (optional).
            password: The user's raw, unhashed password. (optional).
            disabled: A boolean indicating whether or not the user account is disabled (optional).

        Returns:
            UserRecord: A UserRecord instance for the newly created user.

        Raises:
            ValueError: If the specified user properties are invalid.
            FirebaseError: If an error occurs while creating the user account.
        """
        uid = self._user_manager.create_user(**kwargs)
        return self.get_user(uid=uid)

    def update_user(self, uid, **kwargs): # pylint: disable=differing-param-doc
        """Updates an existing user account with the specified properties.

        Args:
            uid: A user ID string.
            kwargs: A series of keyword arguments (optional).

        Keyword Args:
            display_name: The user's display name (optional). Can be removed by explicitly passing
                ``auth.DELETE_ATTRIBUTE``.
            email: The user's primary email (optional).
            email_verified: A boolean indicating whether or not the user's primary email is
                verified (optional).
            phone_number: The user's primary phone number (optional). Can be removed by explicitly
                passing ``auth.DELETE_ATTRIBUTE``.
            photo_url: The user's photo URL (optional). Can be removed by explicitly passing
                ``auth.DELETE_ATTRIBUTE``.
            password: The user's raw, unhashed password. (optional).
            disabled: A boolean indicating whether or not the user account is disabled (optional).
            custom_claims: A dictionary or a JSON string contining the custom claims to be set on
                the user account (optional). To remove all custom claims, pass
                ``auth.DELETE_ATTRIBUTE``.
            valid_since: An integer signifying the seconds since the epoch (optional). This field
                is set by ``revoke_refresh_tokens`` and it is discouraged to set this field
                directly.

        Returns:
            UserRecord: An updated UserRecord instance for the user.

        Raises:
            ValueError: If the specified user ID or properties are invalid.
            FirebaseError: If an error occurs while updating the user account.
        """
        self._user_manager.update_user(uid, **kwargs)
        return self.get_user(uid=uid)

    def set_custom_user_claims(self, uid, custom_claims):
        """Sets additional claims on an existing user account.

        Custom claims set via this function can be used to define user roles and privilege levels.
        These claims propagate to all the devices where the user is already signed in (after token
        expiration or when token refresh is forced), and next time the user signs in. The claims
        can be accessed via the user's ID token JWT. If a reserved OIDC claim is specified (sub,
        iat, iss, etc), an error is thrown. Claims payload must also not be larger then 1000
        characters when serialized into a JSON string.

        Args:
            uid: A user ID string.
            custom_claims: A dictionary or a JSON string of custom claims. Pass None to unset any
                claims set previously.

        Raises:
            ValueError: If the specified user ID or the custom claims are invalid.
            FirebaseError: If an error occurs while updating the user account.
        """
        if custom_claims is None:
            custom_claims = _user_mgt.DELETE_ATTRIBUTE
        self._user_manager.update_user(uid, custom_claims=custom_claims)

    def delete_user(self, uid):
        """Deletes the user identified by the specified user ID.

        Args:
            uid: A user ID string.

        Raises:
            ValueError: If the user ID is None, empty or malformed.
            FirebaseError: If an error occurs while deleting the user account.
        """
        self._user_manager.delete_user(uid)

    def import_users(self, users, hash_alg=None):
        """Imports the specified list of users into Firebase Auth.

        At most 1000 users can be imported at a time. This operation is optimized for bulk imports
        and will ignore checks on identifier uniqueness which could result in duplications. The
        ``hash_alg`` parameter must be specified when importing users with passwords. Refer to the
        ``UserImportHash`` class for supported hash algorithms.

        Args:
            users: A list of ``ImportUserRecord`` instances to import. Length of the list must not
                exceed 1000.
            hash_alg: A ``UserImportHash`` object (optional). Required when importing users with
                passwords.

        Returns:
            UserImportResult: An object summarizing the result of the import operation.

        Raises:
            ValueError: If the provided arguments are invalid.
            FirebaseError: If an error occurs while importing users.
        """
        result = self._user_manager.import_users(users, hash_alg)
        return _user_import.UserImportResult(result, len(users))

    def generate_password_reset_link(self, email, action_code_settings=None):
        """Generates the out-of-band email action link for password reset flows for the specified
        email address.

        Args:
            email: The email of the user whose password is to be reset.
            action_code_settings: ``ActionCodeSettings`` instance (optional). Defines whether
                the link is to be handled by a mobile app and the additional state information to
                be passed in the deep link.

        Returns:
            link: The password reset link created by the API

        Raises:
            ValueError: If the provided arguments are invalid
            FirebaseError: If an error occurs while generating the link
        """
        return self._user_manager.generate_email_action_link(
            'PASSWORD_RESET', email, action_code_settings=action_code_settings)

    def generate_email_verification_link(self, email, action_code_settings=None):
        """Generates the out-of-band email action link for email verification flows for the
        specified email address.

        Args:
            email: The email of the user to be verified.
            action_code_settings: ``ActionCodeSettings`` instance (optional). Defines whether
                the link is to be handled by a mobile app and the additional state information to
                be passed in the deep link.

        Returns:
            link: The email verification link created by the API

        Raises:
            ValueError: If the provided arguments are invalid
            FirebaseError: If an error occurs while generating the link
        """
        return self._user_manager.generate_email_action_link(
            'VERIFY_EMAIL', email, action_code_settings=action_code_settings)

    def generate_sign_in_with_email_link(self, email, action_code_settings):
        """Generates the out-of-band email action link for email link sign-in flows, using the
        action code settings provided.

        Args:
            email: The email of the user signing in.
            action_code_settings: ``ActionCodeSettings`` instance. Defines whether
                the link is to be handled by a mobile app and the additional state information to be
                passed in the deep link.

        Returns:
            link: The email sign-in link created by the API

        Raises:
            ValueError: If the provided arguments are invalid
            FirebaseError: If an error occurs while generating the link
        """
        return self._user_manager.generate_email_action_link(
            'EMAIL_SIGNIN', email, action_code_settings=action_code_settings)

    def get_saml_provider_config(self, provider_id):
        """Returns the SAMLProviderConfig with the given ID.

        Args:
            provider_id: Provider ID string.

        Returns:
            SAMLProviderConfig: A SAMLProviderConfig instance.

        Raises:
            ValueError: If the provider ID is invalid, empty or does not have ``saml.`` prefix.
            ConfigurationNotFoundError: If no SAML provider is available with the given identifier.
            FirebaseError: If an error occurs while retrieving the SAML provider.
        """
        return self._provider_manager.get_saml_provider_config(provider_id)

    def create_saml_provider_config(
            self, provider_id, idp_entity_id, sso_url, x509_certificates, rp_entity_id,
            callback_url, display_name=None, enabled=None):
        """Creates a new SAML provider config from the given parameters.

        SAML provider support requires Google Cloud's Identity Platform (GCIP). To learn more about
        GCIP, including pricing and features, see https://cloud.google.com/identity-platform.

        Args:
            provider_id: Provider ID string. Must have the prefix ``saml.``.
            idp_entity_id: The SAML IdP entity identifier.
            sso_url: The SAML IdP SSO URL. Must be a valid URL.
            x509_certificates: The list of SAML IdP X.509 certificates issued by CA for this
                provider. Multiple certificates are accepted to prevent outages during IdP key
                rotation (for example ADFS rotates every 10 days). When the Auth server receives a
                SAML response, it will match the SAML response with the certificate on record.
                Otherwise the response is rejected. Developers are expected to manage the
                certificate updates as keys are rotated.
            rp_entity_id: The SAML relying party (service provider) entity ID. This is defined by
                the developer but needs to be provided to the SAML IdP.
            callback_url: Callback URL string. This is fixed and must always be the same as the
                OAuth redirect URL provisioned by Firebase Auth, unless a custom authDomain is
                used.
            display_name: The user-friendly display name to the current configuration (optional).
                This name is also used as the provider label in the Cloud Console.
            enabled: A boolean indicating whether the provider configuration is enabled or disabled
                (optional). A user cannot sign in using a disabled provider.

        Returns:
            SAMLProviderConfig: The newly created SAMLProviderConfig instance.

        Raises:
            ValueError: If any of the specified input parameters are invalid.
            FirebaseError: If an error occurs while creating the new SAML provider config.
        """
        return self._provider_manager.create_saml_provider_config(
            provider_id, idp_entity_id=idp_entity_id, sso_url=sso_url,
            x509_certificates=x509_certificates, rp_entity_id=rp_entity_id,
            callback_url=callback_url, display_name=display_name, enabled=enabled)

    def update_saml_provider_config(
            self, provider_id, idp_entity_id=None, sso_url=None, x509_certificates=None,
            rp_entity_id=None, callback_url=None, display_name=None, enabled=None):
        """Updates an existing SAML provider config with the given parameters.

        Args:
            provider_id: Provider ID string. Must have the prefix ``saml.``.
            idp_entity_id: The SAML IdP entity identifier (optional).
            sso_url: The SAML IdP SSO URL. Must be a valid URL (optional).
            x509_certificates: The list of SAML IdP X.509 certificates issued by CA for this
                provider  (optional).
            rp_entity_id: The SAML relying party entity ID (optional).
            callback_url: Callback URL string  (optional).
            display_name: The user-friendly display name to the current configuration (optional).
                Pass ``auth.DELETE_ATTRIBUTE`` to delete the current display name.
            enabled: A boolean indicating whether the provider configuration is enabled or disabled
                (optional).

        Returns:
            SAMLProviderConfig: The updated SAMLProviderConfig instance.

        Raises:
            ValueError: If any of the specified input parameters are invalid.
            FirebaseError: If an error occurs while updating the SAML provider config.
        """
        return self._provider_manager.update_saml_provider_config(
            provider_id, idp_entity_id=idp_entity_id, sso_url=sso_url,
            x509_certificates=x509_certificates, rp_entity_id=rp_entity_id,
            callback_url=callback_url, display_name=display_name, enabled=enabled)

    def delete_saml_provider_config(self, provider_id):
        """Deletes the SAMLProviderConfig with the given ID.

        Args:
            provider_id: Provider ID string.

        Raises:
            ValueError: If the provider ID is invalid, empty or does not have ``saml.`` prefix.
            ConfigurationNotFoundError: If no SAML provider is available with the given identifier.
            FirebaseError: If an error occurs while deleting the SAML provider.
        """
        self._provider_manager.delete_saml_provider_config(provider_id)

    def _check_jwt_revoked(self, verified_claims, exc_type, label):
        user = self.get_user(verified_claims.get('uid'))
        if verified_claims.get('iat') * 1000 < user.tokens_valid_after_timestamp:
            raise exc_type('The Firebase {0} has been revoked.'.format(label))
