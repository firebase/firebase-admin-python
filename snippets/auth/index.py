# Copyright 2018 Google Inc.
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

from __future__ import print_function

import base64
import datetime
import sys
import time

# [START import_sdk]
import firebase_admin
# [END import_sdk]
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin import exceptions
from firebase_admin import tenant_mgt

sys.path.append("lib")

def initialize_sdk_with_service_account():
    # [START initialize_sdk_with_service_account]
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import exceptions

    cred = credentials.Certificate('path/to/serviceAccountKey.json')
    default_app = firebase_admin.initialize_app(cred)
    # [END initialize_sdk_with_service_account]
    firebase_admin.delete_app(default_app)

def initialize_sdk_with_application_default():
    # [START initialize_sdk_with_application_default]
    default_app = firebase_admin.initialize_app()
    # [END initialize_sdk_with_application_default]
    firebase_admin.delete_app(default_app)

def initialize_sdk_with_refresh_token():
    # [START initialize_sdk_with_refresh_token]
    cred = credentials.RefreshToken('path/to/refreshToken.json')
    default_app = firebase_admin.initialize_app(cred)
    # [END initialize_sdk_with_refresh_token]
    firebase_admin.delete_app(default_app)

def initialize_sdk_with_service_account_id():
    # [START initialize_sdk_with_service_account_id]
    options = {
        'serviceAccountId': 'my-client-id@my-project-id.iam.gserviceaccount.com',
    }
    firebase_admin.initialize_app(options=options)
    # [END initialize_sdk_with_service_account_id]
    firebase_admin.delete_app(firebase_admin.get_app())

def access_services_default():
    cred = credentials.Certificate('path/to/service.json')
    # [START access_services_default]
    # Import the Firebase service
    from firebase_admin import auth

    # Initialize the default app
    default_app = firebase_admin.initialize_app(cred)
    print(default_app.name)  # "[DEFAULT]"

    # Retrieve services via the auth package...
    # auth.create_custom_token(...)
    # [END access_services_default]
    firebase_admin.delete_app(default_app)

def access_services_nondefault():
    cred = credentials.Certificate('path/to/service.json')
    other_cred = credentials.Certificate('path/to/other_service.json')

    # [START access_services_nondefault]
    # Initialize the default app
    default_app = firebase_admin.initialize_app(cred)

    #  Initialize another app with a different config
    other_app = firebase_admin.initialize_app(cred, name='other')

    print(default_app.name)    # "[DEFAULT]"
    print(other_app.name)      # "other"

    # Retrieve default services via the auth package...
    # auth.create_custom_token(...)

    # Use the `app` argument to retrieve the other app's services
    # auth.create_custom_token(..., app=other_app)
    # [END access_services_nondefault]
    firebase_admin.delete_app(default_app)
    firebase_admin.delete_app(other_app)

def create_token_uid():
    cred = credentials.Certificate('path/to/service.json')
    default_app = firebase_admin.initialize_app(cred)
    # [START create_token_uid]
    uid = 'some-uid'

    custom_token = auth.create_custom_token(uid)
    # [END create_token_uid]
    firebase_admin.delete_app(default_app)
    return custom_token

def create_token_with_claims():
    cred = credentials.Certificate('path/to/service.json')
    default_app = firebase_admin.initialize_app(cred)
    # [START create_token_with_claims]
    uid = 'some-uid'
    additional_claims = {
        'premiumAccount': True
    }

    custom_token = auth.create_custom_token(uid, additional_claims)
    # [END create_token_with_claims]
    firebase_admin.delete_app(default_app)
    return custom_token

def verify_token_uid(id_token):
    cred = credentials.Certificate('path/to/service.json')
    default_app = firebase_admin.initialize_app(cred)
    # [START verify_token_uid]
    # id_token comes from the client app (shown above)

    decoded_token = auth.verify_id_token(id_token)
    uid = decoded_token['uid']
    # [END verify_token_uid]
    print(uid)
    firebase_admin.delete_app(default_app)

def verify_token_uid_check_revoke(id_token):
    cred = credentials.Certificate('path/to/service.json')
    default_app = firebase_admin.initialize_app(cred)
    # [START verify_token_id_check_revoked]
    try:
        # Verify the ID token while checking if the token is revoked by
        # passing check_revoked=True.
        decoded_token = auth.verify_id_token(id_token, check_revoked=True)
        # Token is valid and not revoked.
        uid = decoded_token['uid']
    except auth.RevokedIdTokenError:
        # Token revoked, inform the user to reauthenticate or signOut().
        pass
    except auth.InvalidIdTokenError:
        # Token is invalid
        pass
    # [END verify_token_id_check_revoked]
    firebase_admin.delete_app(default_app)
    return uid

def revoke_refresh_token_uid():
    cred = credentials.Certificate('path/to/service.json')
    default_app = firebase_admin.initialize_app(cred)
    # [START revoke_tokens]
    # Revoke tokens on the backend.
    auth.revoke_refresh_tokens(uid)
    user = auth.get_user(uid)
    # Convert to seconds as the auth_time in the token claims is in seconds.
    revocation_second = user.tokens_valid_after_timestamp / 1000
    print('Tokens revoked at: {0}'.format(revocation_second))
    # [END revoke_tokens]
    # [START save_revocation_in_db]
    metadata_ref = firebase_admin.db.reference("metadata/" + uid)
    metadata_ref.set({'revokeTime': revocation_second})
    # [END save_revocation_in_db]
    print(uid)
    firebase_admin.delete_app(default_app)

def get_user(uid):
    # [START get_user]
    from firebase_admin import auth

    user = auth.get_user(uid)
    print('Successfully fetched user data: {0}'.format(user.uid))
    # [END get_user]

def get_user_by_email():
    email = 'user@example.com'
    # [START get_user_by_email]
    from firebase_admin import auth

    user = auth.get_user_by_email(email)
    print('Successfully fetched user data: {0}'.format(user.uid))
    # [END get_user_by_email]

def bulk_get_users():
    # [START bulk_get_users]
    from firebase_admin import auth

    result = auth.get_users([
        auth.UidIdentifier('uid1'),
        auth.EmailIdentifier('user2@example.com'),
        auth.PhoneIdentifier(+15555550003),
        auth.ProviderIdentifier('google.com', 'google_uid4')
    ])

    print('Successfully fetched user data:')
    for user in result.users:
        print(user.uid)

    print('Unable to find users corresponding to these identifiers:')
    for uid in result.not_found:
        print(uid)
    # [END bulk_get_users]

def get_user_by_phone_number():
    phone = '+1 555 555 0100'
    # [START get_user_by_phone]
    from firebase_admin import auth

    user = auth.get_user_by_phone_number(phone)
    print('Successfully fetched user data: {0}'.format(user.uid))
    # [END get_user_by_phone]

def create_user():
    # [START create_user]
    user = auth.create_user(
        email='user@example.com',
        email_verified=False,
        phone_number='+15555550100',
        password='secretPassword',
        display_name='John Doe',
        photo_url='http://www.example.com/12345678/photo.png',
        disabled=False)
    print('Sucessfully created new user: {0}'.format(user.uid))
    # [END create_user]
    return user.uid

def create_user_with_id():
    # [START create_user_with_id]
    user = auth.create_user(
        uid='some-uid', email='user@example.com', phone_number='+15555550100')
    print('Sucessfully created new user: {0}'.format(user.uid))
    # [END create_user_with_id]

def update_user(uid):
    # [START update_user]
    user = auth.update_user(
        uid,
        email='user@example.com',
        phone_number='+15555550100',
        email_verified=True,
        password='newPassword',
        display_name='John Doe',
        photo_url='http://www.example.com/12345678/photo.png',
        disabled=True)
    print('Sucessfully updated user: {0}'.format(user.uid))
    # [END update_user]

def delete_user(uid):
    # [START delete_user]
    auth.delete_user(uid)
    print('Successfully deleted user')
    # [END delete_user]

def bulk_delete_users():
    # [START bulk_delete_users]
    from firebase_admin import auth

    result = auth.delete_users(["uid1", "uid2", "uid3"])

    print('Successfully deleted {0} users'.format(result.success_count))
    print('Failed to delete {0} users'.format(result.failure_count))
    for err in result.errors:
        print('error #{0}, reason: {1}'.format(result.index, result.reason))
    # [END bulk_delete_users]

def set_custom_user_claims(uid):
    # [START set_custom_user_claims]
    # Set admin privilege on the user corresponding to uid.
    auth.set_custom_user_claims(uid, {'admin': True})
    # The new custom claims will propagate to the user's ID token the
    # next time a new one is issued.
    # [END set_custom_user_claims]

    id_token = 'id_token'
    # [START verify_custom_claims]
    # Verify the ID token first.
    claims = auth.verify_id_token(id_token)
    if claims['admin'] is True:
        # Allow access to requested admin resource.
        pass
    # [END verify_custom_claims]

    # [START read_custom_user_claims]
    # Lookup the user associated with the specified uid.
    user = auth.get_user(uid)
    # The claims can be accessed on the user record.
    print(user.custom_claims.get('admin'))
    # [END read_custom_user_claims]

def set_custom_user_claims_script():
    # [START set_custom_user_claims_script]
    user = auth.get_user_by_email('user@admin.example.com')
    # Confirm user is verified
    if user.email_verified:
        # Add custom claims for additional privileges.
        # This will be picked up by the user on token refresh or next sign in on new device.
        auth.set_custom_user_claims(user.uid, {
            'admin': True
        })
    # [END set_custom_user_claims_script]

def set_custom_user_claims_incremental():
    # [START set_custom_user_claims_incremental]
    user = auth.get_user_by_email('user@admin.example.com')
    # Add incremental custom claim without overwriting existing claims.
    current_custom_claims = user.custom_claims
    if current_custom_claims.get('admin'):
        # Add level.
        current_custom_claims['accessLevel'] = 10
        # Add custom claims for additional privileges.
        auth.set_custom_user_claims(user.uid, current_custom_claims)
    # [END set_custom_user_claims_incremental]

def list_all_users():
    # [START list_all_users]
    # Start listing users from the beginning, 1000 at a time.
    page = auth.list_users()
    while page:
        for user in page.users:
            print('User: ' + user.uid)
        # Get next batch of users.
        page = page.get_next_page()

    # Iterate through all users. This will still retrieve users in batches,
    # buffering no more than 1000 users in memory at a time.
    for user in auth.list_users().iterate_all():
        print('User: ' + user.uid)
    # [END list_all_users]

def create_session_cookie(flask, app):
    # [START session_login]
    @app.route('/sessionLogin', methods=['POST'])
    def session_login():
        # Get the ID token sent by the client
        id_token = flask.request.json['idToken']
        # Set session expiration to 5 days.
        expires_in = datetime.timedelta(days=5)
        try:
            # Create the session cookie. This will also verify the ID token in the process.
            # The session cookie will have the same claims as the ID token.
            session_cookie = auth.create_session_cookie(id_token, expires_in=expires_in)
            response = flask.jsonify({'status': 'success'})
            # Set cookie policy for session cookie.
            expires = datetime.datetime.now() + expires_in
            response.set_cookie(
                'session', session_cookie, expires=expires, httponly=True, secure=True)
            return response
        except exceptions.FirebaseError:
            return flask.abort(401, 'Failed to create a session cookie')
    # [END session_login]

def check_auth_time(id_token, flask):
    # [START check_auth_time]
    # To ensure that cookies are set only on recently signed in users, check auth_time in
    # ID token before creating a cookie.
    try:
        decoded_claims = auth.verify_id_token(id_token)
        # Only process if the user signed in within the last 5 minutes.
        if time.time() - decoded_claims['auth_time'] < 5 * 60:
            expires_in = datetime.timedelta(days=5)
            expires = datetime.datetime.now() + expires_in
            session_cookie = auth.create_session_cookie(id_token, expires_in=expires_in)
            response = flask.jsonify({'status': 'success'})
            response.set_cookie(
                'session', session_cookie, expires=expires, httponly=True, secure=True)
            return response
        # User did not sign in recently. To guard against ID token theft, require
        # re-authentication.
        return flask.abort(401, 'Recent sign in required')
    except auth.InvalidIdTokenError:
        return flask.abort(401, 'Invalid ID token')
    except exceptions.FirebaseError:
        return flask.abort(401, 'Failed to create a session cookie')
    # [END check_auth_time]

def verfy_session_cookie(app, flask):
    def serve_content_for_user(decoded_claims):
        print('Serving content with claims:', decoded_claims)
        return flask.jsonify({'status': 'success'})

    # [START session_verify]
    @app.route('/profile', methods=['POST'])
    def access_restricted_content():
        session_cookie = flask.request.cookies.get('session')
        if not session_cookie:
            # Session cookie is unavailable. Force user to login.
            return flask.redirect('/login')

        # Verify the session cookie. In this case an additional check is added to detect
        # if the user's Firebase session was revoked, user deleted/disabled, etc.
        try:
            decoded_claims = auth.verify_session_cookie(session_cookie, check_revoked=True)
            return serve_content_for_user(decoded_claims)
        except auth.InvalidSessionCookieError:
            # Session cookie is invalid, expired or revoked. Force user to login.
            return flask.redirect('/login')
    # [END session_verify]

def check_permissions(session_cookie, flask):
    def serve_content_for_admin(decoded_claims):
        print('Serving content with claims:', decoded_claims)
        return flask.jsonify({'status': 'success'})

    # [START session_verify_with_permission_check]
    try:
        decoded_claims = auth.verify_session_cookie(session_cookie, check_revoked=True)
        # Check custom claims to confirm user is an admin.
        if decoded_claims.get('admin') is True:
            return serve_content_for_admin(decoded_claims)

        return flask.abort(401, 'Insufficient permissions')
    except auth.InvalidSessionCookieError:
        # Session cookie is invalid, expired or revoked. Force user to login.
        return flask.redirect('/login')
    # [END session_verify_with_permission_check]

def clear_session_cookie(app, flask):
    # [START session_clear]
    @app.route('/sessionLogout', methods=['POST'])
    def session_logout():
        response = flask.make_response(flask.redirect('/login'))
        response.set_cookie('session', expires=0)
        return response
    # [END session_clear]

def clear_session_cookie_and_revoke(app, flask):
    # [START session_clear_and_revoke]
    @app.route('/sessionLogout', methods=['POST'])
    def session_logout():
        session_cookie = flask.request.cookies.get('session')
        try:
            decoded_claims = auth.verify_session_cookie(session_cookie)
            auth.revoke_refresh_tokens(decoded_claims['sub'])
            response = flask.make_response(flask.redirect('/login'))
            response.set_cookie('session', expires=0)
            return response
        except auth.InvalidSessionCookieError:
            return flask.redirect('/login')
    # [END session_clear_and_revoke]

def import_users():
    # [START build_user_list]
    # Up to 1000 users can be imported at once.
    users = [
        auth.ImportUserRecord(
            uid='uid1',
            email='user1@example.com',
            password_hash=b'password_hash_1',
            password_salt=b'salt1'
        ),
        auth.ImportUserRecord(
            uid='uid2',
            email='user2@example.com',
            password_hash=b'password_hash_2',
            password_salt=b'salt2'
        ),
    ]
    # [END build_user_list]

    # [START import_users]
    hash_alg = auth.UserImportHash.hmac_sha256(key=b'secret_key')
    try:
        result = auth.import_users(users, hash_alg=hash_alg)
        print('Successfully imported {0} users. Failed to import {1} users.'.format(
            result.success_count, result.failure_count))
        for err in result.errors:
            print('Failed to import {0} due to {1}'.format(users[err.index].uid, err.reason))
    except exceptions.FirebaseError:
        # Some unrecoverable error occurred that prevented the operation from running.
        pass
    # [END import_users]

def import_with_hmac():
    # [START import_with_hmac]
    users = [
        auth.ImportUserRecord(
            uid='some-uid',
            email='user@example.com',
            password_hash=b'password_hash',
            password_salt=b'salt'
        ),
    ]

    hash_alg = auth.UserImportHash.hmac_sha256(key=b'secret')
    try:
        result = auth.import_users(users, hash_alg=hash_alg)
        for err in result.errors:
            print('Failed to import user:', err.reason)
    except exceptions.FirebaseError as error:
        print('Error importing users:', error)
    # [END import_with_hmac]

def import_with_pbkdf():
    # [START import_with_pbkdf]
    users = [
        auth.ImportUserRecord(
            uid='some-uid',
            email='user@example.com',
            password_hash=b'password_hash',
            password_salt=b'salt'
        ),
    ]

    hash_alg = auth.UserImportHash.pbkdf2_sha256(rounds=100000)
    try:
        result = auth.import_users(users, hash_alg=hash_alg)
        for err in result.errors:
            print('Failed to import user:', err.reason)
    except exceptions.FirebaseError as error:
        print('Error importing users:', error)
    # [END import_with_pbkdf]

def import_with_standard_scrypt():
    # [START import_with_standard_scrypt]
    users = [
        auth.ImportUserRecord(
            uid='some-uid',
            email='user@example.com',
            password_hash=b'password_hash',
            password_salt=b'salt'
        ),
    ]

    hash_alg = auth.UserImportHash.standard_scrypt(
        memory_cost=1024, parallelization=16, block_size=8, derived_key_length=64)
    try:
        result = auth.import_users(users, hash_alg=hash_alg)
        for err in result.errors:
            print('Failed to import user:', err.reason)
    except exceptions.FirebaseError as error:
        print('Error importing users:', error)
    # [END import_with_standard_scrypt]

def import_with_bcrypt():
    # [START import_with_bcrypt]
    users = [
        auth.ImportUserRecord(
            uid='some-uid',
            email='user@example.com',
            password_hash=b'password_hash',
            password_salt=b'salt'
        ),
    ]

    hash_alg = auth.UserImportHash.bcrypt()
    try:
        result = auth.import_users(users, hash_alg=hash_alg)
        for err in result.errors:
            print('Failed to import user:', err.reason)
    except exceptions.FirebaseError as error:
        print('Error importing users:', error)
    # [END import_with_bcrypt]

def import_with_scrypt():
    # [START import_with_scrypt]
    users = [
        auth.ImportUserRecord(
            uid='some-uid',
            email='user@example.com',
            password_hash=b'password_hash',
            password_salt=b'salt'
        ),
    ]

    # All the parameters below can be obtained from the Firebase Console's "Users"
    # section. Base64 encoded parameters must be decoded into raw bytes.
    hash_alg = auth.UserImportHash.scrypt(
        key=base64.b64decode('base64_secret'),
        salt_separator=base64.b64decode('base64_salt_separator'),
        rounds=8,
        memory_cost=14
    )
    try:
        result = auth.import_users(users, hash_alg=hash_alg)
        for err in result.errors:
            print('Failed to import user:', err.reason)
    except exceptions.FirebaseError as error:
        print('Error importing users:', error)
    # [END import_with_scrypt]

def import_without_password():
    # [START import_without_password]
    users = [
        auth.ImportUserRecord(
            uid='some-uid',
            display_name='John Doe',
            email='johndoe@gmail.com',
            photo_url='http://www.example.com/12345678/photo.png',
            email_verified=True,
            phone_number='+11234567890',
            custom_claims={'admin': True}, # set this user as admin
            provider_data=[ # user with Google provider
                auth.UserProvider(
                    uid='google-uid',
                    email='johndoe@gmail.com',
                    display_name='John Doe',
                    photo_url='http://www.example.com/12345678/photo.png',
                    provider_id='google.com'
                )
            ],
        ),
    ]
    try:
        result = auth.import_users(users)
        for err in result.errors:
            print('Failed to import user:', err.reason)
    except exceptions.FirebaseError as error:
        print('Error importing users:', error)
    # [END import_without_password]

def init_action_code_settings():
    # [START init_action_code_settings]
    action_code_settings = auth.ActionCodeSettings(
        url='https://www.example.com/checkout?cartId=1234',
        handle_code_in_app=True,
        ios_bundle_id='com.example.ios',
        android_package_name='com.example.android',
        android_install_app=True,
        android_minimum_version='12',
        dynamic_link_domain='coolapp.page.link',
    )
    # [END init_action_code_settings]
    return action_code_settings

def password_reset_link():
    action_code_settings = init_action_code_settings()
    # [START password_reset_link]
    email = 'user@example.com'
    link = auth.generate_password_reset_link(email, action_code_settings)
    # Construct password reset email from a template embedding the link, and send
    # using a custom SMTP server.
    send_custom_email(email, link)
    # [END password_reset_link]

def email_verification_link():
    action_code_settings = init_action_code_settings()
    # [START email_verification_link]
    email = 'user@example.com'
    link = auth.generate_email_verification_link(email, action_code_settings)
    # Construct email from a template embedding the link, and send
    # using a custom SMTP server.
    send_custom_email(email, link)
    # [END email_verification_link]

def sign_in_with_email_link():
    action_code_settings = init_action_code_settings()
    # [START sign_in_with_email_link]
    email = 'user@example.com'
    link = auth.generate_sign_in_with_email_link(email, action_code_settings)
    # Construct email from a template embedding the link, and send
    # using a custom SMTP server.
    send_custom_email(email, link)
    # [END sign_in_with_email_link]

def send_custom_email(email, link):
    del email
    del link

def create_saml_provider_config():
	# [START create_saml_provider]
    saml = auth.create_saml_provider_config(
        display_name='SAML provider name',
        enabled=True,
        provider_id='saml.myProvider',
        idp_entity_id='IDP_ENTITY_ID',
        sso_url='https://example.com/saml/sso/1234/',
        x509_certificates=[
            '-----BEGIN CERTIFICATE-----\nCERT1...\n-----END CERTIFICATE-----',
            '-----BEGIN CERTIFICATE-----\nCERT2...\n-----END CERTIFICATE-----',
        ],
        rp_entity_id='P_ENTITY_ID',
        callback_url='https://project-id.firebaseapp.com/__/auth/handler')

    print('Created new SAML provider:', saml.provider_id)
	# [END create_saml_provider]

def update_saml_provider_config():
	# [START update_saml_provider]
    saml = auth.update_saml_provider_config(
        'saml.myProvider',
        x509_certificates=[
            '-----BEGIN CERTIFICATE-----\nCERT2...\n-----END CERTIFICATE-----',
            '-----BEGIN CERTIFICATE-----\nCERT3...\n-----END CERTIFICATE-----',
        ])

    print('Updated SAML provider:', saml.provider_id)
	# [END update_saml_provider]

def get_saml_provider_config():
	# [START get_saml_provider]
    saml = auth.get_saml_provider_config('saml.myProvider')
    print(saml.display_name, saml.enabled)
    # [END get_saml_provider]

def delete_saml_provider_config():
	# [START delete_saml_provider]
    auth.delete_saml_provider_config('saml.myProvider')
	# [END delete_saml_provider]

def list_saml_provider_configs():
	# [START list_saml_providers]
    for saml in auth.list_saml_provider_configs('nextPageToken').iterate_all():
        print(saml.provider_id)
	# [END list_saml_providers]

def create_oidc_provider_config():
	# [START create_oidc_provider]
    oidc = auth.create_oidc_provider_config(
        display_name='OIDC provider name',
        enabled=True,
        provider_id='oidc.myProvider',
        client_id='CLIENT_ID2',
        issuer='https://oidc.com/CLIENT_ID2')

    print('Created new OIDC provider:', oidc.provider_id)
	# [END create_oidc_provider]

def update_oidc_provider_config():
	# [START update_oidc_provider]
    oidc = auth.update_oidc_provider_config(
        'oidc.myProvider',
        client_id='CLIENT_ID',
        issuer='https://oidc.com')

    print('Updated OIDC provider:', oidc.provider_id)
	# [END update_oidc_provider]

def get_oidc_provider_config():
	# [START get_oidc_provider]
    oidc = auth.get_oidc_provider_config('oidc.myProvider')

    print(oidc.display_name, oidc.enabled)
	# [END get_oidc_provider]

def delete_oidc_provider_config():
	# [START delete_oidc_provider]
    auth.delete_oidc_provider_config('oidc.myProvider')
	# [END delete_oidc_provider]

def list_oidc_provider_configs():
	# [START list_oidc_providers]
    for oidc in auth.list_oidc_provider_configs('nextPageToken').iterate_all():
        print(oidc.provider_id)
	# [END list_oidc_providers]

def get_tenant_client(tenant_id):
	# [START get_tenant_client]
    from firebase_admin import tenant_mgt

    tenant_client = tenant_mgt.auth_for_tenant(tenant_id)
	# [END get_tenant_client]
    return tenant_client

def get_tenant(tenant_id):
	# [START get_tenant]
    tenant = tenant_mgt.get_tenant(tenant_id)

    print('Retreieved tenant:', tenant.tenant_id)
	# [END get_tenant]

def create_tenant():
	# [START create_tenant]
    tenant = tenant_mgt.create_tenant(
        display_name='myTenant1',
        enable_email_link_sign_in=True,
        allow_password_sign_up=True)

    print('Created tenant:', tenant.tenant_id)
	# [END create_tenant]

def update_tenant(tenant_id):
	# [START update_tenant]
    tenant = tenant_mgt.update_tenant(
        tenant_id,
        display_name='updatedName',
        allow_password_sign_up=False) # Disable email provider

    print('Updated tenant:', tenant.tenant_id)
	# [END update_tenant]

def delete_tenant(tenant_id):
	# [START delete_tenant]
    tenant_mgt.delete_tenant(tenant_id)
	# [END delete_tenant]

def list_tenants():
	# [START list_tenants]
    for tenant in tenant_mgt.list_tenants().iterate_all():
        print('Retrieved tenant:', tenant.tenant_id)
	# [END list_tenants]

def create_provider_tenant():
	# [START get_tenant_client_short]
    tenant_client = tenant_mgt.auth_for_tenant('TENANT-ID')
	# [END get_tenant_client_short]

	# [START create_saml_provider_tenant]
    saml = tenant_client.create_saml_provider_config(
        display_name='SAML provider name',
        enabled=True,
        provider_id='saml.myProvider',
        idp_entity_id='IDP_ENTITY_ID',
        sso_url='https://example.com/saml/sso/1234/',
        x509_certificates=[
            '-----BEGIN CERTIFICATE-----\nCERT1...\n-----END CERTIFICATE-----',
            '-----BEGIN CERTIFICATE-----\nCERT2...\n-----END CERTIFICATE-----',
        ],
        rp_entity_id='P_ENTITY_ID',
        callback_url='https://project-id.firebaseapp.com/__/auth/handler')

    print('Created new SAML provider:', saml.provider_id)
	# [END create_saml_provider_tenant]

def update_provider_tenant(tenant_client):
    # [START update_saml_provider_tenant]
    saml = tenant_client.update_saml_provider_config(
        'saml.myProvider',
        x509_certificates=[
            '-----BEGIN CERTIFICATE-----\nCERT2...\n-----END CERTIFICATE-----',
            '-----BEGIN CERTIFICATE-----\nCERT3...\n-----END CERTIFICATE-----',
        ])

    print('Updated SAML provider:', saml.provider_id)
	# [END update_saml_provider_tenant]

def get_provider_tenant(tennat_client):
	# [START get_saml_provider_tenant]
    saml = tennat_client.get_saml_provider_config('saml.myProvider')
    print(saml.display_name, saml.enabled)
	# [END get_saml_provider_tenant]

def list_provider_configs_tenant(tenant_client):
	# [START list_saml_providers_tenant]
    for saml in tenant_client.list_saml_provider_configs('nextPageToken').iterate_all():
        print(saml.provider_id)
	# [END list_saml_providers_tenant]

def delete_provider_config_tenant(tenant_client):
	# [START delete_saml_provider_tenant]
    tenant_client.delete_saml_provider_config('saml.myProvider')
	# [END delete_saml_provider_tenant]

def get_user_tenant(tenant_client):
    uid = 'some_string_uid'

	# [START get_user_tenant]
	# Get an auth.Client from tenant_mgt.auth_for_tenant()
    user = tenant_client.get_user(uid)
    print('Successfully fetched user data:', user.uid)
	# [END get_user_tenant]

def get_user_by_email_tenant(tenant_client):
    email = 'some@email.com'
	# [START get_user_by_email_tenant]
    user = tenant_client.get_user_by_email(email)
    print('Successfully fetched user data:', user.uid)
	# [END get_user_by_email_tenant]

def create_user_tenant(tenant_client):
    # [START create_user_tenant]
    user = tenant_client.create_user(
        email='user@example.com',
        email_verified=False,
        phone_number='+15555550100',
        password='secretPassword',
        display_name='John Doe',
        photo_url='http://www.example.com/12345678/photo.png',
        disabled=False)
    print('Sucessfully created new user:', user.uid)
	# [END create_user_tenant]

def update_user_tenant(tenant_client, uid):
    # [START update_user_tenant]
    user = tenant_client.update_user(
        uid,
        email='user@example.com',
        phone_number='+15555550100',
        email_verified=True,
        password='newPassword',
        display_name='John Doe',
        photo_url='http://www.example.com/12345678/photo.png',
        disabled=True)
    print('Sucessfully updated user:', user.uid)
	# [END update_user_tenant]

def delete_user_tenant(tenant_client, uid):
    # [START delete_user_tenant]
    tenant_client.delete_user(uid)
    print('Successfully deleted user')
	# [END delete_user_tenant]

def list_users_tenant(tenant_client):
    # [START list_all_users_tenant]
	# Note, behind the scenes, the iterator will retrive 1000 users at a time through the API
    for user in tenant_client.list_users().iterate_all():
        print('User: ' + user.uid)

	# Iterating by pages of 1000 users at a time.
    page = tenant_client.list_users()
    while page:
        for user in page.users:
            print('User: ' + user.uid)
        # Get next batch of users.
        page = page.get_next_page()
	# [END list_all_users_tenant]

def import_with_hmac_tenant(tenant_client):
	# [START import_with_hmac_tenant]
    users = [
        auth.ImportUserRecord(
            uid='uid1',
            email='user1@example.com',
            password_hash=b'password_hash_1',
            password_salt=b'salt1'
        ),
        auth.ImportUserRecord(
            uid='uid2',
            email='user2@example.com',
            password_hash=b'password_hash_2',
            password_salt=b'salt2'
        ),
    ]

    hash_alg = auth.UserImportHash.hmac_sha256(key=b'secret')
    try:
        result = tenant_client.import_users(users, hash_alg=hash_alg)
        for err in result.errors:
            print('Failed to import user:', err.reason)
    except exceptions.FirebaseError as error:
        print('Error importing users:', error)
	# [END import_with_hmac_tenant]

def import_without_password_tenant(tenant_client):
	# [START import_without_password_tenant]
    users = [
        auth.ImportUserRecord(
            uid='some-uid',
            display_name='John Doe',
            email='johndoe@gmail.com',
            photo_url='http://www.example.com/12345678/photo.png',
            email_verified=True,
            phone_number='+11234567890',
            custom_claims={'admin': True}, # set this user as admin
            provider_data=[ # user with SAML provider
                auth.UserProvider(
                    uid='saml-uid',
                    email='johndoe@gmail.com',
                    display_name='John Doe',
                    photo_url='http://www.example.com/12345678/photo.png',
                    provider_id='saml.acme'
                )
            ],
        ),
    ]
    try:
        result = tenant_client.import_users(users)
        for err in result.errors:
            print('Failed to import user:', err.reason)
    except exceptions.FirebaseError as error:
        print('Error importing users:', error)
	# [END import_without_password_tenant]

def verify_id_token_tenant(tenant_client, id_token):
	# [START verify_id_token_tenant]
	# id_token comes from the client app
    try:
        decoded_token = tenant_client.verify_id_token(id_token)

        # This should be set to TENANT-ID. Otherwise TenantIdMismatchError error raised.
        print('Verified ID token from tenant:', decoded_token['firebase']['tenant'])
    except tenant_mgt.TenantIdMismatchError:
        # Token revoked, inform the user to reauthenticate or signOut().
        pass
    # [END verify_id_token_tenant]

def verify_id_token_access_control_tenant(id_token):
	# [START id_token_access_control_tenant]
    decoded_token = auth.verify_id_token(id_token)

    tenant = decoded_token['firebase']['tenant']
    if tenant == 'TENANT-ID1':
		# Allow appropriate level of access for TENANT-ID1.
        pass
    elif tenant == 'TENANT-ID2':
		# Allow appropriate level of access for TENANT-ID2.
        pass
    else:
		# Access not allowed -- Handle error
        pass
	# [END id_token_access_control_tenant]

def revoke_refresh_tokens_tenant(tenant_client, uid):
	# [START revoke_tokens_tenant]
	# Revoke all refresh tokens for a specified user in a specified tenant for whatever reason.
	# Retrieve the timestamp of the revocation, in seconds since the epoch.
    tenant_client.revoke_refresh_tokens(uid)

    user = tenant_client.get_user(uid)
    # Convert to seconds as the auth_time in the token claims is in seconds.
    revocation_second = user.tokens_valid_after_timestamp / 1000
    print('Tokens revoked at: {0}'.format(revocation_second))
	# [END revoke_tokens_tenant]

def verify_id_token_and_check_revoked_tenant(tenant_client, id_token):
	# [START verify_id_token_and_check_revoked_tenant]
	# Verify the ID token for a specific tenant while checking if the token is revoked.
    try:
        # Verify the ID token while checking if the token is revoked by
        # passing check_revoked=True.
        decoded_token = tenant_client.verify_id_token(id_token, check_revoked=True)
        # Token is valid and not revoked.
        uid = decoded_token['uid']
    except tenant_mgt.TenantIdMismatchError:
        # Token belongs to a different tenant.
        pass
    except auth.RevokedIdTokenError:
        # Token revoked, inform the user to reauthenticate or signOut().
        pass
    except auth.InvalidIdTokenError:
        # Token is invalid
        pass
	# [END verify_id_token_and_check_revoked_tenant]

def custom_claims_set_tenant(tenant_client, uid):
	# [START set_custom_user_claims_tenant]
    # Set admin privilege on the user corresponding to uid.
    tenant_client.set_custom_user_claims(uid, {'admin': True})
    # The new custom claims will propagate to the user's ID token the
    # next time a new one is issued.
	# [END set_custom_user_claims_tenant]

def custom_claims_verify_tenant(tenant_client, id_token):
	# [START verify_custom_claims_tenant]
    # Verify the ID token first.
    claims = tenant_client.verify_id_token(id_token)
    if claims['admin'] is True:
        # Allow access to requested admin resource.
        pass
	# [END verify_custom_claims_tenant]

def custom_claims_read_tenant(tenant_client, uid):
	# [START read_custom_user_claims_tenant]
	# Lookup the user associated with the specified uid.
    user = tenant_client.get_user(uid)

	# The claims can be accessed on the user record.
    print(user.custom_claims.get('admin'))
	# [END read_custom_user_claims_tenant]

def generate_email_verification_link_tenant(tenant_client):
	# [START email_verification_link_tenant]
    action_code_settings = auth.ActionCodeSettings(
        url='https://www.example.com/checkout?cartId=1234',
        handle_code_in_app=True,
        ios_bundle_id='com.example.ios',
        android_package_name='com.example.android',
        android_install_app=True,
        android_minimum_version='12',
        # FDL custom domain.
        dynamic_link_domain='coolapp.page.link',
    )

    email = 'user@example.com'
    link = tenant_client.generate_email_verification_link(email, action_code_settings)
    # Construct email from a template embedding the link, and send
    # using a custom SMTP server.
    send_custom_email(email, link)
	# [END email_verification_link_tenant]


initialize_sdk_with_service_account()
initialize_sdk_with_application_default()
#initialize_sdk_with_refresh_token()
access_services_default()
access_services_nondefault()
create_token_uid()
token_with_claims = create_token_with_claims()
#verify_token_uid()

uid = create_user()
create_user_with_id()
get_user(uid)
get_user_by_email()
get_user_by_phone_number()
update_user(uid)
set_custom_user_claims(uid)
list_all_users()
delete_user(uid)
