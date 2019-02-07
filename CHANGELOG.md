# Unreleased

- [added] Migrated the `auth` user management API to the
  new Identity Toolkit endpoint.
- [fixed] Extending HTTP retries to more HTTP methods like POST and PATCH.

# v2.15.1

- [added] Implemented HTTP retries. The SDK now retries HTTP calls on
  low-level connection and socket read errors, as well as HTTP 500 and
  503 errors.

# v2.15.0

- [changed] Taking a direct dependency on `google-api-core[grpc]` in order to
  resolve some long standing Firestore installation problems.
- `messaging.WebpushConfig` class now supports configuring additional
  [added] FCM options for the features supported by the web SDK. A new
  `messaging.WebpushFcmOptions` type has been introduced for this
  purpose.
- [added] `messaging.Aps` class now supports configuring a critical sound. A
  new `messaging.CriticalSound` class has been introduced for this purpose.
- [changed] Dropped support for Python 3.3.

# v2.14.0

- [added] A new `project_management` API for managing apps in a
  project.
- [added] `messaging.AndroidNotification` type now supports `channel_id`.
- [fixed] FCM errors sent by the back-end now include more details
  that are helpful when debugging problems.
- [fixed] Fixing error handling in FCM. The SDK now checks the key
  type.googleapis.com/google.firebase.fcm.v1.FcmError to set error code.
- [fixed] Ensuring that `UserRecord.tokens_valid_after_time` always
  returns an integer, and never returns `None`.
- [fixed] Fixing a performance issue in the `db.listen()` API
  where it was taking a long time to process large RTDB nodes.

# v2.13.0

- [added] The `db.Reference` type now provides a `listen()` API for
  receiving realtime update events from the Firebase Database.
- [added] The `db.reference()` method now optionally takes a `url`
  parameter. This can be used to access multiple Firebase Databases
  in the same project more easily.
- [added] The `messaging.WebpushNotification` type now supports
  additional parameters.

# v2.12.0

- [added] Implemented the ability to create custom tokens without
  service account credentials.
- [added] Admin SDK can now read the project ID from both `GCLOUD_PROJECT` and
  `GOOGLE_CLOUD_PROJECT` environment variables.

# v2.11.0

- [added] A new `auth.import_users()` API for importing users into Firebase
  Auth in bulk.
- [fixed] The `db.Reference.update()` function now accepts dictionaries with
  `None` values. This can be used to delete child keys from a reference.

# v2.10.0

- [added] A new `create_session_cookie()` method for creating a long-lived
  session cookie given a valid ID token.
- [added] A new `verify_session_cookie()` method for verifying a given
  cookie string is valid.
- [added] `auth` module now caches the public key certificates used to
  verify ID tokens and sessions cookies. This enables the SDK to avoid
  making a network call everytime a credential needs to be verified.
- [added] Added the `mutable_content` optional field to the `messaging.Aps`
  type.
- [added] Added support for specifying arbitrary custom key-value
  fields in the `messaging.Aps` type.

# v2.9.1

### Cloud Messaging

- [changed] Improved error handling in FCM by mapping more server-side
  errors to client-side error codes. See [documentation](https://firebase.google.com/docs/cloud-messaging/admin/errors).
- [changed] The `messaging` module now supports specifying an HTTP timeout
  for all egress requests. Pass the `httpTimeout` option
  to `firebase_admin.initialize_app()` before invoking any functions in
  `messaging`.

# v2.9.0

### Cloud Messaging

- [feature] Added the `firebase_admin.messaging` module for sending
  Firebase notifications and managing topic subscriptions.

### Authentication

- [added] The ['verify_id_token()'](https://firebase.google.com/docs/reference/admin/python/firebase_admin.auth#verify_id_token)
  function now accepts an optional `check_revoked` parameter. When `True`, an
  additional check is performed to see whether the token has been revoked.
- [added] A new
  ['auth.revoke_refresh_tokens(uid)'](https://firebase.google.com/docs/reference/admin/python/firebase_admin.auth#revoke_refresh_tokens)
  function has been added to invalidate all tokens issued to a user.
- [added] A new `tokens_valid_after_timestamp` property has been added to the
  ['UserRecord'](https://firebase.google.com/docs/reference/admin/python/firebase_admin.auth#userrecord),
  class indicating the time before which tokens are not valid.

# v2.8.0

### Initialization

- [added] The [`initialize_app()`](https://firebase.google.com/docs/reference/admin/python/firebase_admin#initialize_app)
  method can now be invoked without any arguments. This initializes an app
  using Google Application Default Credentials, and other
  options loaded from the `FIREBASE_CONFIG` environment variable.

### Realtime Database

- [added] The [`db.Reference.get()`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.db#reference)
  method now accepts an optional `shallow`
  argument. If set to `True` this causes the SDK to execute a shallow read,
  which does not retrieve the child node values of the current reference.

# v2.7.0

- [added] A new [`instance_id`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.instance_id)
  API that facilitates deleting instance IDs and associated user data from
  Firebase projects.

# v2.6.0

### Authentication

- [added] Added the
  [`list_users()`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.auth#list_users)
  function to the `firebase_admin.auth` module. This function enables listing
  or iterating over all user accounts in a Firebase project.
- [added] Added the
  [`set_custom_user_claims()`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.auth#set_custom_user_claims)
  function to the `firebase_admin.auth` module. This function enables setting
  custom claims on a Firebase user. The custom claims can be accessed via that
  user's ID token.

### Realtime Database

- [changed] Updated the `start_at()`, `end_at()` and `equal_to()` methods of
  the [`db.Query`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.db#query) class
  so they can accept empty string arguments.

# v2.5.0

- [added] A new [`Firestore` API](https://firebase.google.com/docs/reference/admin/python/firebase_admin.firestore)
  that enables access to [Cloud Firestore](https://firebase.google.com/docs/firestore) databases.

# v2.4.0

### Realtime Database

- [added] The [`db.Reference`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.db#reference)
  class now has a `get_if_changed()` method, which retrieves a
  database value only if the value has changed since last read.
- [added] The options dictionary passed to
  [`initialize_app()`](https://firebase.google.com/docs/reference/admin/python/firebase_admin#initialize_app)
  function can now contain an `httpTimeout` option, which sets
  the timeout (in seconds) for outbound HTTP connections started by the SDK.

# v2.3.0

### Realtime Database

- [added] You can now get the ETag value of a database reference by passing
  `etag=True` to the `get()` method of a
  [`db.Reference`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.db#reference)
  object.
- [added] The [`db.Reference`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.db#reference)
  class now has a `set_if_unchanged()` method, which you can use to write to a
  database location only when the location has the ETag value you specify.
- [changed] Fixed an issue with the `transaction()` method that prevented you
  from updating scalar values in a transaction.

# v2.2.0

- [added] A new [Cloud Storage API](https://firebase.google.com/docs/reference/admin/python/firebase_admin.storage)
  that facilitates accessing Google Cloud Storage buckets using the
  [`google-cloud-storage`](https://googlecloudplatform.github.io/google-cloud-python/stable/storage/client.html)
  library.

### Authentication
- [added] A new user management API that allows provisioning and managing
  Firebase users from Python applications. This API adds `get_user()`,
  `get_user_by_email()`, `get_user_by_phone_number()`, `create_user()`,
  `update_user()` and `delete_dser()` methods
  to the [`firebase_admin.auth`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.auth)
  module.

### Realtime Database
- [added] The [`db.Reference`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.db#reference)
  class now exposes a `transaction()` method, which can be used to execute atomic updates
  on database references.

# v2.1.1

- [changed] Constructors of
  [`Certificate`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.credentials#certificate) and
  [`RefreshToken`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.credentials#refreshtoken)
  credential types can now be invoked with either a file path or a parsed JSON object.
  This facilitates the consumption of service account credentials and refresh token
  credentials from sources other than the local file system.
- [changed] Better integration with the `google-auth` library for making authenticated
  HTTP requests from the SDK.

# v2.1.0

- [added] A new [database API](https://firebase.google.com/docs/reference/admin/python/firebase_admin.db)
  that facilitates basic data manipulation
  operations (create, read, update and delete), and advanced queries. Currently,
  this API does not support realtime event listeners. See
  [Add the Firebase Admin SDK to your Server](/docs/admin/setup/)
  to get started.

# v2.0.0

- [changed] This SDK has been migrated from `oauth2client` to the new
  `google-auth` library.

### Authentication
- [changed] This SDK now supports verifying ID tokens when initialized with
  application default credentials.


# v1.0.0

- [added] Initial release of the Admin Python SDK. See
  [Add the Firebase Admin SDK to your Server](https://firebase.google.com/docs/admin/setup/)
  to get started.

### Initialization
- [added] Implemented the
  [`firebase_admin`](https://firebase.google.com/docs/reference/admin/python/firebase_admin)
  module, which provides the `initialize_app()` function for initializing the
  SDK with a credential.
- [added] Implemented the
  [`firebase_admin.credentials`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.credentials)
  module, which contains constructors for `Certificate`, `ApplicationDefault`
  and `RefreshToken` credential types.

### Authentication
- [added] Implemented the
  [`firebase_admin.auth`](https://firebase.google.com/docs/reference/admin/python/firebase_admin.auth)
  module, which provides `create_custom_token()` and `verify_id_token()`
  functions for minting custom authentication tokens and verifying Firebase ID
  tokens.
